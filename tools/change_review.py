#!/usr/bin/env python3
"""Build a deterministic PR review packet and fail on missing verification evidence."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SECURITY_CORE = {
    "agentguard/linter.py",
    "agentguard/models.py",
    "agentguard/project.py",
    "agentguard/remote.py",
    "agentguard/rules.py",
}
EXTERNAL_ACTION = {
    "action.yml",
    "tools/publish_audit_issue.py",
    ".github/workflows/agent-factory.yml",
    ".github/workflows/publish.yml",
}
KNOWLEDGE_MODEL = {
    "schemas/corpus-audit.schema.json",
    "tools/corpus_audit.py",
    "tools/query_audit.py",
    "skills/agentguard-corpus-analyst/SKILL.md",
    "skills/agentguard-corpus-analyst/references/data-model.md",
}
WORKFLOW_FILES = {
    ".github/workflows/agent-factory.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/publish.yml",
    "Makefile",
}


@dataclass(frozen=True)
class Requirement:
    name: str
    reason: str
    evidence: tuple[str, ...]


def _changed_from_git(base: str, head: str) -> list[str]:
    command = ["git", "diff", "--name-only", f"{base}...{head}", "--"]
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def _touches(changed: set[str], paths: set[str]) -> bool:
    return bool(changed & paths)


def _has_prefix(changed: set[str], prefix: str) -> bool:
    return any(path.startswith(prefix) for path in changed)


def review(changed_paths: list[str]) -> dict[str, object]:
    changed = set(changed_paths)
    domains: set[str] = set()
    requirements: list[Requirement] = []

    security_change = _touches(changed, SECURITY_CORE)
    rules_change = "agentguard/rules.py" in changed
    external_change = _touches(changed, EXTERNAL_ACTION)
    knowledge_change = _touches(changed, KNOWLEDGE_MODEL)
    workflow_change = _touches(changed, WORKFLOW_FILES)

    if security_change:
        domains.update({"security", "trust-boundary"})
        requirements.append(Requirement(
            "security regression evidence",
            "security-sensitive code changed",
            ("tests/",),
        ))
        requirements.append(Requirement(
            "maintainer knowledge update",
            "the maintained operating instructions must evolve with the security model",
            ("skills/agentguard-maintainer/SKILL.md",),
        ))
    if rules_change:
        requirements.append(Requirement(
            "rule regression tests",
            "rule behavior changed",
            ("tests/",),
        ))
        requirements.append(Requirement(
            "precision and recall evidence",
            "security-rule changes must update or explicitly exercise the labeled benchmark",
            ("eval/benchmark.py", "eval/quality-baseline.json"),
        ))
    if external_change:
        domains.update({"security", "release", "trust-boundary"})
        requirements.append(Requirement(
            "external-action regression evidence",
            "code that can publish, release, or mutate remote state changed",
            ("tests/test_publish_audit_issue.py", "tests/test_distribution_assets.py"),
        ))
        requirements.append(Requirement(
            "human-gate documentation",
            "external effects must remain explicit and human-approved",
            ("docs/agent-factory.md", "PUBLISHING.md", "SECURITY.md"),
        ))
    if knowledge_change:
        domains.update({"data-model", "docs"})
        requirements.append(Requirement(
            "analyst knowledge update",
            "the maintained analyst instructions must evolve with the corpus data model",
            ("skills/agentguard-corpus-analyst/SKILL.md",),
        ))
        requirements.append(Requirement(
            "versioned corpus schema",
            "corpus implementation changes need a machine-readable data contract",
            ("schemas/corpus-audit.schema.json",),
        ))
        requirements.append(Requirement(
            "knowledge contract tests",
            "knowledge-model changes need a deterministic drift check",
            ("tests/test_contracts.py", "tests/test_corpus_audit.py"),
        ))
    if workflow_change:
        domains.update({"developer-experience", "release"})
        requirements.append(Requirement(
            "workflow cost evidence",
            "automation topology changed and can add noise or duplicated work",
            ("docs/evidence/workflow-budget.json", "tests/test_workflow_audit.py"),
        ))
    if _has_prefix(changed, "docs/") or "README.md" in changed:
        domains.add("docs")
    if _has_prefix(changed, "schemas/") or _has_prefix(changed, "docs/evidence/"):
        domains.add("data-model")

    checks = []
    failures = []
    for requirement in requirements:
        satisfied_by = sorted(
            evidence
            for evidence in requirement.evidence
            if evidence in changed or _has_prefix(changed, evidence)
        )
        passed = bool(satisfied_by)
        checks.append({
            "name": requirement.name,
            "reason": requirement.reason,
            "accepted_evidence": list(requirement.evidence),
            "satisfied_by": satisfied_by,
            "passed": passed,
        })
        if not passed:
            failures.append(requirement.name)

    return {
        "schema_version": 1,
        "changed_paths": sorted(changed),
        "review_domains": sorted(domains),
        "human_review_required": bool(domains & {"security", "trust-boundary", "release"}),
        "checks": checks,
        "failures": failures,
        "passed": not failures,
    }


def render_markdown(packet: dict[str, object]) -> str:
    domains = packet["review_domains"]
    checks = packet["checks"]
    lines = [
        "# Change Review Packet",
        "",
        f"- Changed paths: {len(packet['changed_paths'])}",
        f"- Review domains: {', '.join(domains) if domains else 'none'}",
        f"- Human review required: {'yes' if packet['human_review_required'] else 'no'}",
        f"- Gate: {'pass' if packet['passed'] else 'fail'}",
        "",
        "## Verification",
        "",
    ]
    if not checks:
        lines.append("No elevated review requirements.")
    for check in checks:
        mark = "PASS" if check["passed"] else "FAIL"
        evidence = ", ".join(check["satisfied_by"]) or "missing"
        lines.append(f"- **{mark}** {check['name']}: {evidence}")
        lines.append(f"  Reason: {check['reason']}")
    lines += [
        "",
        "## Human Boundary",
        "",
        "Agents may prepare evidence and patches. A human must approve security-sensitive, "
        "trust-boundary, release, or external-action changes.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="origin/main")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--changed-file", action="append", default=[])
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args(argv)
    try:
        paths = args.changed_file or _changed_from_git(args.base, args.head)
        packet = review(paths)
        if args.json_output:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
        markdown = render_markdown(packet)
        if args.markdown_output:
            args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
            args.markdown_output.write_text(markdown, encoding="utf-8")
        print(markdown)
        return 0 if packet["passed"] else 1
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"change review failed to run: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
