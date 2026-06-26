#!/usr/bin/env python3
"""Fail CI when code, docs, evidence, tests, or the maintainer skill drift apart."""
from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentguard.automation import AUTOMATION_TITLES  # noqa: E402
from agentguard.frameworks import REFS  # noqa: E402
from agentguard.project import PROJECT_TITLES  # noqa: E402
from agentguard.rules import TITLES, all_rules  # noqa: E402
from agentguard.workflow import WORKFLOW_TITLES  # noqa: E402

VERSION_RE = re.compile(r'^version = "([^"]+)"$', re.MULTILINE)
RULE_RE = re.compile(r"\bAL\d{3}\b")
SECURITY_MAPPED = {
    "AL200", "AL202", "AL203", "AL204",
    "AL300", "AL301", "AL302", "AL303", "AL305", "AL306", "AL307", "AL308", "AL310",
    "AL503", "AL504", "AL510", "AL511", "AL512", "AL513",
}


def evidence_is_stale(measured_on: str, max_age_days: int, today: date | None = None) -> bool:
    measured = date.fromisoformat(measured_on)
    current = today or date.today()
    return (current - measured).days > max_age_days


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _version() -> str:
    match = VERSION_RE.search(_read("pyproject.toml"))
    if not match:
        raise ValueError("project version missing from pyproject.toml")
    return match.group(1)


def verify() -> list[str]:
    failures: list[str] = []
    version = _version()
    readme = _read("README.md")
    rules_doc = _read("docs/rules.md")
    mapping_doc = _read("docs/threat-mapping.md")
    test_text = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "tests").glob("test_*.py"))

    failures.extend(
        f"README release pin drifted or missing: {pin}"
        for pin in (f"yingchen-coding/agentguard@v{version}", f"rev: v{version}")
        if pin not in readme
    )

    registered = {code for code, _ in all_rules()}
    known = registered | set(PROJECT_TITLES) | set(WORKFLOW_TITLES) | set(AUTOMATION_TITLES)
    documented = set(RULE_RE.findall(rules_doc))
    missing_docs = known - documented
    unknown_docs = documented - known
    if missing_docs:
        failures.append("rules missing from docs/rules.md: " + ", ".join(sorted(missing_docs)))
    if unknown_docs:
        failures.append("docs/rules.md names unknown rules: " + ", ".join(sorted(unknown_docs)))

    missing_tests = {code for code in known if code not in test_text}
    if missing_tests:
        failures.append("rules missing direct test references: " + ", ".join(sorted(missing_tests)))

    missing_mappings = SECURITY_MAPPED - set(REFS)
    if missing_mappings:
        failures.append("security rules missing framework mappings: "
                        + ", ".join(sorted(missing_mappings)))
    mapping_doc_codes = set(RULE_RE.findall(mapping_doc))
    undocumented_mappings = set(REFS) - mapping_doc_codes
    if undocumented_mappings:
        failures.append("framework mappings missing from docs: "
                        + ", ".join(sorted(undocumented_mappings)))

    evidence = json.loads(_read("evidence/marketplace-snapshot.json"))
    scope = evidence["scope"]
    findings = evidence["findings"]
    expected_fragments = (
        f"{scope['unique_definitions']} unique agent / command / skill definitions",
        f"{scope['plugins']} plugins",
        f"{findings['no_injection_guard']['count']} / {scope['unique_definitions']} "
        f"({findings['no_injection_guard']['percent']}%)",
        f"{findings['injection_to_action']['count']} / {scope['unique_definitions']} "
        f"({findings['injection_to_action']['percent']}%)",
        f"agentguard {evidence['agentguard_version']}",
        evidence["measured_on"],
    )
    failures.extend(
        f"README marketplace evidence drift: missing {fragment!r}"
        for fragment in expected_fragments
        if fragment not in readme
    )
    max_age = int(evidence["max_age_days"])
    if evidence_is_stale(evidence["measured_on"], max_age):
        evidence_age = (date.today() - date.fromisoformat(evidence["measured_on"])).days
        failures.append(
            f"marketplace evidence is stale: {evidence_age} days old, maximum is {max_age}"
        )

    maintainer = ROOT / "skills" / "agentguard-maintainer" / "SKILL.md"
    analyst = ROOT / "skills" / "agentguard-corpus-analyst" / "SKILL.md"
    if not maintainer.is_file():
        failures.append("maintainer skill missing: skills/agentguard-maintainer/SKILL.md")
    else:
        skill_text = maintainer.read_text(encoding="utf-8")
        failures.extend(
            f"maintainer skill missing required workflow reference: {required}"
            for required in (
                "eval/quality-baseline.json",
                "verify_contracts.py",
                "corpus_audit.py",
                "query_audit.py",
                "change_review.py",
                "workflow_audit.py",
            )
            if required not in skill_text
        )
    if not analyst.is_file():
        failures.append("analyst skill missing: skills/agentguard-corpus-analyst/SKILL.md")
    elif "schemas/corpus-audit.schema.json" not in analyst.read_text(encoding="utf-8"):
        failures.append("analyst skill is not tied to the corpus audit schema")
    schema = json.loads(_read("schemas/corpus-audit.schema.json"))
    required_fields = {
        "schema_version", "generated_at_epoch", "manifest", "summary",
        "repositories", "diff", "findings",
    }
    if set(schema.get("required", [])) != required_fields:
        failures.append("corpus audit schema top-level contract drifted")
    finding_modes = set(
        schema["properties"]["findings"]["items"]["properties"]["failure_mode"]["enum"]
    )
    if finding_modes != {
        "ambiguity",
        "retrieval_failure",
        "execution_risk",
        "other_quality",
    }:
        failures.append("corpus audit failure-mode taxonomy drifted")

    manifest = _read("MANIFEST.in")
    failures.extend(
        f"source distribution omits agent-factory directory: {directory}"
        for directory in ("corpus", "eval", "evidence", "schemas", "skills", "tools")
        if f"recursive-include {directory} " not in manifest
    )
    workflow_budget = json.loads(_read("evidence/workflow-budget.json"))
    budgeted_workflows = set(workflow_budget["workflows"])
    repository_workflows = {
        str(path.relative_to(ROOT))
        for pattern in ("*.yml", "*.yaml")
        for path in (ROOT / ".github" / "workflows").glob(pattern)
    }
    if budgeted_workflows != repository_workflows:
        failures.append("workflow budget does not cover exactly the repository workflows")

    title_codes = set(TITLES)
    if title_codes != registered:
        failures.append("rule title registry differs from executable registry")
    return failures


def main() -> int:
    try:
        failures = verify()
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"contract verification failed to run: {e}", file=sys.stderr)
        return 1
    if failures:
        print("contract verification failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("contract verification passed: code, tests, docs, evidence, mappings, and skill agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
