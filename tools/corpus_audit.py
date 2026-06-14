#!/usr/bin/env python3
"""Parallel real-corpus audit with deduplication, state diffing, and repair patches."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentguard.fix import apply_fixes  # noqa: E402
from agentguard.frameworks import refs_for  # noqa: E402
from agentguard.linter import Linter  # noqa: E402
from agentguard.models import Finding  # noqa: E402
from agentguard.project import scan_project  # noqa: E402

_NUM = re.compile(r"\d+")
_MAX_REPOS = 100
_MAX_JOBS = 16
_MAX_REPORT_FINDINGS = 100
_AMBIGUITY_RULES = {
    "AL004", "AL100", "AL101", "AL200", "AL201", "AL204", "AL205", "AL206",
}
_RETRIEVAL_RULES = {"AL000", "AL001", "AL006"}
_EXECUTION_RULES = {
    "AL202", "AL203",
    "AL300", "AL301", "AL302", "AL303", "AL305", "AL306", "AL307", "AL308", "AL310",
    "AL503", "AL510", "AL511", "AL512", "AL513",
}


@dataclass(frozen=True)
class RepoSpec:
    name: str
    url: str = ""
    path: str = ""
    ref: str = ""
    publish_check: bool = False


@dataclass
class RepoResult:
    name: str
    source: str
    ok: bool
    elapsed_seconds: float
    definitions: int = 0
    findings: list[dict[str, Any]] | None = None
    patch: str = ""
    error: str = ""
    revision: str = ""


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "repo"


def _load_manifest(path: Path) -> tuple[list[RepoSpec], float]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("manifest schema_version must be 1")
    raw_repos = data.get("repositories")
    if not isinstance(raw_repos, list) or not raw_repos:
        raise ValueError("manifest repositories must be a non-empty list")
    if len(raw_repos) > _MAX_REPOS:
        raise ValueError(f"manifest exceeds {_MAX_REPOS} repositories")
    specs = []
    names = set()
    for raw in raw_repos:
        if not isinstance(raw, dict):
            raise ValueError("each repository entry must be an object")
        name = str(raw.get("name", "")).strip()
        url = str(raw.get("url", "")).strip()
        local_path = str(raw.get("path", "")).strip()
        if not name or bool(url) == bool(local_path):
            raise ValueError("each repository needs a unique name and exactly one of url/path")
        if name in names:
            raise ValueError(f"duplicate repository name: {name}")
        names.add(name)
        specs.append(RepoSpec(
            name=name,
            url=url,
            path=local_path,
            ref=str(raw.get("ref", "")).strip(),
            publish_check=bool(raw.get("publish_check", False)),
        ))
    min_success_rate = float(data.get("min_success_rate", 1.0))
    if not 0 < min_success_rate <= 1:
        raise ValueError("min_success_rate must be > 0 and <= 1")
    return specs, min_success_rate


def _materialize(spec: RepoSpec, manifest_dir: Path, temp: Path) -> Path:
    dest = temp / "repo"
    if spec.path:
        source = Path(spec.path)
        if not source.is_absolute():
            source = (manifest_dir / source).resolve()
        if not source.is_dir():
            raise RuntimeError(f"local path not found: {source}")
        shutil.copytree(
            source,
            dest,
            ignore=shutil.ignore_patterns(".git", ".venv", "node_modules", "dist", "build"),
        )
        return dest
    command = ["git", "clone", "--depth", "1", "--quiet"]
    if spec.ref:
        command += ["--branch", spec.ref]
    command += ["--", spec.url, str(dest)]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=180)
    except subprocess.CalledProcessError as e:
        message = (e.stderr or "git clone failed").strip().splitlines()[-1]
        raise RuntimeError(message) from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("git clone timed out after 180 seconds") from e
    return dest


def _finding_dict(
    repo: str,
    path: str,
    finding: Finding,
    definition_hash: str = "",
) -> dict[str, Any]:
    normalized = _NUM.sub("#", finding.message)
    identity = f"{finding.rule}\0{normalized}\0{definition_hash or path}"
    fingerprint = hashlib.sha256(identity.encode()).hexdigest()[:20]
    if finding.rule in _AMBIGUITY_RULES:
        failure_mode = "ambiguity"
    elif finding.rule in _RETRIEVAL_RULES:
        failure_mode = "retrieval_failure"
    elif finding.rule in _EXECUTION_RULES:
        failure_mode = "execution_risk"
    else:
        failure_mode = "other_quality"
    return {
        "fingerprint": fingerprint,
        "repo": repo,
        "path": path,
        "rule": finding.rule,
        "severity": finding.severity.label,
        "message": finding.message,
        "fix": finding.fix,
        "line": finding.line,
        "refs": refs_for(finding.rule),
        "failure_mode": failure_mode,
    }


def _revision(results: list[Any], root: Path) -> str:
    digest = hashlib.sha256()
    for result in sorted(results, key=lambda item: str(item.path)):
        digest.update(str(result.path.relative_to(root)).encode())
        digest.update(b"\0")
        digest.update(result.definition.raw.encode())
        digest.update(b"\0")
    return digest.hexdigest()[:20]


def _patch_for(results: list[Any], root: Path) -> str:
    before: dict[Path, str] = {}
    for result in results:
        if any(f.rule in {"AL202", "AL300", "AL307"} for f in result.findings):
            before[result.path] = result.path.read_text(encoding="utf-8", errors="replace")
    changed = apply_fixes(results)
    chunks = []
    for path in changed:
        rel = str(path.relative_to(root))
        after = path.read_text(encoding="utf-8", errors="replace")
        chunks.extend(difflib.unified_diff(
            before[path].splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        ))
    return "".join(chunks)


def _scan_one(spec: RepoSpec, manifest_dir: Path, make_patches: bool) -> RepoResult:
    started = time.monotonic()
    source = spec.url or spec.path
    with tempfile.TemporaryDirectory(prefix="agentguard-corpus-") as td:
        try:
            repo = _materialize(spec, manifest_dir, Path(td)).resolve()
            report = Linter().lint([repo])
            findings = []
            for result in report.results:
                rel = str(result.path.relative_to(repo))
                definition_hash = hashlib.sha256(result.definition.raw.encode()).hexdigest()[:20]
                findings.extend(
                    _finding_dict(spec.name, rel, finding, definition_hash)
                    for finding in result.findings
                )
            if spec.publish_check:
                findings.extend(
                    _finding_dict(spec.name, finding.path or ".", finding)
                    for finding in scan_project(repo)
                )
            patch = _patch_for(report.results, repo) if make_patches else ""
            return RepoResult(
                name=spec.name,
                source=source,
                ok=True,
                elapsed_seconds=time.monotonic() - started,
                definitions=len(report.results),
                findings=findings,
                patch=patch,
                revision=_revision(report.results, repo),
            )
        except (OSError, RuntimeError, ValueError) as e:
            return RepoResult(
                name=spec.name,
                source=source,
                ok=False,
                elapsed_seconds=time.monotonic() - started,
                findings=[],
                error=f"{type(e).__name__}: {e}",
            )


def _deduplicate(results: list[RepoResult]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for result in results:
        for finding in result.findings or []:
            fingerprint = str(finding["fingerprint"])
            occurrence = {
                "repo": finding["repo"],
                "path": finding["path"],
                "line": finding["line"],
            }
            if fingerprint not in grouped:
                grouped[fingerprint] = {
                    key: finding[key]
                    for key in (
                        "fingerprint",
                        "rule",
                        "severity",
                        "message",
                        "fix",
                        "refs",
                        "failure_mode",
                    )
                }
                grouped[fingerprint]["occurrences"] = []
            grouped[fingerprint]["occurrences"].append(occurrence)
    return sorted(grouped.values(), key=lambda item: (
        {"critical": 0, "major": 1, "minor": 2, "info": 3}[str(item["severity"])],
        str(item["rule"]),
        str(item["fingerprint"]),
    ))


def _previous_fingerprints(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {str(item["fingerprint"]) for item in data.get("findings", [])}
    except (OSError, json.JSONDecodeError, TypeError, KeyError):
        return set()


def _markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# AgentGuard Corpus Audit",
        "",
        "- Repositories: "
        f"{summary['repositories_succeeded']}/{summary['repositories_total']} succeeded",
        f"- Definitions scanned: {summary['definitions_scanned']}",
        f"- Raw findings: {summary['raw_findings']}",
        f"- Unique findings: {summary['unique_findings']}",
        "- New / unchanged / resolved: "
        f"{summary['new']} / {summary['unchanged']} / {summary['resolved']}",
        f"- Auto-fix patches: {summary['patches']}",
        f"- Wall time: {summary['elapsed_seconds']:.2f}s",
        "",
    ]
    failed = [repo for repo in payload["repositories"] if not repo["ok"]]
    if failed:
        lines += ["## Failed Repositories", ""]
        lines += [f"- `{repo['name']}`: {repo['error']}" for repo in failed]
        lines.append("")
    severity_counts = Counter(str(item["severity"]) for item in payload["findings"])
    rule_counts = Counter(str(item["rule"]) for item in payload["findings"])
    failure_counts = Counter(str(item["failure_mode"]) for item in payload["findings"])
    lines += [
        "## Distribution",
        "",
        "- Severity: "
        + ", ".join(
            f"{severity}={severity_counts.get(severity, 0)}"
            for severity in ("critical", "major", "minor", "info")
        ),
        "- Top rules: "
        + ", ".join(f"{rule}={count}" for rule, count in rule_counts.most_common(10)),
        "- Failure modes: "
        + ", ".join(
            f"{mode}={failure_counts.get(mode, 0)}"
            for mode in (
                "ambiguity",
                "retrieval_failure",
                "execution_risk",
                "other_quality",
                "staleness",
            )
        ),
        "",
    ]
    lines += ["## New Findings", ""]
    new_set = set(payload["diff"]["new"])
    new_findings = [item for item in payload["findings"] if item["fingerprint"] in new_set]
    if not new_findings:
        lines.append("None.")
    for item in new_findings[:_MAX_REPORT_FINDINGS]:
        where = ", ".join(
            f"{occ['repo']}:{occ['path']}:{occ['line']}" for occ in item["occurrences"][:5]
        )
        lines.append(
            f"- **{item['severity']} {item['rule']}** `{item['fingerprint']}` — "
            f"{item['message']} ({where})"
        )
    omitted = len(new_findings) - _MAX_REPORT_FINDINGS
    if omitted > 0:
        lines += [
            "",
            f"_Omitted {omitted} additional new findings; see `audit.json` in the artifact._",
        ]
    lines.append("")
    return "\n".join(lines)


def run_audit(
    manifest: Path,
    output: Path,
    jobs: int = 4,
    previous_state: Path | None = None,
    make_patches: bool = True,
) -> tuple[dict[str, Any], bool]:
    specs, min_success_rate = _load_manifest(manifest)
    jobs = max(1, min(jobs, _MAX_JOBS, len(specs)))
    output.mkdir(parents=True, exist_ok=True)
    prior_path = previous_state or output / "state.json"
    previous = _previous_fingerprints(prior_path)
    started = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(_scan_one, spec, manifest.parent, make_patches): spec
            for spec in specs
        }
        results.extend(future.result() for future in as_completed(futures))
    results.sort(key=lambda result: result.name)
    findings = _deduplicate(results)
    failure_modes = Counter(str(item["failure_mode"]) for item in findings)
    failure_modes["retrieval_failure"] += sum(not result.ok for result in results)
    failure_modes["staleness"] = sum(
        1 for result in results if not result.ok and "stale" in result.error.lower()
    )
    current = {str(item["fingerprint"]) for item in findings}
    new = sorted(current - previous)
    unchanged = sorted(current & previous)
    resolved = sorted(previous - current)
    patches = 0
    for result in results:
        if result.patch:
            patches += 1
            (output / f"{_safe_name(result.name)}.patch").write_text(
                result.patch, encoding="utf-8"
            )
    succeeded = sum(result.ok for result in results)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at_epoch": int(time.time()),
        "manifest": str(manifest),
        "summary": {
            "repositories_total": len(results),
            "repositories_succeeded": succeeded,
            "success_rate": succeeded / len(results),
            "definitions_scanned": sum(result.definitions for result in results),
            "raw_findings": sum(len(result.findings or []) for result in results),
            "unique_findings": len(findings),
            "new": len(new),
            "unchanged": len(unchanged),
            "resolved": len(resolved),
            "patches": patches,
            "elapsed_seconds": time.monotonic() - started,
            "failure_modes": dict(sorted(failure_modes.items())),
        },
        "repositories": [
            {
                "name": result.name,
                "source": result.source,
                "ok": result.ok,
                "elapsed_seconds": result.elapsed_seconds,
                "definitions": result.definitions,
                "findings": len(result.findings or []),
                "patch": f"{_safe_name(result.name)}.patch" if result.patch else "",
                "error": result.error,
                "revision": result.revision,
            }
            for result in results
        ],
        "diff": {"new": new, "unchanged": unchanged, "resolved": resolved},
        "findings": findings,
    }
    (output / "audit.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (output / "report.md").write_text(_markdown(payload), encoding="utf-8")
    (output / "state.json").write_text(
        json.dumps({"schema_version": 1, "findings": findings}, indent=2) + "\n",
        encoding="utf-8",
    )
    return payload, payload["summary"]["success_rate"] >= min_success_rate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=ROOT / "corpus" / "manifest.json")
    parser.add_argument("--output", type=Path, default=ROOT / "build" / "corpus-audit")
    parser.add_argument("--state", type=Path, help="prior state.json for new/resolved comparison")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--no-patches", action="store_true")
    args = parser.parse_args(argv)
    try:
        payload, healthy = run_audit(
            args.manifest.resolve(),
            args.output.resolve(),
            jobs=args.jobs,
            previous_state=args.state.resolve() if args.state else None,
            make_patches=not args.no_patches,
        )
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"corpus audit failed: {e}", file=sys.stderr)
        return 2
    summary = payload["summary"]
    print(
        f"corpus audit: {summary['repositories_succeeded']}/{summary['repositories_total']} repos, "
        f"{summary['definitions_scanned']} definitions, {summary['unique_findings']} unique "
        f"findings, {summary['new']} new, {summary['resolved']} resolved"
    )
    print(f"artifacts: {args.output.resolve()}")
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
