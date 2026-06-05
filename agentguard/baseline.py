"""Baseline support: snapshot today's findings so CI fails only on *new* ones.

This is how you adopt a linter on a repo that already has findings — record the current state once,
then the gate only trips on regressions. Findings are fingerprinted by (rule, path, normalized
message) so they survive line-number drift from unrelated edits.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .linter import LintReport

_NUM = re.compile(r"\d+")


def _fingerprint(path: str, rule: str, message: str) -> str:
    norm = _NUM.sub("#", message)  # ignore embedded counts/line refs
    # sha256 (not sha1) purely so this security tool doesn't trip its own CodeQL/bandit scan;
    # truncated — it's a content fingerprint, not a security primitive.
    return hashlib.sha256(f"{path}\0{rule}\0{norm}".encode()).hexdigest()[:16]


def _iter(report: LintReport, root: Path | None):
    for r in report.results:
        try:
            path = str(r.path.relative_to(root)) if root else str(r.path)
        except ValueError:
            path = str(r.path)
        for f in r.findings:
            yield _fingerprint(path, f.rule, f.message), f
    for f in report.project_findings:
        yield _fingerprint(f.path or ".", f.rule, f.message), f


def fingerprints(report: LintReport, root: Path | None) -> set[str]:
    return {fp for fp, _ in _iter(report, root)}


def write_baseline(path: Path, report: LintReport, root: Path | None) -> int:
    fps = sorted(fingerprints(report, root))
    path.write_text(json.dumps({"version": 1, "fingerprints": fps}, indent=2) + "\n",
                    encoding="utf-8")
    return len(fps)


def load_baseline(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    try:
        return set(json.loads(path.read_text(encoding="utf-8")).get("fingerprints", []))
    except (json.JSONDecodeError, OSError):
        return set()


def apply_baseline(report: LintReport, baseline: set[str], root: Path | None) -> int:
    """Drop findings whose fingerprint is in the baseline. Returns how many were suppressed."""
    suppressed = 0
    keep_fp = {id(f): fp for fp, f in _iter(report, root)}
    for r in report.results:
        kept = [f for f in r.findings if keep_fp.get(id(f)) not in baseline]
        suppressed += len(r.findings) - len(kept)
        r.findings = kept
    kept_proj = [f for f in report.project_findings if keep_fp.get(id(f)) not in baseline]
    suppressed += len(report.project_findings) - len(kept_proj)
    report.project_findings = kept_proj
    return suppressed
