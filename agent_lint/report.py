"""Output formatters: human (terminal), json, and sarif (for GitHub code scanning)."""
from __future__ import annotations

import json
from pathlib import Path

from .linter import LintReport
from .models import Severity

# ANSI — disabled automatically when stdout isn't a tty (handled in cli).
_COLOR = {
    "critical": "\033[1;31m",  # bold red
    "major": "\033[31m",       # red
    "minor": "\033[33m",       # yellow
    "info": "\033[36m",        # cyan
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}
_NOCOLOR = {k: "" for k in _COLOR}

_GLYPH = {"critical": "✖", "major": "✖", "minor": "▲", "info": "·"}


def render_human(report: LintReport, color: bool = True, root: Path | None = None) -> str:
    c = _COLOR if color else _NOCOLOR
    out: list[str] = []
    for r in report.results:
        if not r.findings:
            continue
        try:
            shown = r.path.relative_to(root) if root else r.path
        except ValueError:
            shown = r.path
        out.append(f"\n{c['bold']}{shown}{c['reset']}")
        for f in r.findings:
            loc = f"{f.line}" if f.line else "—"
            col = c[f.severity.label]
            out.append(
                f"  {col}{_GLYPH[f.severity.label]} {f.severity.label:<8}{c['reset']} "
                f"{c['dim']}{loc:>4}{c['reset']}  {f.rule}  {f.message}"
            )
            out.append(f"        {c['dim']}↳ fix:{c['reset']} {f.fix}")

    tc = report.total_counts
    n_files = len(report.results)
    if report.findings:
        summary = (f"{c['critical']}{tc['critical']} critical{c['reset']}, "
                   f"{c['major']}{tc['major']} major{c['reset']}, "
                   f"{c['minor']}{tc['minor']} minor{c['reset']}, "
                   f"{c['info']}{tc['info']} info{c['reset']}")
        out.append(f"\n{c['bold']}✖ {len(report.findings)} findings{c['reset']} "
                   f"in {report.files_with_findings}/{n_files} files  ({summary})")
    else:
        out.append(f"\n{c['bold']}✓ clean{c['reset']} — {n_files} definition"
                   f"{'s' if n_files != 1 else ''} checked, no findings")
    return "\n".join(out)


def render_json(report: LintReport, root: Path | None = None) -> str:
    files = []
    for r in report.results:
        try:
            shown = str(r.path.relative_to(root)) if root else str(r.path)
        except ValueError:
            shown = str(r.path)
        files.append({
            "path": shown,
            "kind": r.definition.kind,
            "counts": r.counts,
            "findings": [f.to_dict() for f in r.findings],
        })
    return json.dumps({
        "version": 1,
        "summary": {
            "files": len(report.results),
            "files_with_findings": report.files_with_findings,
            "counts": report.total_counts,
        },
        "files": files,
    }, indent=2)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.MAJOR: "error",
    Severity.MINOR: "warning",
    Severity.INFO: "note",
}


def render_sarif(report: LintReport, root: Path | None = None) -> str:
    """SARIF 2.1.0 — GitHub renders these inline on PRs via the code-scanning API."""
    rules_seen: dict[str, dict] = {}
    results = []
    for r in report.results:
        try:
            uri = str(r.path.relative_to(root)) if root else str(r.path)
        except ValueError:
            uri = str(r.path)
        for f in r.findings:
            rules_seen.setdefault(f.rule, {
                "id": f.rule,
                "shortDescription": {"text": f.message[:120]},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            })
            results.append({
                "ruleId": f.rule,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.message}  Fix: {f.fix}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": max(f.line, 1)},
                    }
                }],
            })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agent-lint",
                "informationUri": "https://github.com/YOUR_USERNAME/agent-lint",
                "rules": list(rules_seen.values()),
            }},
            "results": results,
        }],
    }, indent=2)
