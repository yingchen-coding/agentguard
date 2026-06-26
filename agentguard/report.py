"""Output formatters: human (terminal), json, and sarif (for GitHub code scanning)."""
from __future__ import annotations

import json
from pathlib import Path

from .automation import AUTOMATION_TITLES
from .frameworks import refs_for, short_refs
from .linter import LintReport
from .models import Finding, Severity
from .project import PROJECT_TITLES
from .rules import TITLES
from .workflow import WORKFLOW_TITLES

# ANSI — disabled automatically when stdout isn't a tty (handled in cli).
_COLOR = {
    "critical": "\033[1;31m",  # bold red
    "major": "\033[31m",       # red
    "minor": "\033[33m",       # yellow
    "info": "\033[36m",        # cyan
    "good": "\033[32m",        # green
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}
_NOCOLOR = dict.fromkeys(_COLOR, "")

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
            ref = short_refs(f.rule)
            ref_s = f"  {c['dim']}[{ref}]{c['reset']}" if ref else ""
            out.append(
                f"  {col}{_GLYPH[f.severity.label]} {f.severity.label:<8}{c['reset']} "
                f"{c['dim']}{loc:>4}{c['reset']}  {f.rule}  {f.message}{ref_s}"
            )
            out.append(f"        {c['dim']}↳ fix:{c['reset']} {f.fix}")

    if report.project_findings:
        out.append(f"\n{c['bold']}project (publish & supply-chain){c['reset']}")
        for f in report.project_findings:
            col = c[f.severity.label]
            loc = f"{f.path}:{f.line}" if f.line else (f.path or "—")
            ref = short_refs(f.rule)
            ref_s = f"  {c['dim']}[{ref}]{c['reset']}" if ref else ""
            out.append(
                f"  {col}{_GLYPH[f.severity.label]} {f.severity.label:<8}{c['reset']} "
                f"{c['dim']}{loc}{c['reset']}  {f.rule}  {f.message}{ref_s}"
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


_DENSITY_FLOOR = 5  # treat scans smaller than this as this size, so a tiny scan can't look "dense"


def _letter(score: int) -> str:
    return ("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70
            else "D" if score >= 60 else "F")


def grade(report: LintReport) -> tuple[str, int]:
    """A 0–100 security score and letter grade that reflects security *posture*, independent of how
    many files were scanned. Two orthogonal axes, combined by the worse (`min`) of the two:

      • danger ceiling — criticals are a presence/worst-case signal, so they're counted, not summed
        per-file: 0 → can still reach 100, 1 → caps at D (66), ≥2 → F (32). A big benign codebase
        never manufactures a critical, so this axis doesn't scale with size.
      • sloppiness density — majors/minors are a rate signal: their weight averaged *per file*, so a
        sprawling-but-clean repo isn't punished for size the way a raw sum punished it.

    This preserves the original intent (one critical = serious; clean = A) while fixing the bug
    where a summed score scaled with codebase size — flooring a 40-file benign scan to F while a
    tiny genuinely-dangerous one scored the same. Now those separate."""
    c = report.total_counts
    n = max(len(report.results), _DENSITY_FLOOR)
    ceiling = 100 - 34 * min(c["critical"], 2)            # 0→100, 1→66 (D), ≥2→32 (F)
    density = (7 * c["major"] + 2 * c["minor"]) / n       # per-file major/minor weight
    score = max(0, min(ceiling, round(100 - density)))
    return _letter(score), score


def top_density_contributors(
    report: LintReport, limit: int = 5
) -> list[tuple[Path, int, int, int]]:
    """Files dragging the density score down, worst first. Returns up to `limit` tuples of
    (path, weight, major, minor) where weight = 7*major + 2*minor, skipping files whose weight is 0.
    Sorted by weight desc, then path for stable ordering."""
    contributors: list[tuple[Path, int, int, int]] = []
    for result in report.results:
        major = result.counts["major"]
        minor = result.counts["minor"]
        weight = 7 * major + 2 * minor
        if weight:
            contributors.append((result.path, weight, major, minor))
    contributors.sort(key=lambda item: (-item[1], item[0]))
    return contributors[:max(limit, 0)]


def render_grade(report: LintReport, color: bool = True, root: Path | None = None) -> str:
    c = _COLOR if color else _NOCOLOR
    letter, score = grade(report)
    band = "good" if letter in "AB" else "critical" if letter in "DF" else "major"
    tc = report.total_counts
    n = len(report.results)
    scope = f"{n} definition{'s' if n != 1 else ''}"
    if report.project_findings:
        p = len(report.project_findings)
        scope += f", {p} project finding{'s' if p != 1 else ''}"
    lines = [
        f"{c['bold']}Security grade: {c[band]}{letter}{c['reset']}{c['bold']} ({score}/100)"
        f"{c['reset']} — {tc['critical']} critical, {tc['major']} major, "
        f"{tc['minor']} minor across {scope}"
    ]
    # When majors/minors pulled the score (i.e. not a clean A), name the files doing the pulling so
    # the grade is actionable rather than a bare number.
    if score < 100:
        for path, _weight, major, minor in top_density_contributors(report, limit=3):
            try:
                shown = path.relative_to(root) if root else path
            except ValueError:
                shown = path
            lines.append(f"  {c['dim']}↳ {shown} — {major} major, {minor} minor{c['reset']}")
    return "\n".join(lines)


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
            "findings": [{**f.to_dict(), "refs": refs_for(f.rule)} for f in r.findings],
        })
    return json.dumps({
        "version": 1,
        "summary": {
            "files": len(report.results),
            "files_with_findings": report.files_with_findings,
            "counts": report.total_counts,
        },
        "files": files,
        "project": [
            {**f.to_dict(), "path": f.path} for f in report.project_findings
        ],
    }, indent=2)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.MAJOR: "error",
    Severity.MINOR: "warning",
    Severity.INFO: "note",
}


def _sarif_result(f: Finding, uri: str) -> dict[str, object]:
    refs = refs_for(f.rule)
    cites = refs["owasp"] + refs["atlas"]
    msg = f"{f.message}  Fix: {f.fix}"
    if cites:
        msg += "  [" + " · ".join(cites) + "]"
    return {
        "ruleId": f.rule,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": msg},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": max(f.line, 1)},
            }
        }],
    }


def render_sarif(report: LintReport, root: Path | None = None) -> str:
    """SARIF 2.1.0 — GitHub renders these inline on PRs via the code-scanning API."""
    rules_seen: dict[str, dict[str, object]] = {}
    results = []
    for r in report.results:
        try:
            uri = str(r.path.relative_to(root)) if root else str(r.path)
        except ValueError:
            uri = str(r.path)
        for f in r.findings:
            rules_seen.setdefault(f.rule, {
                "id": f.rule,
                "shortDescription": {
                    "text": TITLES.get(
                        f.rule,
                        WORKFLOW_TITLES.get(f.rule, AUTOMATION_TITLES.get(f.rule, f.rule)),
                    )
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            })
            results.append(_sarif_result(f, uri))
    for f in report.project_findings:
        rules_seen.setdefault(f.rule, {
            "id": f.rule,
            "shortDescription": {
                "text": PROJECT_TITLES.get(f.rule, AUTOMATION_TITLES.get(f.rule, f.rule))
            },
            "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
        })
        results.append(_sarif_result(f, f.path or "."))
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agentguard",
                "informationUri": "https://github.com/yingchen-coding/agentguard",
                "rules": list(rules_seen.values()),
            }},
            "results": results,
        }],
    }, indent=2)
