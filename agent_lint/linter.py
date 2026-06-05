"""The engine: discover definition files, parse them, run every enabled rule, collect findings."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .models import Definition, Finding, Severity, parse_definition
from .rules import all_rules

# Files we treat as agent/command/skill definitions.
_DEF_DIRS = {"agents", "commands", "skills"}
_SKIP_NAMES = {"readme.md", "license.md", "changelog.md", "contributing.md", "code_of_conduct.md"}
_SKIP_WALK_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}


@dataclass
class FileResult:
    path: Path
    definition: Definition
    findings: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = {s.label: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.label] += 1
        return c

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


@dataclass
class LintReport:
    results: list[FileResult] = field(default_factory=list)
    project_findings: list[Finding] = field(default_factory=list)  # AL5xx, repo-level

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings] + self.project_findings

    @property
    def total_counts(self) -> dict[str, int]:
        c = {s.label: 0 for s in Severity}
        for r in self.results:
            for k, v in r.counts.items():
                c[k] += v
        for f in self.project_findings:
            c[f.severity.label] += 1
        return c

    @property
    def files_with_findings(self) -> int:
        return sum(1 for r in self.results if r.findings)

    def exit_code(self, fail_at: Severity) -> int:
        """0 = clean (relative to threshold), 1 = findings at/above fail_at."""
        worst = max((f.severity for f in self.findings), default=None)
        return 1 if worst is not None and worst >= fail_at else 0


class Linter:
    def __init__(self, select: set[str] | None = None, ignore: set[str] | None = None):
        self.select = select   # if set, ONLY these rule codes run
        self.ignore = ignore or set()

    def _active(self, code: str, definition: Definition) -> bool:
        if code in definition.disabled_rules:
            return False
        if self.select is not None and code not in self.select:
            return False
        if code in self.ignore:
            return False
        return True

    def lint_definition(self, definition: Definition) -> list[Finding]:
        findings: list[Finding] = []
        for code, fn in all_rules():
            if not self._active(code, definition):
                continue
            try:
                findings.extend(fn(definition))
            except Exception as e:  # a buggy rule must never crash the whole run
                findings.append(Finding(code, Severity.INFO,
                                        f"rule {code} raised {type(e).__name__}: {e}",
                                        "This is an agent-lint bug — please report it.", 0))
        findings.sort(key=lambda f: (-f.severity, f.line, f.rule))
        return findings

    def lint_file(self, path: Path) -> FileResult:
        definition = parse_definition(path)
        return FileResult(path=path, definition=definition,
                          findings=self.lint_definition(definition))

    def lint(self, paths: list[Path]) -> LintReport:
        report = LintReport()
        for p in sorted(discover(paths)):
            report.results.append(self.lint_file(p))
        return report


def discover(paths: list[Path]) -> list[Path]:
    """Expand paths into the set of definition files to lint.

    A bare .md file is taken at face value. A directory is walked, collecting .md files that
    live under an agents/ commands/ or skills/ dir, OR (if no such structure exists) any .md
    that has frontmatter — so the tool works on both plugin layouts and loose definition files.
    """
    found: set[Path] = set()
    for p in paths:
        p = Path(p)
        if p.is_file():
            if p.suffix.lower() == ".md":
                found.add(p.resolve())
            continue
        if not p.is_dir():
            continue
        # Walk once, pruning heavy dirs during traversal (not after).
        mds = list(_walk_md(p))
        structured = any((p / d).is_dir() for d in _DEF_DIRS) or \
            any(part.lower() in _DEF_DIRS for md in mds for part in md.parts)
        for md in mds:
            if md.name.lower() in _SKIP_NAMES:
                continue
            in_def_dir = any(part.lower() in _DEF_DIRS for part in md.parts)
            if structured and not in_def_dir:
                continue
            if not structured and not _has_frontmatter(md):
                continue
            found.add(md.resolve())
    return sorted(found)


def _walk_md(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_WALK_DIRS]
        for fn in filenames:
            if fn.lower().endswith(".md"):
                yield Path(dirpath) / fn


def _has_frontmatter(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.read(8).lstrip().startswith("---")
    except OSError:
        return False


# ---- functional conveniences ----

def lint_path(path: str | Path, **kw) -> LintReport:
    return Linter(**kw).lint([Path(path)])


def lint_paths(paths: list[str | Path], **kw) -> LintReport:
    return Linter(**kw).lint([Path(p) for p in paths])
