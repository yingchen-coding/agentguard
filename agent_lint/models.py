"""Core data models for agent-lint."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    """Ordered so we can threshold (e.g. fail CI on >= MAJOR)."""
    INFO = 1
    MINOR = 2
    MAJOR = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    rule: str          # e.g. "AL050"
    severity: Severity
    message: str       # what's wrong
    fix: str           # how to fix it
    line: int = 0      # 1-based; 0 = file-level
    column: int = 0

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.label,
            "message": self.message,
            "fix": self.fix,
            "line": self.line,
            "column": self.column,
        }


@dataclass
class Definition:
    """A parsed agent / command / skill definition (a markdown file with optional frontmatter)."""
    path: Path
    raw: str
    frontmatter: dict = field(default_factory=dict)
    body: str = ""
    fm_end_line: int = 0          # line where frontmatter closes (0 if none)
    kind: str = "agent"           # agent | command | skill (inferred from path)
    disabled_rules: set[str] = field(default_factory=set)  # via inline directive

    # ---- convenience views (computed once) ----
    @property
    def body_lower(self) -> str:
        return self.body.lower()

    @property
    def body_line_count(self) -> int:
        return self.body.count("\n") + 1

    def line_of(self, needle_regex: str) -> int:
        """1-based line number of the first match in the full file, or 0."""
        m = re.search(needle_regex, self.raw, re.IGNORECASE | re.MULTILINE)
        if not m:
            return 0
        return self.raw.count("\n", 0, m.start()) + 1


_FM_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
_DISABLE_RE = re.compile(r"agent-lint-disable\s+([A-Z0-9, ]+)")


def _parse_frontmatter(text: str) -> tuple[dict, str, int]:
    """Minimal YAML-ish frontmatter parser (key: value, no nesting needed for our rules)."""
    m = _FM_RE.match(text)
    if not m:
        return {}, text, 0
    fm_block = m.group(1)
    fm: dict = {}
    cur_key = None
    for line in fm_block.split("\n"):
        if re.match(r"^\s+", line) and cur_key:  # continuation (folded description)
            fm[cur_key] = (fm.get(cur_key, "") + " " + line.strip()).strip()
            continue
        mk = re.match(r"^([A-Za-z_][\w-]*):\s?(.*)$", line)
        if mk:
            cur_key = mk.group(1).strip()
            fm[cur_key] = mk.group(2).strip()
    body = text[m.end():]
    fm_end_line = text.count("\n", 0, m.end())
    return fm, body, fm_end_line


def parse_definition(path: Path) -> Definition:
    raw = path.read_text(encoding="utf-8", errors="replace")
    fm, body, fm_end = _parse_frontmatter(raw)
    parts = {p.lower() for p in path.parts}
    if "commands" in parts:
        kind = "command"
    elif "skills" in parts:
        kind = "skill"
    else:
        kind = "agent"
    disabled = set()
    for m in _DISABLE_RE.finditer(raw):
        for r in m.group(1).split(","):
            r = r.strip()
            if r:
                disabled.add(r)
    return Definition(path=path, raw=raw, frontmatter=fm, body=body,
                      fm_end_line=fm_end, kind=kind, disabled_rules=disabled)
