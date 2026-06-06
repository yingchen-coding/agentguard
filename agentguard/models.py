"""Core data models for agentguard."""
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
    path: str = ""     # set for project-level findings that name a specific file

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.label,
            "message": self.message,
            "fix": self.fix,
            "line": self.line,
            "column": self.column,
        }


# --- capability model -------------------------------------------------------------
# Claude Code tools, grouped by the security property that matters for threat analysis.
# A tool can belong to more than one group.

# Pull in content the agent does not author — a vector for prompt injection.
EXTERNAL_READERS = {"WebFetch", "WebSearch", "Read", "Grep", "Glob", "NotebookRead"}
# Clearly untrusted / network-sourced (stronger signal than reading a local file).
UNTRUSTED_READERS = {"WebFetch", "WebSearch"}
# Execute code or mutate state irreversibly.
EXEC_SINKS = {"Bash", "Write", "Edit", "NotebookEdit"}
# Can move data off the machine (exfiltration sink).
NETWORK_SINKS = {"WebFetch", "WebSearch", "Bash"}
# Propagate privilege by spawning more agents.
SPAWN_SINKS = {"Task", "Agent"}

ALL_SINKS = EXEC_SINKS | NETWORK_SINKS | SPAWN_SINKS

_TOOL_TOKEN = re.compile(r"[A-Za-z_][\w.:-]*")


def classify_tools(tokens: set[str]) -> set[str]:
    """Canonicalize tool names. mcp__server__action tools are kept verbatim but recognized
    as both readers and network sinks (they reach external systems both ways)."""
    return {t.strip() for t in tokens if t.strip()}


def _mcp(tokens: set[str]) -> bool:
    return any(t.lower().startswith("mcp__") or t.lower().startswith("mcp:") for t in tokens)


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
    tools: set[str] | None = None     # declared tool grant; None = field absent
    tools_declared: bool = False      # whether a tools/allowed-tools field was present

    # ---- convenience views (computed once) ----
    @property
    def body_lower(self) -> str:
        return self.body.lower()

    @property
    def body_line_count(self) -> int:
        return self.body.count("\n") + 1

    @property
    def unrestricted(self) -> bool:
        """An agent with no tools field inherits the FULL toolset — maximal blast radius."""
        return self.kind == "agent" and not self.tools_declared

    @property
    def capabilities(self) -> set[str]:
        """Effective tool set: the declared grant, or every tool if unrestricted."""
        if self.unrestricted:
            return EXEC_SINKS | EXTERNAL_READERS | NETWORK_SINKS | SPAWN_SINKS
        return self.tools or set()

    def has_reader(self) -> bool:
        caps = self.capabilities
        return bool(caps & EXTERNAL_READERS) or _mcp(caps)

    def has_untrusted_reader(self) -> bool:
        caps = self.capabilities
        return bool(caps & UNTRUSTED_READERS) or _mcp(caps)

    def has_exec_sink(self) -> bool:
        return bool(self.capabilities & EXEC_SINKS)

    def has_network_sink(self) -> bool:
        caps = self.capabilities
        return bool(caps & NETWORK_SINKS) or _mcp(caps)

    def line_of(self, needle_regex: str) -> int:
        """1-based line number of the first match in the full file, or 0."""
        m = re.search(needle_regex, self.raw, re.IGNORECASE | re.MULTILINE)
        if not m:
            return 0
        return self.raw.count("\n", 0, m.start()) + 1


_FM_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
_DISABLE_RE = re.compile(r"agentguard-disable\s+([A-Z0-9, ]+)")


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


# Definitions are small (well under 100 KB). Cap what we feed the regex engine so a pathological
# or oversized file can't cause catastrophic backtracking or memory blowup on a security tool.
_MAX_ANALYZE_BYTES = 512 * 1024


def parse_definition(path: Path) -> Definition:
    raw = path.read_text(encoding="utf-8", errors="replace")
    if len(raw) > _MAX_ANALYZE_BYTES:
        raw = raw[:_MAX_ANALYZE_BYTES]
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
    tools, declared = _parse_tools(fm)
    return Definition(path=path, raw=raw, frontmatter=fm, body=body,
                      fm_end_line=fm_end, kind=kind, disabled_rules=disabled,
                      tools=tools, tools_declared=declared)


def _parse_tools(fm: dict) -> tuple[set[str] | None, bool]:
    """Extract the tool grant from frontmatter. Handles `tools: ["Read", "Write"]`,
    `tools: Read, Grep`, and `allowed-tools: ...`. Returns (toolset, was_declared).

    A field that is *present but empty* (`tools:` or `tools: []`) means **no tools** — declared
    with an empty grant — never "inherit everything". Only an entirely absent field is treated as
    unrestricted; inferring full access from an empty field would be the dangerous direction.
    """
    for key in ("tools", "allowed-tools", "allowed_tools"):
        if key in fm:
            tokens = set(_TOOL_TOKEN.findall(str(fm[key])))
            return classify_tools(tokens), True
    return None, False
