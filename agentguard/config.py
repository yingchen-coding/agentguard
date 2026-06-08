"""Project configuration via `[tool.agentguard]` in pyproject.toml or a `.agentguard.toml` file.

Honors the zero-dependency promise: uses the stdlib `tomllib` (Python 3.11+) when available, and
falls back to a tiny parser scoped to the one table we read on older interpreters.

Recognized keys (all optional):
    select      = ["AL300", "AL301"]   # only run these rule codes
    ignore      = ["AL206"]            # skip these
    fail-at     = "critical"           # info | minor | major | critical
    publish-check = true               # also run the AL5xx repo checks
"""
from __future__ import annotations

import re
from pathlib import Path

_KEYS = {"select", "ignore", "fail-at", "fail_at", "publish-check", "publish_check"}


def load_config(root: Path) -> dict[str, object]:
    """Return the merged agentguard config dict for a scan root, or {} if none."""
    for name in (".agentguard.toml", "agentguard.toml"):
        f = root / name
        if f.is_file():
            return _parse(f.read_text(encoding="utf-8", errors="replace"), table="agentguard")
    pp = root / "pyproject.toml"
    if pp.is_file():
        return _parse(pp.read_text(encoding="utf-8", errors="replace"), table="tool.agentguard")
    return {}


def _parse(text: str, table: str) -> dict[str, object]:
    try:
        import tomllib  # Python 3.11+
        data = tomllib.loads(text)
        node: object = data
        for part in table.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                node = {}
                break
        return _normalize(node if isinstance(node, dict) else {})
    except ModuleNotFoundError:
        return _normalize(_mini_table(text, table))


def _mini_table(text: str, table: str) -> dict[str, object]:
    """Minimal fallback: grab simple `key = value` lines inside [table]."""
    out: dict[str, object] = {}
    in_table = False
    header = "[" + table + "]"
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_table = line == header
            continue
        if not in_table or "=" not in line or line.startswith("#"):
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if key not in _KEYS:
            continue
        out[key] = _coerce(val)
    return out


def _coerce(val: str) -> object:
    val = val.split("#", 1)[0].strip()
    if val.startswith("[") and val.endswith("]"):
        return [v.strip().strip("'\"") for v in re.split(r",", val[1:-1]) if v.strip()]
    if val.lower() in ("true", "false"):
        return val.lower() == "true"
    return val.strip("'\"")


def _as_code_set(value: object) -> set[str]:
    """Coerce a config value (list/tuple/str) into a normalized set of rule codes."""
    if isinstance(value, (list, tuple, set)):
        return {str(x).upper() for x in value if str(x).strip()}
    if isinstance(value, str) and value.strip():
        return {value.strip().upper()}
    return set()


def _normalize(d: dict[str, object]) -> dict[str, object]:
    out: dict[str, object] = {}
    if "select" in d:
        out["select"] = _as_code_set(d["select"]) or None
    if "ignore" in d:
        out["ignore"] = _as_code_set(d["ignore"])
    fa = d.get("fail-at", d.get("fail_at"))
    if fa:
        out["fail_at"] = str(fa).lower()
    pc = d.get("publish-check", d.get("publish_check"))
    if pc is not None:
        out["publish_check"] = bool(pc)
    return out
