"""Project configuration via `[tool.agent-lint]` in pyproject.toml or a `.agent-lint.toml` file.

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


def load_config(root: Path) -> dict:
    """Return the merged agent-lint config dict for a scan root, or {} if none."""
    for name in (".agent-lint.toml", "agent-lint.toml"):
        f = root / name
        if f.is_file():
            return _parse(f.read_text(encoding="utf-8", errors="replace"), table="agent-lint")
    pp = root / "pyproject.toml"
    if pp.is_file():
        return _parse(pp.read_text(encoding="utf-8", errors="replace"), table="tool.agent-lint")
    return {}


def _parse(text: str, table: str) -> dict:
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


def _mini_table(text: str, table: str) -> dict:
    """Minimal fallback: grab simple `key = value` lines inside [table]."""
    out: dict = {}
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


def _coerce(val: str):
    val = val.split("#", 1)[0].strip()
    if val.startswith("[") and val.endswith("]"):
        return [v.strip().strip("'\"") for v in re.split(r",", val[1:-1]) if v.strip()]
    if val.lower() in ("true", "false"):
        return val.lower() == "true"
    return val.strip("'\"")


def _normalize(d: dict) -> dict:
    out: dict = {}
    if "select" in d:
        out["select"] = {str(x).upper() for x in (d["select"] or [])} or None
    for k in ("ignore",):
        if k in d:
            out["ignore"] = {str(x).upper() for x in (d[k] or [])}
    fa = d.get("fail-at", d.get("fail_at"))
    if fa:
        out["fail_at"] = str(fa).lower()
    pc = d.get("publish-check", d.get("publish_check"))
    if pc is not None:
        out["publish_check"] = bool(pc)
    return out
