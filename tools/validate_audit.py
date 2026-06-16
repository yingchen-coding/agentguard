#!/usr/bin/env python3
"""Independent verification for the scheduled agent-factory loop.

Loop Engineering says a loop needs a verify step that is *not* the thing that did the work. The
agent-factory produces a corpus audit and hands it to humans for review — so before that handoff,
validate the audit payload against the committed schema. A malformed or truncated audit should fail
the run, not reach the review queue.

Zero-dependency by design (matching the rest of agentguard): this checks the schema's required
top-level keys and their declared JSON types — not a full JSON-Schema engine, but enough to catch a
broken audit fast.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schemas" / "corpus-audit.schema.json"

_JSON_TYPES: dict[str, type | tuple[type, ...]] = {
    "object": dict,
    "array": list,
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "null": type(None),
}


def validate(audit_path: Path, schema_path: Path = SCHEMA) -> list[str]:
    """Return a list of human-readable problems; empty means the audit conforms."""
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read schema {schema_path}: {exc}"]
    try:
        data = json.loads(audit_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read/parse audit {audit_path}: {exc}"]

    if not isinstance(data, dict):
        return [f"audit root must be an object, got {type(data).__name__}"]
    errors: list[str] = [
        f"missing required key: {key!r}"
        for key in schema.get("required", [])
        if key not in data
    ]
    for key, spec in (schema.get("properties") or {}).items():
        # Only check single string types; a union like ["string","null"] (unhashable list) or a
        # missing type is left to a fuller validator rather than crashing here.
        type_name = spec.get("type") if isinstance(spec, dict) else None
        if key in data and isinstance(type_name, str):
            expected = _JSON_TYPES.get(type_name)
            if expected is not None and not isinstance(data[key], expected):
                got = type(data[key]).__name__
                errors.append(f"key {key!r} should be {type_name}, got {got}")
    return errors


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: validate_audit.py <audit.json>", file=sys.stderr)
        return 2
    audit = Path(args[0])
    errors = validate(audit)
    if errors:
        print(f"audit {audit} FAILED schema validation:", file=sys.stderr)
        for problem in errors:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"audit {audit} ✓ conforms to {SCHEMA.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
