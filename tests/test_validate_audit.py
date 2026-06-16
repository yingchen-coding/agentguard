"""The agent-factory loop's verify step: a corpus audit must conform to its schema before review."""
import json
from pathlib import Path

import pytest

from tools.validate_audit import validate

ROOT = Path(__file__).parent.parent
SCHEMA = json.loads((ROOT / "schemas" / "corpus-audit.schema.json").read_text(encoding="utf-8"))
_SAMPLE = {"object": {}, "array": [], "string": "x", "number": 1, "integer": 1, "boolean": True}


def _valid_payload() -> dict:
    props = SCHEMA.get("properties", {})
    return {
        key: _SAMPLE.get((props.get(key) or {}).get("type", "object"), {})
        for key in SCHEMA.get("required", [])
    }


def test_conforming_audit_passes(tmp_path):
    p = tmp_path / "audit.json"
    p.write_text(json.dumps(_valid_payload()), encoding="utf-8")
    assert validate(p) == []


def test_missing_required_key_fails(tmp_path):
    payload = _valid_payload()
    missing = SCHEMA["required"][0]
    del payload[missing]
    p = tmp_path / "audit.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    assert any(missing in e for e in validate(p))


def test_wrong_type_fails(tmp_path):
    props = SCHEMA.get("properties", {})
    arr_key = next((k for k in SCHEMA["required"] if (props.get(k) or {}).get("type") == "array"), None)
    if arr_key is None:
        pytest.skip("schema has no array-typed required key")
    payload = _valid_payload()
    payload[arr_key] = "not-an-array"
    p = tmp_path / "audit.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    assert any(arr_key in e for e in validate(p))


def test_malformed_json_fails(tmp_path):
    p = tmp_path / "audit.json"
    p.write_text("{not valid json", encoding="utf-8")
    assert validate(p)  # non-empty error list


def test_union_type_in_schema_does_not_crash(tmp_path):
    # a JSON-Schema union type is an (unhashable) list — the validator must skip it, not crash
    schema = {"required": ["x"], "properties": {"x": {"type": ["string", "null"]}}}
    sp = tmp_path / "schema.json"
    sp.write_text(json.dumps(schema), encoding="utf-8")
    ap = tmp_path / "audit.json"
    ap.write_text(json.dumps({"x": 5}), encoding="utf-8")
    assert validate(ap, sp) == []
