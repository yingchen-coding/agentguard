import json
from pathlib import Path

from agentguard.cli import main
from agentguard.interop import check_interop_manifest, load_manifest

FIX = Path(__file__).parent / "fixtures"


def test_interop_good_manifest_is_clean(capsys):
    assert main(["--interop-check", str(FIX / "interop_good.json"), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["surface"] == "interop"
    assert data["summary"]["findings"] == 0


def test_interop_bad_manifest_reports_readiness_gaps(capsys):
    assert main(["--interop-check", str(FIX / "interop_bad.json"), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    rules = {finding["rule"] for finding in data["findings"]}
    assert {"AI101", "AI103", "AI108", "AI111", "AI114", "AI115"} <= rules


def test_interop_minor_findings_can_pass_at_major(capsys):
    assert main(
        [
            "--interop-check",
            str(FIX / "interop_good.json"),
            "--fail-at",
            "major",
        ]
    ) == 0


def test_interop_manifest_requires_json_object(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text("[]", encoding="utf-8")
    try:
        load_manifest(path)
    except ValueError as error:
        assert "JSON object" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_interop_checker_accepts_string_capabilities():
    findings = check_interop_manifest(
        {
            "agent_id": "agent.example",
            "name": "Example",
            "version": "1",
            "capabilities": ["search"],
            "tools": [{"name": "search", "input_schema": {"type": "object"}}],
            "permissions": {
                "data_access": ["public"],
                "confirmation_required_for": ["external-write"],
            },
            "audit": {"event_fields": ["agent_id", "tool", "timestamp"]},
        }
    )
    assert findings == []
