import subprocess

import pytest

from tools.publish_audit_issue import publish


def test_publish_is_dry_run_without_confirmation(tmp_path):
    report = tmp_path / "report.md"
    report.write_text("# Report")
    action, number = publish(report, "owner/repo", "Audit", confirm=False)
    assert action == "dry-run"
    assert number is None


def test_publish_requires_token(tmp_path, monkeypatch):
    report = tmp_path / "report.md"
    report.write_text("# Report")
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="required"):
        publish(report, "owner/repo", "Audit", confirm=True)


def test_publish_updates_existing_marker_issue(tmp_path, monkeypatch):
    report = tmp_path / "report.md"
    report.write_text("# Report")
    monkeypatch.setenv("GH_TOKEN", "test-token")
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/gh")
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        stdout = '[{"number": 7}]' if args[2:4] == ["list", "--repo"] else ""
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    action, number = publish(report, "owner/repo", "Audit", confirm=True, runner=runner)
    assert (action, number) == ("updated", 7)
    assert any(call[2] == "edit" for call in calls)
