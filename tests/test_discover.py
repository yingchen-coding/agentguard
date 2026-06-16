"""--discover: auto-find every local agent definition set without being handed paths."""
from agentguard.linter import discover_agent_roots


def test_discovers_claude_dirs_and_skips_noise(tmp_path):
    (tmp_path / "repoA" / ".claude" / "agents").mkdir(parents=True)
    (tmp_path / "repoB" / ".claude").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / ".claude").mkdir(parents=True)  # vendor → pruned
    (tmp_path / "agentguard-backup-2026" / ".claude").mkdir(parents=True)  # backup → pruned

    roots = {str(r) for r in discover_agent_roots([tmp_path])}

    assert str((tmp_path / "repoA" / ".claude").resolve()) in roots
    assert str((tmp_path / "repoB" / ".claude").resolve()) in roots
    assert not any("node_modules" in r for r in roots)
    assert not any("backup" in r for r in roots)


def test_missing_root_is_skipped(tmp_path):
    # a non-existent search root must not raise — discovery just yields whatever exists
    roots = discover_agent_roots([tmp_path / "does-not-exist"])
    assert all("does-not-exist" not in str(r) for r in roots)
