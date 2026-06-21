"""--discover: auto-find every local agent definition set without being handed paths."""
from agentguard.linter import discover, discover_agent_roots


def _agent(path, body="---\nname: x\ndescription: Use when reviewing. Reviews code.\n---\nDo the review.\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_vendored_plugins_under_claude_are_skipped(tmp_path):
    # the user's own agent
    _agent(tmp_path / ".claude" / "agents" / "mine.md")
    # a machine-installed third-party plugin (vendored) — must NOT be linted by default
    _agent(tmp_path / ".claude" / "plugins" / "cache" / "vendor" / "agents" / "theirs.md")

    files = {p.name for p in discover([tmp_path / ".claude"])}
    assert "mine.md" in files
    assert "theirs.md" not in files  # vendored plugin pruned like node_modules


def test_explicit_plugin_path_still_scans(tmp_path):
    # pointing AGENTGUARD AT a plugin dir is a deliberate supply-chain audit — still works
    plugin = tmp_path / ".claude" / "plugins" / "cache" / "vendor"
    _agent(plugin / "agents" / "theirs.md")
    files = {p.name for p in discover([plugin])}
    assert "theirs.md" in files


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
