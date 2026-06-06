"""Scan a repo you don't have locally: `agentguard owner/repo` or a git URL.

The "vet a plugin before you install it" use case — shallow-clone to a temp dir, scan, clean up.
Network + git required (only for this path; local scans stay offline).
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

_OWNER_REPO = re.compile(r"^[\w.-]+/[\w.-]+$")


def looks_remote(spec: str) -> bool:
    """A spec is remote if it's a URL or `owner/repo` AND not an existing local path."""
    if Path(spec).exists():
        return False
    return spec.startswith(("http://", "https://", "git@", "ssh://")) or \
        bool(_OWNER_REPO.match(spec))


def _to_url(spec: str) -> str:
    if _OWNER_REPO.match(spec):
        return f"https://github.com/{spec}.git"
    if spec.startswith("http") and not spec.endswith(".git"):
        return spec + ".git"
    return spec


def clone_to_temp(spec: str) -> Path:
    """Shallow-clone `spec` to a fresh temp dir and return the repo path. Caller cleans up the
    parent with `cleanup()`. Raises RuntimeError on failure (no git, bad URL, network, timeout)."""
    if shutil.which("git") is None:
        raise RuntimeError("git is not installed — needed to scan a remote repo")
    tmp = Path(tempfile.mkdtemp(prefix="agentguard-remote-"))
    dest = tmp / "repo"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", _to_url(spec), str(dest)],
            check=True, capture_output=True, text=True, timeout=120,
        )
    except subprocess.CalledProcessError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        msg = (e.stderr or "").strip().splitlines()[-1] if e.stderr else "git clone failed"
        raise RuntimeError(f"could not clone {spec}: {msg}") from e
    except subprocess.TimeoutExpired as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"cloning {spec} timed out") from e
    return dest


def cleanup(repo_path: Path) -> None:
    shutil.rmtree(repo_path.parent, ignore_errors=True)
