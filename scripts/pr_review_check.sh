#!/usr/bin/env bash
set -euo pipefail

python - <<'PYATTR'
import subprocess

allowed = "Ying Chen <yingchen.for.upload@gmail.com>"  # agentguard-allow AL504
# Block AI *attribution* — a co-author trailer or an AI-bot identity — NOT bare product mentions.
# An AI-tooling repo legitimately writes "claude"/"anthropic"/"codex" in commit subjects (e.g.
# "skip .claude/plugins when scanning"); the strong guard is the author/committer identity check
# below. Scan HEAD (the branch being shipped), not --all (stray unmerged dependabot/PR refs and
# orphaned pre-rewrite tags are not what main publishes).
blocked_message_markers = [
    "co-authored-by:",
    "noreply@anthropic.com",
    "noreply@openai.com",
]

raw = subprocess.check_output(
    ["git", "log", "HEAD", "--format=%H%x00%an <%ae>%x00%cn <%ce>%x00%B%x1e"],
    text=True,
)
findings: list[str] = []
for record in raw.strip("\x1e\n").split("\x1e"):
    if not record.strip():
        continue
    commit, author, committer, message = record.split("\x00", 3)
    short = commit[:12]
    if author != allowed:
        findings.append(f"{short}: author is {author}, expected {allowed}")
    if committer != allowed:
        findings.append(f"{short}: committer is {committer}, expected {allowed}")
    lowered = message.lower()
    if any(marker in lowered for marker in blocked_message_markers):
        findings.append(f"{short}: commit message contains an AI co-author / bot-attribution marker")

if findings:
    print("\n".join(findings))
    raise SystemExit("git history attribution scan failed")
PYATTR

python - <<'PYHOOKS'
from pathlib import Path
import os
import stat
import subprocess

expected_name = "Ying Chen"
expected_email = "yingchen.for.upload@gmail.com"
expected_hooks = Path.home() / ".git-hooks"
findings: list[str] = []


def git_config(key: str) -> str:
    result = subprocess.run(
        ["git", "config", "--global", "--get", key],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


if git_config("user.name") != expected_name:
    findings.append(f"global user.name must be {expected_name!r}")
if git_config("user.email") != expected_email:
    findings.append(f"global user.email must be {expected_email!r}")

configured_hooks = git_config("core.hooksPath")
if Path(configured_hooks).expanduser() != expected_hooks:
    findings.append(f"global core.hooksPath must be {expected_hooks}")

for hook in ("pre-commit", "commit-msg", "pre-push"):
    path = expected_hooks / hook
    if not path.exists():
        findings.append(f"missing global git hook: {path}")
        continue
    mode = path.stat().st_mode
    if not mode & stat.S_IXUSR:
        findings.append(f"global git hook is not executable: {path}")
    text = path.read_text(encoding="utf-8")
    if hook in {"pre-commit", "pre-push"}:
        for required in ("Ying Chen", "yingchen.for.upload@gmail.com"):
            if required not in text:
                findings.append(f"global git hook {hook} is missing required identity check")
                break
    if hook in {"commit-msg", "pre-push"}:
        for required in ("claude", "codex", "anthropic", "openai", "co-authored-by"):
            if required not in text.lower():
                findings.append(f"global git hook {hook} is missing blocked marker {required!r}")
                break

if findings:
    print("\n".join(findings))
    raise SystemExit("global git guard is not installed correctly")
PYHOOKS

python - <<'PY'
import subprocess

allowed = "Ying Chen <yingchen.for.upload@gmail.com>"
blocked_message_markers = [
    "co-authored-by: claude",
    "co-authored-by: codex",
    "co-authored-by: anthropic",
    "co-authored-by: openai",
    "noreply@anthropic.com",
    "noreply@openai.com",
]

raw = subprocess.check_output(
    ["git", "log", "HEAD", "--format=%H%x00%an <%ae>%x00%cn <%ce>%x00%B%x1e"],
    text=True,
)
findings: list[str] = []
for record in raw.strip("\x1e\n").split("\x1e"):
    if not record.strip():
        continue
    commit, author, committer, message = record.split("\x00", 3)
    short = commit[:12]
    if author != allowed:
        findings.append(f"{short}: author is {author}, expected {allowed}")
    if committer != allowed:
        findings.append(f"{short}: committer is {committer}, expected {allowed}")
    lowered = message.lower()
    if any(marker in lowered for marker in blocked_message_markers):
        findings.append(f"{short}: commit message contains blocked AI co-author marker")

if findings:
    print("\n".join(findings))
    raise SystemExit("git attribution scan failed")
PY

python -m pytest -q
python -m ruff check .
python -m mypy agentguard
python tools/verify_contracts.py
python eval/adversarial_review.py
python tools/workflow_audit.py
agentguard --publish-check --score --no-color .

package_dir="$(mktemp -d)"
python -m build --sdist --wheel --outdir "$package_dir"
python -m twine check "$package_dir"/*

agentguard --publish-check --fail-at minor --no-color .
