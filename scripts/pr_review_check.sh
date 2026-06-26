#!/usr/bin/env bash
set -euo pipefail

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

python - <<'PY'
from pathlib import Path

blocked = [
    "/" + "Users" + "/",
    "ghp" + "_",
    "BEGIN " + "RSA" + " KEY",
    "BEGIN " + "OPENSSH" + " KEY",
    "BEGIN " + "PRIVATE" + " KEY",
    "private-user" + "-images",
    "Temporary" + "Items",
    "NSIRD_screencaptureui_",  # agentguard-allow AL504
    "OPENAI_API_KEY",  # agentguard-allow AL504
    "ANTHROPIC_API_KEY",  # agentguard-allow AL504
    "GITHUB_TOKEN=",  # agentguard-allow AL504
    "GH_TOKEN=",  # agentguard-allow AL504
    "AWS_ACCESS_KEY_ID",  # agentguard-allow AL504
    "AWS_SECRET_ACCESS_KEY",  # agentguard-allow AL504
    "DATABRICKS_TOKEN",  # agentguard-allow AL504
    "personal_medical_record",  # agentguard-allow AL504
    "google-team-match",  # agentguard-allow AL504
]
skip_dirs = {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "build", "dist"}
skip_files = {
    Path("agentguard/rules.py"),
    Path("agentguard/project.py"),
    Path("eval/benchmark.py"),
    Path("LAUNCH-KIT.private.md"),
    Path("scripts/pr_review_check.sh"),
}
skip_parts = {"tests"}
findings: list[str] = []

for path in Path(".").rglob("*"):
    if not path.is_file():
        continue
    if any(part in skip_dirs or part.endswith(".egg-info") for part in path.parts):
        continue
    if path in skip_files or any(part in skip_parts for part in path.parts):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for needle in blocked:
        if needle in text:
            findings.append(f"{path}: contains blocked public-surface marker")
            break

if findings:
    print("\n".join(findings))
    raise SystemExit("public-surface scan failed")
PY
