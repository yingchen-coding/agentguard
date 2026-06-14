#!/usr/bin/env python3
"""Publish one deduplicated corpus-audit issue, only behind explicit confirmation."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

MARKER = "<!-- agentguard-corpus-audit -->"
Runner = Callable[..., subprocess.CompletedProcess[str]]


def _run(runner: Runner, args: list[str]) -> subprocess.CompletedProcess[str]:
    return runner(args, check=True, capture_output=True, text=True, timeout=60)


def publish(
    report: Path,
    repo: str,
    title: str,
    confirm: bool,
    runner: Runner = subprocess.run,
) -> tuple[str, int | None]:
    body = report.read_text(encoding="utf-8")
    body = MARKER + "\n\n" + body
    if len(body) > 60_000:
        body = body[:59_900] + "\n\n_Report truncated; see the workflow artifact._\n"
    if not confirm:
        return "dry-run", None
    if not (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")):
        raise RuntimeError("GH_TOKEN or GITHUB_TOKEN is required with --confirm-publish")
    if shutil.which("gh") is None:
        raise RuntimeError("GitHub CLI `gh` is required with --confirm-publish")

    query = _run(runner, [
        "gh", "issue", "list", "--repo", repo, "--state", "open",
        "--search", f'"{MARKER}" in:body', "--json", "number", "--limit", "10",
    ])
    matches: list[dict[str, Any]] = json.loads(query.stdout or "[]")
    if matches:
        number = int(matches[0]["number"])
        _run(runner, [
            "gh", "issue", "edit", str(number), "--repo", repo,
            "--title", title, "--body", body,
        ])
        return "updated", number
    created = _run(runner, [
        "gh", "issue", "create", "--repo", repo, "--title", title, "--body", body,
    ])
    url = created.stdout.strip().rstrip("/")
    try:
        number = int(url.rsplit("/", 1)[-1])
    except ValueError:
        number = None
    return "created", number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--repo", required=True, help="GitHub owner/repo")
    parser.add_argument("--title", default="AgentGuard corpus audit")
    parser.add_argument("--confirm-publish", action="store_true")
    args = parser.parse_args(argv)
    try:
        action, number = publish(
            args.report,
            args.repo,
            args.title,
            args.confirm_publish,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as e:
        print(f"publish failed: {e}", file=sys.stderr)
        return 2
    suffix = f" issue #{number}" if number is not None else ""
    print(f"{action}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
