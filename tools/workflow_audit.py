#!/usr/bin/env python3
"""Audit GitHub Actions topology for noisy, duplicated, or unbounded work."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.MULTILINE)
MATRIX_LIST_RE = re.compile(r"^\s{8}([A-Za-z0-9_-]+):\s*\[([^\]]+)\]\s*$", re.MULTILINE)


def _job_blocks(text: str) -> dict[str, str]:
    jobs_match = re.search(r"^jobs:\s*$", text, re.MULTILINE)
    if not jobs_match:
        return {}
    section = text[jobs_match.end():]
    matches = list(JOB_RE.finditer(section))
    blocks = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(section)
        blocks[match.group(1)] = section[match.end():end]
    return blocks


def _expanded_jobs(blocks: dict[str, str]) -> int:
    total = 0
    for block in blocks.values():
        dimensions = MATRIX_LIST_RE.findall(block)
        expansion = 1
        for _name, values in dimensions:
            expansion *= len([value for value in values.split(",") if value.strip()])
        total += expansion
    return total


def audit(budget_path: Path) -> tuple[dict[str, Any], list[str]]:
    budget = json.loads(budget_path.read_text(encoding="utf-8"))
    if budget.get("schema_version") != 1:
        raise ValueError("workflow budget schema_version must be 1")
    failures = []
    results = []
    configured = set(budget["workflows"])
    present = {
        str(path.relative_to(ROOT))
        for pattern in ("*.yml", "*.yaml")
        for path in (ROOT / ".github" / "workflows").glob(pattern)
    }
    failures.extend(
        f"{path}: workflow is not covered by docs/evidence/workflow-budget.json"
        for path in sorted(present - configured)
    )
    failures.extend(
        f"{path}: budget references a missing workflow"
        for path in sorted(configured - present)
    )
    for relative, limits in sorted(budget["workflows"].items()):
        path = ROOT / relative
        text = path.read_text(encoding="utf-8")
        blocks = _job_blocks(text)
        expanded = _expanded_jobs(blocks)
        workflow_failures = []
        maximum = int(limits["max_jobs_after_matrix"])
        if expanded > maximum:
            workflow_failures.append(
                f"matrix expands to {expanded} jobs, budget is {maximum}"
            )
        if limits.get("require_job_timeouts"):
            missing = sorted(
                name
                for name, block in blocks.items()
                if "timeout-minutes:" not in block
            )
            if missing:
                workflow_failures.append("jobs missing timeout-minutes: " + ", ".join(missing))
        if limits.get("require_cancel_in_progress") and (
            "concurrency:" not in text or "cancel-in-progress: true" not in text
        ):
            workflow_failures.append("PR workflow lacks concurrency cancellation")
        command_counts = {}
        for command, command_maximum in limits.get("command_budgets", {}).items():
            count = text.count(command)
            command_counts[command] = count
            if count > int(command_maximum):
                workflow_failures.append(
                    f"{command!r} occurs {count} times, budget is {command_maximum}"
                )
        failures.extend(f"{relative}: {failure}" for failure in workflow_failures)
        results.append({
            "path": relative,
            "jobs": sorted(blocks),
            "jobs_after_matrix": expanded,
            "command_counts": command_counts,
            "failures": workflow_failures,
        })
    return {
        "schema_version": 1,
        "workflows": results,
        "passed": not failures,
    }, failures


def render(payload: dict[str, Any]) -> str:
    lines = ["# Workflow Cost Audit", ""]
    for workflow in payload["workflows"]:
        lines.append(
            f"- `{workflow['path']}`: {workflow['jobs_after_matrix']} jobs after matrix expansion"
        )
        for command, count in workflow["command_counts"].items():
            lines.append(f"  - `{command}`: {count}")
    lines += ["", f"Gate: {'pass' if payload['passed'] else 'fail'}", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--budget",
        type=Path,
        default=ROOT / "docs" / "evidence" / "workflow-budget.json",
    )
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args(argv)
    try:
        payload, failures = audit(args.budget)
        if args.json_output:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(render(payload))
        for failure in failures:
            print(f"workflow audit: {failure}", file=sys.stderr)
        return 0 if not failures else 1
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"workflow audit failed to run: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
