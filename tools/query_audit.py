#!/usr/bin/env python3
"""Structured, schema-aware queries over corpus audit artifacts."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError(f"unsupported audit schema_version: {payload.get('schema_version')!r}")
    for field in ("summary", "repositories", "diff", "findings"):
        if field not in payload:
            raise ValueError(f"audit artifact is missing required field: {field}")
    return payload


def _filtered_findings(
    payload: dict[str, Any],
    rule: str,
    severity: str,
    failure_mode: str,
    repo: str,
) -> list[dict[str, Any]]:
    findings = payload["findings"]
    if rule:
        findings = [item for item in findings if item["rule"] == rule]
    if severity:
        findings = [item for item in findings if item["severity"] == severity]
    if failure_mode:
        findings = [item for item in findings if item["failure_mode"] == failure_mode]
    if repo:
        findings = [
            item for item in findings
            if any(occurrence["repo"] == repo for occurrence in item["occurrences"])
        ]
    return findings


def query(
    payload: dict[str, Any],
    view: str,
    *,
    rule: str = "",
    severity: str = "",
    failure_mode: str = "",
    repo: str = "",
    limit: int = 20,
    min_repositories: int = 3,
) -> dict[str, Any]:
    findings = _filtered_findings(payload, rule, severity, failure_mode, repo)
    if view == "summary":
        raw = int(payload["summary"]["raw_findings"])
        unique = int(payload["summary"]["unique_findings"])
        repositories = payload["repositories"]
        patchable = sum(bool(item["patch"]) for item in repositories)
        return {
            "summary": payload["summary"],
            "duplicate_rate": 1 - unique / raw if raw else 0.0,
            "repair_repository_coverage": patchable / len(repositories) if repositories else 0.0,
            "failed_repositories": [
                {"name": item["name"], "error": item["error"]}
                for item in repositories
                if not item["ok"]
            ],
            "revisions": {
                item["name"]: item["revision"]
                for item in repositories
                if item["revision"]
            },
        }
    if view == "hotspots":
        repository_counts: Counter[str] = Counter()
        rule_counts: Counter[str] = Counter()
        mode_counts: Counter[str] = Counter()
        for item in findings:
            rule_counts[item["rule"]] += 1
            mode_counts[item["failure_mode"]] += 1
            repository_counts.update(
                occurrence["repo"] for occurrence in item["occurrences"]
            )
        return {
            "filters": {
                "rule": rule,
                "severity": severity,
                "failure_mode": failure_mode,
                "repo": repo,
            },
            "unique_findings": len(findings),
            "top_repositories": repository_counts.most_common(limit),
            "top_rules": rule_counts.most_common(limit),
            "failure_modes": dict(mode_counts),
        }
    if view in {"new", "resolved"}:
        fingerprints = set(payload["diff"][view])
        selected = [item for item in findings if item["fingerprint"] in fingerprints]
        return {
            "view": view,
            "count": len(selected),
            "findings": selected[:limit],
            "truncated": len(selected) > limit,
        }
    if view == "repositories":
        selected = payload["repositories"]
        if repo:
            selected = [item for item in selected if item["name"] == repo]
        return {"repositories": selected}
    if view == "automation":
        by_rule: dict[str, dict[str, Any]] = {}
        for item in findings:
            entry = by_rule.setdefault(item["rule"], {
                "rule": item["rule"],
                "unique_findings": 0,
                "repositories": set(),
                "sample_fix": item["fix"],
            })
            entry["unique_findings"] += 1
            entry["repositories"].update(
                occurrence["repo"] for occurrence in item["occurrences"]
            )
        candidates = []
        for entry in by_rule.values():
            repositories = sorted(entry["repositories"])
            if len(repositories) < min_repositories:
                continue
            candidates.append({
                "rule": entry["rule"],
                "unique_findings": entry["unique_findings"],
                "repository_count": len(repositories),
                "repositories": repositories,
                "sample_fix": entry["sample_fix"],
            })
        candidates.sort(
            key=lambda item: (-item["repository_count"], -item["unique_findings"], item["rule"])
        )
        return {
            "minimum_repositories": min_repositories,
            "candidates": candidates[:limit],
            "truncated": len(candidates) > limit,
        }
    raise ValueError(f"unsupported view: {view}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument(
        "--view",
        choices=("summary", "hotspots", "new", "resolved", "repositories", "automation"),
        default="summary",
    )
    parser.add_argument("--rule", default="")
    parser.add_argument(
        "--severity",
        choices=("", "critical", "major", "minor", "info"),
        default="",
    )
    parser.add_argument(
        "--failure-mode",
        choices=("", "ambiguity", "retrieval_failure", "execution_risk", "other_quality"),
        default="",
    )
    parser.add_argument("--repo", default="")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--min-repositories", type=int, default=3)
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.limit <= 500:
            raise ValueError("--limit must be between 1 and 500")
        if not 1 <= args.min_repositories <= 100:
            raise ValueError("--min-repositories must be between 1 and 100")
        result = query(
            _load(args.artifact),
            args.view,
            rule=args.rule,
            severity=args.severity,
            failure_mode=args.failure_mode,
            repo=args.repo,
            limit=args.limit,
            min_repositories=args.min_repositories,
        )
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"audit query failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
