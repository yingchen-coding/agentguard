#!/usr/bin/env python3
"""External validation on the public MaliciousAgentSkillsBench artifact.

The released malicious URLs are intentionally redacted, so this benchmark uses:

* the authors' defanged, behaviorally confirmed malicious sample as the positive; and
* a deterministic repository-disjoint sample from the released ``safe`` metadata as weak
  negatives.

Run:
    python eval/malicious_skills_bench.py --safe-sample 25
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from agentguard.linter import Linter
from agentguard.project import scan_project

DATASET_COMMIT = "9b525dbbfb528ed152a6a9e3ce43e29eb8686515"
RAW_ROOT = (
    "https://raw.githubusercontent.com/protectskills/"
    f"MaliciousAgentSkillsBench/{DATASET_COMMIT}"
)
DATASET_URL = f"{RAW_ROOT}/data/skills_dataset.csv"
POSITIVE_FILES = {
    "SKILL.md": f"{RAW_ROOT}/code/samples/math-calculator/SKILL.md",
    "scripts/calculate.py": (
        f"{RAW_ROOT}/code/samples/math-calculator/scripts/calculate.py"
    ),
}

# Rules that assert an exploitable definition or malicious implementation, rather than general
# quality/publishing advice. This matches the alarm subset used by eval/benchmark.py.
DEFINITION_ALARMS = {
    "AL202",
    "AL203",
    "AL300",
    "AL301",
    "AL305",
    "AL307",
    "AL308",
    "AL310",
}
PROJECT_ALARMS = {"AL510", "AL511", "AL512", "AL513"}
USER_AGENT = "agentguard-external-benchmark/1"
# api.github.com's tree/blob API is rate-limited to 60 requests/hour when unauthenticated —
# resolving ~25 safe skills routinely needs 2-3x that many candidate lookups (many repos have
# renamed/deleted the referenced skill, or the dataset's slug no longer resolves), so an
# unauthenticated run reliably exhausts the limit partway through and silently truncates the
# sample. A token raises the ceiling to 5000/hour. raw.githubusercontent.com is unauthenticated
# and uncapped, so the token is only attached to api.github.com requests.
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")  # agentguard-allow AL504


def _get(url: str) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    if GITHUB_TOKEN and urlsplit(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=8) as response:
        return response.read()


def _slug_from_archive(url: str) -> tuple[str, str] | None:
    match = re.fullmatch(
        r"https://github\.com/([^/]+)/([^/]+)/archive/main\.zip", url
    )
    return (match.group(1), match.group(2)) if match else None


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _candidate_rows(csv_bytes: bytes) -> list[dict[str, str]]:
    rows = csv.DictReader(io.StringIO(csv_bytes.decode("utf-8")))
    by_repo: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows:
        slug = _slug_from_archive(row["url"])
        if row["classification"] != "safe" or slug is None:
            continue
        key = slug
        candidate = {**row, "owner": slug[0], "github_repo": slug[1]}
        current = by_repo.get(key)
        if current is None or candidate["skill_name"] < current["skill_name"]:
            by_repo[key] = candidate
    return sorted(
        by_repo.values(),
        key=lambda row: hashlib.sha256(
            f"{row['owner']}/{row['github_repo']}/{row['skill_name']}".encode()
        ).hexdigest(),
    )


def _github_tree(owner: str, repo: str) -> tuple[str, list[str]]:
    """Resolve the branch from the dataset-era main/master convention without a metadata call."""
    last_error: urllib.error.HTTPError | None = None
    for branch in ("main", "master"):
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        try:
            payload = json.loads(_get(url))
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            last_error = error
            continue
        return (
            branch,
            [
                item["path"]
                for item in payload.get("tree", [])
                if item.get("type") == "blob" and item["path"].lower().endswith("skill.md")
            ],
        )
    assert last_error is not None
    raise last_error


def _select_skill_path(paths: list[str], skill_name: str) -> str | None:
    target = _normalized(skill_name)
    exact = [
        path
        for path in paths
        if _normalized(Path(path).parent.name) == target
    ]
    if exact:
        return sorted(exact, key=lambda path: (len(Path(path).parts), path))[0]
    if len(paths) == 1:
        return paths[0]
    return None


def _scan_skill(path: Path) -> set[str]:
    report = Linter().lint([path])
    return {
        finding.rule
        for result in report.results
        for finding in result.findings
        if finding.rule in DEFINITION_ALARMS
    }


def _scan_project(path: Path) -> set[str]:
    return {
        finding.rule
        for finding in scan_project(path)
        if finding.rule in PROJECT_ALARMS
    }


def evaluate(safe_sample: int, candidate_limit: int) -> dict[str, object]:
    dataset = _get(DATASET_URL)
    dataset_sha256 = hashlib.sha256(dataset).hexdigest()
    candidates = _candidate_rows(dataset)

    rows: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="agentguard-msb-") as temp:
        root = Path(temp)
        positive = root / "positive"
        for relative, url in POSITIVE_FILES.items():
            target = positive / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_get(url))
        positive_rules = _scan_skill(positive / "SKILL.md") | _scan_project(positive)

        attempted = 0
        for candidate in candidates:
            if len(rows) >= safe_sample:
                break
            if attempted >= candidate_limit:
                break
            attempted += 1
            owner = candidate["owner"]
            repo = candidate["github_repo"]
            skill_name = candidate["skill_name"]
            try:
                branch, paths = _github_tree(owner, repo)
                skill_path = _select_skill_path(paths, skill_name)
                if skill_path is None:
                    failures.append(
                        {
                            "repo": f"{owner}/{repo}",
                            "skill": skill_name,
                            "reason": "skill path not uniquely resolved",
                        }
                    )
                    continue
                raw_url = (
                    f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{skill_path}"
                )
                target = root / "safe" / f"{len(rows):03d}" / "SKILL.md"
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(_get(raw_url))
                rules = sorted(_scan_skill(target))
                rows.append(
                    {
                        "repo": f"{owner}/{repo}",
                        "skill": skill_name,
                        "source_path": skill_path,
                        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                        "alarm_rules": rules,
                    }
                )
            except (OSError, ValueError, urllib.error.HTTPError) as error:
                failures.append(
                    {
                        "repo": f"{owner}/{repo}",
                        "skill": skill_name,
                        "reason": (
                            f"HTTP {error.code}"
                            if isinstance(error, urllib.error.HTTPError)
                            else type(error).__name__
                        ),
                    }
                )

    alarm_counts = Counter(rule for row in rows for rule in row["alarm_rules"])
    false_alarm_rows = [row for row in rows if row["alarm_rules"]]
    return {
        "benchmark": "ProtectSkills/MaliciousAgentSkillsBench",
        "dataset_commit": DATASET_COMMIT,
        "dataset_sha256": dataset_sha256,
        "negative_label_caveat": (
            "Released 'safe' rows are registry skills with no study static-analysis flags, "
            "not independently behavior-verified benign labels."
        ),
        "positive": {
            "name": "math-calculator",
            "provenance": "authors' defanged controlled copy of confirmed rest_1659",
            "detected": bool(positive_rules),
            "alarm_rules": sorted(positive_rules),
        },
        "safe_sample": {
            "requested": safe_sample,
            "resolved": len(rows),
            "repo_disjoint": True,
            "definition_alarm_skills": len(false_alarm_rows),
            "definition_alarm_rate": (
                len(false_alarm_rows) / len(rows) if rows else None
            ),
            "rule_counts": dict(sorted(alarm_counts.items())),
            "rows": rows,
        },
        "resolution": {
            "candidate_limit": candidate_limit,
            "attempted": attempted,
            "unresolved": len(failures),
        },
        "resolution_failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--safe-sample", type=int, default=25)
    parser.add_argument(
        "--candidate-limit",
        type=int,
        help="maximum repository candidates to resolve (default: 20x safe sample)",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.safe_sample < 1:
        parser.error("--safe-sample must be positive")
    candidate_limit = args.candidate_limit or args.safe_sample * 20
    if candidate_limit < args.safe_sample:
        parser.error("--candidate-limit must be at least --safe-sample")
    result = evaluate(args.safe_sample, candidate_limit)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    positive_ok = bool(result["positive"]["detected"])
    enough_negatives = result["safe_sample"]["resolved"] == args.safe_sample
    return 0 if positive_ok and enough_negatives else 1


if __name__ == "__main__":
    raise SystemExit(main())
