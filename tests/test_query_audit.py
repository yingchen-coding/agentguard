from __future__ import annotations

from tools.query_audit import query

PAYLOAD = {
    "schema_version": 1,
    "summary": {
        "raw_findings": 4,
        "unique_findings": 2,
    },
    "repositories": [
        {"name": "one", "ok": True, "error": "", "patch": "one.patch", "revision": "abc"},
        {"name": "two", "ok": False, "error": "clone failed", "patch": "", "revision": ""},
    ],
    "diff": {"new": ["a"], "resolved": ["z"], "unchanged": ["b"]},
    "findings": [
        {
            "fingerprint": "a",
            "rule": "AL300",
            "severity": "critical",
            "failure_mode": "execution_risk",
            "fix": "add a guard",
            "occurrences": [{"repo": "one", "path": "a.md", "line": 1}],
        },
        {
            "fingerprint": "b",
            "rule": "AL004",
            "severity": "major",
            "failure_mode": "ambiguity",
            "fix": "add a trigger",
            "occurrences": [
                {"repo": "one", "path": "b.md", "line": 1},
                {"repo": "two", "path": "b.md", "line": 1},
            ],
        },
    ],
}


def test_summary_computes_value_metrics():
    result = query(PAYLOAD, "summary")
    assert result["duplicate_rate"] == 0.5
    assert result["repair_repository_coverage"] == 0.5
    assert result["failed_repositories"][0]["name"] == "two"


def test_hotspots_use_structured_filters():
    result = query(PAYLOAD, "hotspots", failure_mode="ambiguity")
    assert result["unique_findings"] == 1
    assert result["top_rules"] == [("AL004", 1)]


def test_new_view_returns_only_new_fingerprints():
    result = query(PAYLOAD, "new")
    assert result["count"] == 1
    assert result["findings"][0]["fingerprint"] == "a"


def test_automation_view_surfaces_patterns_repeated_across_repositories():
    result = query(PAYLOAD, "automation", min_repositories=2)
    assert result["candidates"][0]["rule"] == "AL004"
    assert result["candidates"][0]["repository_count"] == 2
