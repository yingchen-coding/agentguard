from datetime import date

from tools.verify_contracts import evidence_is_stale, verify


def test_repository_contracts_do_not_drift():
    assert verify() == []


def test_evidence_freshness_boundary():
    assert not evidence_is_stale("2026-01-01", 30, date(2026, 1, 31))
    assert evidence_is_stale("2026-01-01", 30, date(2026, 2, 1))
