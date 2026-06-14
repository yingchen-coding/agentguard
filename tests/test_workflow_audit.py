import json

from tools.workflow_audit import audit


def test_repository_workflows_stay_within_budget():
    payload, failures = audit(
        __import__("pathlib").Path("evidence/workflow-budget.json")
    )
    assert not failures
    assert payload["passed"]


def test_duplicate_expensive_command_fails(tmp_path, monkeypatch):
    workflow = tmp_path / "ci.yml"
    workflow.write_text(
        "name: ci\non: push\njobs:\n  test:\n    timeout-minutes: 5\n"
        "    steps:\n      - run: python -m build && python -m build\n"
    )
    budget = tmp_path / "budget.json"
    budget.write_text(json.dumps({
        "schema_version": 1,
        "workflows": {
            "ci.yml": {
                "max_jobs_after_matrix": 1,
                "require_job_timeouts": True,
                "require_cancel_in_progress": False,
                "command_budgets": {"python -m build": 1},
            }
        },
    }))
    monkeypatch.setattr("tools.workflow_audit.ROOT", tmp_path)
    _payload, failures = audit(budget)
    assert any("occurs 2 times" in failure for failure in failures)
