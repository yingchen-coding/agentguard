"""Regression checks for the install and publishing paths users copy from the README."""
from pathlib import Path


ROOT = Path(__file__).parent.parent


def test_composite_action_installs_its_checked_out_source():
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert 'pip install --quiet "$AGENTGUARD_ACTION_PATH"' in action
    assert 'pip install --quiet "agentguard==' not in action
    assert "${{ inputs.args }}" not in action.split("run: |", 1)[-1]


def test_readme_does_not_claim_unpublished_pypi_install():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "\npip install agentguard\n" not in readme
    assert "pip install git+https://github.com/yingchen-coding/agentguard" in readme


def test_publish_workflow_uses_oidc():
    workflow = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    assert "id-token: write" in workflow
    assert "pypa/gh-action-pypi-publish@release/v1" in workflow
    assert "password:" not in workflow
