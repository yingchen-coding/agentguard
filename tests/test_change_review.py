from tools.change_review import render_markdown, review


def test_rule_change_requires_tests_benchmark_and_knowledge():
    packet = review(["agentguard/rules.py", "tests/test_rules.py"])
    assert not packet["passed"]
    assert "precision and recall evidence" in packet["failures"]
    assert "maintainer knowledge update" in packet["failures"]


def test_security_change_with_evidence_requires_human_review():
    packet = review([
        "agentguard/rules.py",
        "tests/test_rules.py",
        "eval/benchmark.py",
        "skills/agentguard-maintainer/SKILL.md",
    ])
    assert packet["passed"]
    assert packet["human_review_required"]
    assert {"security", "trust-boundary"} <= set(packet["review_domains"])


def test_external_action_change_requires_gate_docs_and_tests():
    packet = review([
        "tools/publish_audit_issue.py",
        "tests/test_publish_audit_issue.py",
        "docs/agent-factory.md",
    ])
    assert packet["passed"]
    assert "release" in packet["review_domains"]


def test_markdown_packet_exposes_missing_evidence():
    packet = review(["tools/corpus_audit.py"])
    rendered = render_markdown(packet)
    assert "FAIL" in rendered
    assert "analyst knowledge update" in rendered
