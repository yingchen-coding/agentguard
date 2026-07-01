"""Workflow text checks: prompts, shell commands, git logs, and trace snippets."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from .models import Finding, Severity

Surface = Literal["command", "prompt", "git-log", "text"]


@dataclass(frozen=True)
class WorkflowRule:
    code: str
    title: str
    severity: Severity
    surfaces: tuple[Surface, ...]
    pattern: str
    message: str
    fix: str


WORKFLOW_TITLES: dict[str, str] = {
    "AL600": "destructive memory/core-state action",
    "AL601": "identity / AI co-author risk",
    "AL602": "completion claim needs verification",
    "AL603": "recommendation before source check",
    "AL604": "infrastructure should be checked before code",
    "AL605": "fake or stale number risk",
    "AL606": "launch/distribution bottleneck reminder",
}


WORKFLOW_RULES: tuple[WorkflowRule, ...] = (
    WorkflowRule(
        "AL600",
        WORKFLOW_TITLES["AL600"],
        Severity.CRITICAL,
        ("command",),
        (
            r"\b(rm|mv|unlink|shred)\b.*"
            r"(/memory/|MEMORY\.md|CLAUDE\.md|AGENTS\.md|/state/)"
        ),
        "Destructive shell action targets memory or core-state files.",
        "Edit in place, or quarantine with an explicit backup and human approval.",
    ),
    WorkflowRule(
        "AL601",
        WORKFLOW_TITLES["AL601"],
        Severity.MAJOR,
        ("command", "git-log", "text"),
        (
            r"\bgit\s+commit\b|gh\s+pr\s+create|create_pull_request|"
            r"co-authored-by|claude|anthropic|codex|openai"
        ),
        "Identity-bearing action or AI attribution marker found.",
        "Confirm the intended human author/committer and remove AI co-author markers.",
    ),
    WorkflowRule(
        "AL602",
        WORKFLOW_TITLES["AL602"],
        Severity.MAJOR,
        ("command", "prompt", "text"),
        (
            r"\b(done|fixed|passing|green|works|complete|verified|ship|shipped)\b"
            r"|好了|完成|通过|修好"
        ),
        "Completion or green-state claim needs live verification.",
        "Run or read the actual check before claiming done, fixed, green, or passing.",
    ),
    WorkflowRule(
        "AL603",
        WORKFLOW_TITLES["AL603"],
        Severity.MAJOR,
        ("command", "prompt", "text"),
        (
            r"\b(overdue|missing|recommend|exclude|should add|rule out|workup)\b"
            r"|过期|缺|建议|推荐"
        ),
        "Recommendation or gap claim may be made before checking source data.",
        "Search the real source or log first; cite the checked evidence or say it was missing.",
    ),
    WorkflowRule(
        "AL604",
        WORKFLOW_TITLES["AL604"],
        Severity.MINOR,
        ("command", "prompt", "text"),
        (
            r"\bcron(tab)?\b|launchctl|watchdog|scheduled|\.cron\.log|\bCI\b|"
            r"actions/runs|auth|TCC|Full Disk Access"
        ),
        "Infrastructure-sensitive workflow mentioned.",
        "Check logs, freshness, auth, CI, and macOS permissions before debugging code.",
    ),
    WorkflowRule(
        "AL605",
        WORKFLOW_TITLES["AL605"],
        Severity.MAJOR,
        ("command", "prompt", "text"),
        (
            r"\bstock\w*|\bportfolio\b|\bmarket value\b|\bgrant\b|\bbuy\b|"
            r"\bsell\b|\bRSU\b|\bvaluation\b"
        ),
        "Money, portfolio, grant, or valuation language needs current labeled data.",
        "Use current data and label stale, nominal, placeholder, grant, and market values.",
    ),
    WorkflowRule(
        "AL606",
        WORKFLOW_TITLES["AL606"],
        Severity.INFO,
        ("command", "prompt", "text"),
        (
            r"\b(star|stars|traffic|launch|Show HN|Reddit|product|repo|money|"
            r"users|market)\b|流量|发布|赚钱"
        ),
        "Launch, traffic, or product-growth language found.",
        "If the repo works but has no users, treat distribution as the bottleneck.",
    ),
)


def scan_workflow_text(text: str, surface: Surface) -> list[Finding]:
    findings: list[Finding] = []
    for rule in WORKFLOW_RULES:
        if surface not in rule.surfaces:
            continue
        match = re.search(rule.pattern, text, re.IGNORECASE)
        if not match:
            continue
        findings.append(Finding(
            rule.code,
            rule.severity,
            rule.message,
            rule.fix,
            line=text[:match.start()].count("\n") + 1,
            column=match.start() - text.rfind("\n", 0, match.start()),
        ))
    findings.sort(key=lambda f: (-f.severity, f.line, f.rule))
    return findings

