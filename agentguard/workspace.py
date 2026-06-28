"""Agent workspace/runtime planning."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class WorkspaceOption:
    environment: str
    fit: str
    risk: str
    strengths: list[str]
    required_evidence: list[str]
    blockers: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def plan_workspace(text: str) -> dict[str, Any]:
    lower = text.lower()
    options = [
        _local_desktop(lower),
        _remote_mac(lower),
        _cloud_pc(lower),
        _phone_agent(lower),
        _enterprise_app_agent(lower),
    ]
    ranked = sorted(options, key=lambda item: (_fit_rank(item.fit), _risk_rank(item.risk)))
    return {
        "version": 1,
        "surface": "workspace-plan",
        "request": text,
        "policy": (
            "Choose the least-privileged workspace that can capture required evidence. "
            "Private files, microphone, screenshots, purchases, messages, and credentials need "
            "explicit consent and audit logs."
        ),
        "recommendation": ranked[0].environment,
        "options": [item.to_dict() for item in ranked],
    }


def render_workspace_json(plan: dict[str, Any]) -> str:
    return json.dumps(plan, indent=2)


def render_workspace_plan(plan: dict[str, Any]) -> str:
    lines = [
        "env                   fit       risk      evidence",
        "--------------------  --------  --------  --------",
    ]
    for option in plan["options"]:
        lines.append(
            f"{option['environment']:<20}  {option['fit']:<8}  {option['risk']:<8}  "
            f"{', '.join(option['required_evidence'])}"
        )
        if option["blockers"]:
            lines.append(f"  blockers: {', '.join(option['blockers'])}")
    lines.append("")
    lines.append(f"recommendation: {plan['recommendation']}")
    return "\n".join(lines)


def _local_desktop(text: str) -> WorkspaceOption:
    needs_gui = _has_any(text, "screenshot", "screen", "wechat", "browser", "audio", "voice", "gui")
    explicit_remote = _has_any(text, "remote", "mac mini", "tailscale", "rdp", "ssh")
    return WorkspaceOption(
        environment="local-desktop",
        fit="medium" if explicit_remote else "high" if needs_gui else "medium",
        risk="high" if _has_private_surface(text) else "medium",
        strengths=["best access to local apps", "supports screenshots/audio"],
        required_evidence=["app scope", "screenshot log", "permission boundary"],
        blockers=["private data exposure"] if _has_private_surface(text) else [],
    )


def _remote_mac(text: str) -> WorkspaceOption:
    remote = _has_any(text, "remote", "mac mini", "tailscale", "rdp", "ssh")
    return WorkspaceOption(
        environment="remote-mac",
        fit="high" if remote else "medium",
        risk="medium",
        strengths=["reuses existing machine", "keeps data local if tunnel is private"],
        required_evidence=["network path", "latency sample", "access log"],
        blockers=[
            "unreliable audio/screenshot capture"
        ] if _has_any(text, "audio", "voice") else [],
    )


def _cloud_pc(text: str) -> WorkspaceOption:
    cloud = _has_any(text, "cloud", "云电脑", "cloud pc")
    return WorkspaceOption(
        environment="cloud-pc",
        fit="high" if cloud else "low",
        risk="high" if _has_private_surface(text) else "medium",
        strengths=["easy to scale", "clean disposable workspace"],
        required_evidence=["data residency", "egress policy", "cost per hour", "audit log"],
        blockers=["do not upload private local files without a redaction plan"]
        if _has_private_surface(text)
        else [],
    )


def _phone_agent(text: str) -> WorkspaceOption:
    phone = _has_any(text, "phone", "mobile", "ios", "android", "手机")
    return WorkspaceOption(
        environment="phone-agent",
        fit="high" if phone else "low",
        risk="high",
        strengths=["best fit for mobile-only app flows"],
        required_evidence=["screen recording", "tap confirmation", "app permission list"],
        blockers=["small context window", "harder audit", "high accidental-action risk"],
    )


def _enterprise_app_agent(text: str) -> WorkspaceOption:
    enterprise = _has_any(text, "enterprise", "jira", "salesforce", "service", "快递", "订单")
    return WorkspaceOption(
        environment="enterprise-app-agent",
        fit="high" if enterprise else "medium",
        risk="high" if _has_any(text, "order", "purchase", "send", "订单", "下单") else "medium",
        strengths=["narrow app-specific permissions", "stronger audit trail"],
        required_evidence=["role scope", "action allowlist", "audit event export"],
        blockers=["write actions require approval"]
        if _has_any(text, "order", "purchase", "send", "订单", "下单")
        else [],
    )


def _has_any(text: str, *needles: str) -> bool:
    return any(needle in text for needle in needles)


def _has_private_surface(text: str) -> bool:
    return _has_any(
        text,
        "private",
        "local file",
        "documents",
        "wechat",
        "email",
        "medical",
        "audio",
        "voice",
        "隐私",
        "微信",
        "邮件",
        "医疗",
    )


def _fit_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _risk_rank(value: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(value, 4)
