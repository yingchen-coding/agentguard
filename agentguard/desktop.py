"""Desktop-agent task planning: classify app scope, action risk, and confirmation gates."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class ActionType(str, Enum):
    READ = "read"
    WRITE = "write"
    AMBIGUOUS = "ambiguous"


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


READ_WORDS = {
    "read", "open", "search", "find", "view", "inspect", "capture", "screenshot",
    "list", "scan", "查看", "搜索", "打开", "读取", "查找", "截图", "浏览",
}
WRITE_WORDS = {
    "send", "delete", "remove", "post", "submit", "purchase", "pay", "buy", "move",
    "rename", "overwrite", "change", "edit", "update", "create", "write", "save",
    "configure", "install", "approve", "发送", "删除", "提交", "购买", "支付", "移动",
    "重命名", "覆盖", "更改", "修改", "更新", "创建", "写入", "保存", "配置", "安装", "批准",
}
CRITICAL_WORDS = {
    "password", "credential", "token", "secret", "private key", "bank", "wire",
    "transfer", "medical", "health", "ssn", "密码", "凭证", "密钥", "银行", "转账",
    "医疗", "病历", "身份证",
}


@dataclass(frozen=True)
class DesktopStep:
    index: int
    instruction: str
    app: str
    action_type: ActionType
    risk: Risk
    requires_confirmation: bool
    evidence_required: list[str]
    blocked_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["action_type"] = self.action_type.value
        data["risk"] = self.risk.value
        return data


@dataclass(frozen=True)
class DesktopPlan:
    original_request: str
    steps: list[DesktopStep]
    policy: str = (
        "This plan is advisory and does not execute desktop actions. Write, send, delete, "
        "purchase, submit, terminal, credential, private-data, and ambiguous desktop steps "
        "require explicit confirmation."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "surface": "desktop-plan",
            "original_request": self.original_request,
            "policy": self.policy,
            "summary": summarize_desktop_plan(self),
            "steps": [step.to_dict() for step in self.steps],
        }


def split_steps(text: str) -> list[str]:
    separator = (
        r"\n+|[;；]|(?:,?\s+\bthen\b\s+)|(?:，?\s*(?:然后|再)\s*)|(?<=[。！？.!?])\s*"
    )
    return [re.sub(r"\s+", " ", part).strip() for part in re.split(separator, text) if part.strip()]


def infer_app(step: str) -> str:
    lower = step.lower()
    if "wechat" in lower or "微信" in step:
        return "WeChat"
    if any(word in lower for word in ("browser", "chrome", "safari", "firefox", "web")) or any(
        word in step for word in ("网页", "浏览器", "搜索")
    ):
        return "Browser"
    if any(word in lower for word in ("file", "finder", "folder", "pdf")) or any(
        word in step for word in ("文件", "文件夹")
    ):
        return "Finder"
    if any(word in lower for word in ("terminal", "shell", "command", "pytest", "git ", "python")):
        return "Terminal"
    if any(word in lower for word in ("mail", "email", "gmail")) or any(
        word in step for word in ("邮件", "邮箱")
    ):
        return "Mail"
    if any(word in lower for word in ("slack", "discord", "teams")):
        return "Chat"
    return "UnknownApp"


def classify_action(step: str) -> ActionType:
    lower = step.lower()
    if any(word in lower or word in step for word in WRITE_WORDS):
        return ActionType.WRITE
    if any(word in lower or word in step for word in READ_WORDS):
        return ActionType.READ
    return ActionType.AMBIGUOUS


def classify_risk(step: str, action_type: ActionType, app: str) -> Risk:
    lower = step.lower()
    if any(word in lower or word in step for word in CRITICAL_WORDS):
        return Risk.CRITICAL
    if action_type is ActionType.WRITE or app == "Terminal":
        return Risk.HIGH
    if action_type is ActionType.AMBIGUOUS or app == "UnknownApp":
        return Risk.MEDIUM
    return Risk.LOW


def evidence_for(app: str, action_type: ActionType, risk: Risk) -> list[str]:
    evidence = ["brief textual result"]
    if app in {"WeChat", "Browser", "Mail", "Chat"}:
        evidence.append("screenshot before and after")
    if app == "Finder":
        evidence.append("affected file paths")
    if app == "Terminal":
        evidence.append("command and captured stdout/stderr")
    if action_type is ActionType.WRITE or risk in {Risk.HIGH, Risk.CRITICAL}:
        evidence.append("explicit human confirmation")
    return evidence


def blocked_reason(action_type: ActionType, risk: Risk) -> str:
    if risk is Risk.CRITICAL:
        return "critical private, credential, financial, or medical surface"
    if action_type is ActionType.WRITE:
        return "write-capable desktop action"
    if action_type is ActionType.AMBIGUOUS:
        return "ambiguous desktop action"
    return ""


def plan_desktop_task(text: str) -> DesktopPlan:
    steps: list[DesktopStep] = []
    for index, instruction in enumerate(split_steps(text), start=1):
        app = infer_app(instruction)
        action_type = classify_action(instruction)
        risk = classify_risk(instruction, action_type, app)
        reason = blocked_reason(action_type, risk)
        steps.append(
            DesktopStep(
                index=index,
                instruction=instruction,
                app=app,
                action_type=action_type,
                risk=risk,
                requires_confirmation=bool(
                    reason or risk in {Risk.MEDIUM, Risk.HIGH, Risk.CRITICAL}
                ),
                evidence_required=evidence_for(app, action_type, risk),
                blocked_reason=reason,
            )
        )
    return DesktopPlan(original_request=text, steps=steps)


def summarize_desktop_plan(plan: DesktopPlan) -> dict[str, int | str]:
    counts: dict[str, int | str] = {
        "steps": len(plan.steps),
        "confirmations": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
        "max_risk": "low",
    }
    order = {Risk.LOW: 0, Risk.MEDIUM: 1, Risk.HIGH: 2, Risk.CRITICAL: 3}
    max_risk = Risk.LOW
    for step in plan.steps:
        if step.requires_confirmation:
            counts["confirmations"] = int(counts["confirmations"]) + 1
        counts[step.risk.value] = int(counts[step.risk.value]) + 1
        if order[step.risk] > order[max_risk]:
            max_risk = step.risk
    counts["max_risk"] = max_risk.value
    return counts


def render_desktop_plan(plan: DesktopPlan) -> str:
    lines = [
        "idx  app         risk      confirm  action      instruction",
        "---  ----------  --------  -------  ----------  -----------",
    ]
    for step in plan.steps:
        lines.append(
            f"{step.index:<3}  {step.app:<10}  {step.risk.value:<8}  "
            f"{str(step.requires_confirmation).lower():<7}  "
            f"{step.action_type.value:<10}  {step.instruction}"
        )
        if step.blocked_reason:
            lines.append(f"     block: {step.blocked_reason}")
        lines.append(f"     evidence: {', '.join(step.evidence_required)}")
    lines.append("")
    lines.append(f"summary: {summarize_desktop_plan(plan)}")
    return "\n".join(lines)


def render_desktop_json(plan: DesktopPlan) -> str:
    return json.dumps(plan.to_dict(), indent=2)
