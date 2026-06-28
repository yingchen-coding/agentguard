"""Agent interoperability readiness checks."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = {
    "agent_id": ("AI101", "major", "Declare a stable agent_id for identity and audit joins."),
    "name": ("AI102", "minor", "Declare a human-readable agent name."),
    "version": ("AI103", "minor", "Declare a version so compatibility can be tracked."),
    "capabilities": ("AI104", "major", "Declare capabilities as structured names."),
    "tools": ("AI105", "major", "Declare tool schemas or tool names explicitly."),
    "permissions": ("AI106", "major", "Declare permission boundaries for tools and data access."),
    "audit": ("AI107", "major", "Declare audit/logging fields for actions and handoffs."),
}


@dataclass(frozen=True)
class InteropFinding:
    rule: str
    severity: str
    message: str
    fix: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "fix": self.fix,
        }


def load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("interop manifest must be a JSON object")
    return data


def check_interop_manifest(manifest: dict[str, Any]) -> list[InteropFinding]:
    findings: list[InteropFinding] = []
    for field, (rule, severity, fix) in REQUIRED_FIELDS.items():
        if not manifest.get(field):
            findings.append(
                InteropFinding(rule, severity, f"Missing interop field: {field}.", fix)
            )

    capabilities = manifest.get("capabilities")
    if capabilities is not None and not _list_of_objects_or_strings(capabilities):
        findings.append(
            InteropFinding(
                "AI108",
                "major",
                "capabilities must be a list of strings or objects.",
                "Use a list so other agents can inspect capability names and scopes.",
            )
        )

    tools = manifest.get("tools")
    if tools is not None and not isinstance(tools, list):
        findings.append(
            InteropFinding(
                "AI109",
                "major",
                "tools must be a list.",
                "Represent each callable tool with a name and optional input schema.",
            )
        )
    elif isinstance(tools, list):
        for index, tool in enumerate(tools, start=1):
            if not isinstance(tool, dict):
                findings.append(
                    InteropFinding(
                        "AI110",
                        "minor",
                        f"tool #{index} is not an object.",
                        "Use objects like {'name': 'search', 'input_schema': {...}}.",
                    )
                )
                continue
            if not tool.get("name"):
                findings.append(
                    InteropFinding(
                        "AI111",
                        "major",
                        f"tool #{index} is missing name.",
                        "Give every tool a stable name.",
                    )
                )
            if "input_schema" not in tool:
                findings.append(
                    InteropFinding(
                        "AI112",
                        "minor",
                        f"tool #{index} is missing input_schema.",
                        "Add a JSON-schema-like input contract for compatibility testing.",
                    )
                )

    permissions = manifest.get("permissions")
    if isinstance(permissions, dict):
        if not permissions.get("data_access"):
            findings.append(
                InteropFinding(
                    "AI113",
                    "major",
                    "permissions.data_access is missing.",
                    "Declare whether the agent can read local, remote, private, or public data.",
                )
            )
        if not permissions.get("confirmation_required_for"):
            findings.append(
                InteropFinding(
                    "AI114",
                    "major",
                    "permissions.confirmation_required_for is missing.",
                    "List action classes that require explicit human confirmation.",
                )
            )

    audit = manifest.get("audit")
    if isinstance(audit, dict) and not audit.get("event_fields"):
        findings.append(
            InteropFinding(
                "AI115",
                "minor",
                "audit.event_fields is missing.",
                "List log fields such as agent_id, tool, input_hash, decision, and timestamp.",
            )
        )

    return findings


def render_interop_json(
    path: Path,
    manifest: dict[str, Any],
    findings: list[InteropFinding],
) -> str:
    return json.dumps(
        {
            "version": 1,
            "surface": "interop",
            "path": str(path),
            "agent_id": manifest.get("agent_id", ""),
            "summary": {"findings": len(findings)},
            "findings": [finding.to_dict() for finding in findings],
        },
        indent=2,
    )


def render_interop_human(
    path: Path,
    manifest: dict[str, Any],
    findings: list[InteropFinding],
) -> str:
    if not findings:
        return f"agentguard: interop manifest clean: {path}"
    lines = [
        f"interop:{path}",
        f"  agent_id: {manifest.get('agent_id') or '-'}",
    ]
    for finding in findings:
        lines.append(f"  {finding.severity:<8} {finding.rule}  {finding.message}")
        lines.append(f"            fix: {finding.fix}")
    return "\n".join(lines)


def interop_exit_code(findings: list[InteropFinding], fail_at: str) -> int:
    order = {"info": 1, "minor": 2, "major": 3, "critical": 4}
    threshold = order[fail_at]
    worst = max((order.get(finding.severity, 1) for finding in findings), default=0)
    return 1 if worst >= threshold else 0


def _list_of_objects_or_strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, (dict, str)) for item in value)
