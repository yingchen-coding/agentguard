"""Maps agent-lint rules to recognized AI-security frameworks.

Each security-relevant rule cites where it sits in the **OWASP Top 10 for LLM Applications (2025)**
and **MITRE ATLAS** — so a finding isn't "a regex fired", it's "this is OWASP LLM01 / ATLAS
AML.T0051, here in your definition". Structure/clarity rules (AL0xx/AL1xx) have no security mapping
and are intentionally absent.
"""
from __future__ import annotations

# OWASP LLM Top 10 (2025) titles, for display.
OWASP = {
    "LLM01": "LLM01:2025 Prompt Injection",
    "LLM02": "LLM02:2025 Sensitive Information Disclosure",
    "LLM03": "LLM03:2025 Supply Chain",
    "LLM05": "LLM05:2025 Improper Output Handling",
    "LLM06": "LLM06:2025 Excessive Agency",
    "LLM09": "LLM09:2025 Misinformation",
}

# MITRE ATLAS technique titles, for display.
ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0011": "User Execution",
}

# rule -> (owasp keys, atlas keys)
REFS: dict[str, tuple[list[str], list[str]]] = {
    "AL200": (["LLM05"], []),
    "AL202": (["LLM01"], ["AML.T0051.001"]),
    "AL203": (["LLM06"], ["AML.T0053"]),
    "AL204": (["LLM09"], []),
    "AL300": (["LLM01", "LLM06"], ["AML.T0051.001"]),
    "AL301": (["LLM02"], ["AML.T0057"]),
    "AL302": (["LLM06"], []),
    "AL303": (["LLM02"], ["AML.T0057"]),
    "AL305": (["LLM01", "LLM05"], ["AML.T0051"]),
    "AL306": (["LLM06"], []),
    "AL307": (["LLM01"], ["AML.T0051.001"]),
    "AL308": (["LLM06"], []),
    "AL310": (["LLM01"], ["AML.T0051"]),
    "AL503": (["LLM02"], ["AML.T0057"]),
    "AL510": (["LLM03"], ["AML.T0011"]),
    "AL511": (["LLM03"], ["AML.T0011"]),
    "AL512": (["LLM03"], ["AML.T0011"]),
    "AL513": (["LLM03"], ["AML.T0010", "AML.T0011"]),
}


def refs_for(rule: str) -> dict:
    """Return {'owasp': [...], 'atlas': [...]} display strings for a rule, or empty lists."""
    owasp_keys, atlas_keys = REFS.get(rule, ([], []))
    return {
        "owasp": [OWASP[k] for k in owasp_keys],
        "atlas": [f"{k} {ATLAS[k]}" for k in atlas_keys],
    }


def short_refs(rule: str) -> str:
    """Compact one-line citation, e.g. 'OWASP LLM01 · ATLAS AML.T0051.001'."""
    owasp_keys, atlas_keys = REFS.get(rule, ([], []))
    parts = []
    if owasp_keys:
        parts.append("OWASP " + "/".join(owasp_keys))
    if atlas_keys:
        parts.append("ATLAS " + "/".join(atlas_keys))
    return " · ".join(parts)
