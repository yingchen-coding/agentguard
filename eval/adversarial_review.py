#!/usr/bin/env python3
"""Metamorphic review: security decisions must survive harmless prompt-structure changes."""
from __future__ import annotations

import json
from collections.abc import Callable

if __package__:
    from eval.benchmark import ALARM_RULES, CASES, DEFAULT_BASELINE, run_case
else:
    from benchmark import ALARM_RULES, CASES, DEFAULT_BASELINE, run_case

Mutation = tuple[str, Callable[[str], str]]


def _prefix_prose(body: str, prefix: str) -> str:
    """Mutate prose structure without changing executable fenced examples."""
    in_fence = False
    lines: list[str] = []
    for line in body.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            lines.append(line)
        elif in_fence or not line:
            lines.append(line)
        else:
            lines.append(f"{prefix}{line}")
    return "\n".join(lines)


MUTATIONS: list[Mutation] = [
    ("bulleted", lambda body: _prefix_prose(body, "- ")),
    ("blockquote", lambda body: _prefix_prose(body, "> ")),
    ("section-noise", lambda body: "## Operating Procedure\n\n" + body + "\n\n## End\n"),
]


def review() -> list[str]:
    baseline = json.loads(DEFAULT_BASELINE.read_text(encoding="utf-8"))
    allowed_misses = set(baseline.get("allowed_missed_cases", []))
    failures = []
    checked = 0
    for name, kind, fm, body, expected, _note in CASES:
        if name in allowed_misses:
            continue
        for mutation_name, mutate in MUTATIONS:
            checked += 1
            got = run_case(fm, kind, mutate(body))
            if expected:
                missed = expected - got
                if missed:
                    failures.append(
                        f"{name}/{mutation_name} lost expected rules: {sorted(missed)}"
                    )
            else:
                alarms = got & ALARM_RULES
                if alarms:
                    failures.append(
                        f"{name}/{mutation_name} introduced false alarms: {sorted(alarms)}"
                    )
    minimum = int(baseline.get("min_adversarial_variants", 0))
    if checked < minimum:
        failures.append(f"adversarial inventory shrank: {checked} < required {minimum}")
    return failures


def main() -> int:
    failures = review()
    if failures:
        print("adversarial review failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    checked = (len(CASES) - 1) * len(MUTATIONS)
    print(f"adversarial review passed: {checked} metamorphic cases stayed stable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
