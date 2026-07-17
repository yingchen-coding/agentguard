#!/usr/bin/env python3
"""Naive-baseline comparison on the same 28-case benchmark agentguard is gated on.

Two obvious deterministic alternatives to a capability model, plus their conjunction:

  grant    — flag any definition whose frontmatter grants an exec/write-capable tool
             (or omits `tools:`, which inherits full privilege). This is what a
             least-privilege audit that never reads the body would do.
  keyword  — flag any definition whose text matches a dangerous-keyword grep
             (rm/curl/password/secret/token/delete/execute...). This is the naive
             port of code-SAST string matching to agent definitions.
  both     — flag only when grant AND keyword agree.

Scoring is case-level against the benchmark's own labels: a positive case counts as
caught if the baseline flags it at all; a safe case flagged at all is a false alarm.
This is deliberately generous to the baselines — agentguard's own gate additionally
requires the *right rule* to fire.

Run:  python3 eval/naive_baselines.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eval.benchmark import CASES

EXEC_TOOLS = re.compile(r"\b(Bash|Write|Edit|NotebookEdit)\b")
KEYWORDS = re.compile(
    r"(rm -|curl|password|secret|token|delete|run (any|the) command|execute)", re.I
)


def case_text(case) -> str:
    _name, _kind, fm, body, _expected, _note = case
    fm_lines = [f"{k}: {v}" for k, v in fm.items()]
    return "\n".join(["---", *fm_lines, "---", body])


def grant_flags(case) -> bool:
    fm = case[2]
    return "tools" not in fm or bool(EXEC_TOOLS.search(str(fm.get("tools", ""))))


def keyword_flags(case) -> bool:
    return bool(KEYWORDS.search(case_text(case)))


def score(flag_fn) -> dict:
    tp = fp = fn = tn = 0
    for case in CASES:
        flagged = flag_fn(case)
        if case[4]:  # expected rules non-empty -> vulnerable case
            tp += flagged
            fn += not flagged
        else:
            fp += flagged
            tn += not flagged
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    return {"recall": recall, "precision": precision, "false_alarms": fp}


def main() -> int:
    rows = [
        ("grant-based (exec-capable grant)", grant_flags),
        ("keyword grep", keyword_flags),
        ("grant AND keyword", lambda c: grant_flags(c) and keyword_flags(c)),
    ]
    npos = sum(1 for c in CASES if c[4])
    print(f"naive baselines on the gated benchmark ({npos} vulnerable / "
          f"{len(CASES) - npos} safe cases)")
    print(f"{'baseline':38s} {'recall':>7s} {'precision':>10s} {'false alarms':>13s}")
    for name, fn in rows:
        s = score(fn)
        print(f"{name:38s} {s['recall']:7.2f} {s['precision']:10.2f} "
              f"{s['false_alarms']:13d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
