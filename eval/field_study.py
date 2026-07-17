#!/usr/bin/env python3
"""Reproducible field study: exposure rates of agent definitions across plugin corpora.

Given one or more plugin-corpus roots, this scans every agent/command/skill definition, deduplicates
by content hash (installed plugin caches keep orphaned copies that would double-count), and reports
the structural-exposure rates AgentGuard's field study cares about:

  AL202  read untrusted input with no "treat as data" guard  (the injection-guard-absent rate)
  AL300  drivable to run a command / write a file by read content (the full injection->action chain)
  AL3xx  at least one security-class finding (excluding advisory AL302/AL306)

Each root is reported separately (a distribution channel) plus a combined total, so the same code
produces the official-marketplace numbers and any independent third-party corpus for cross-channel
replication. Paths are passed on the command line; nothing is hardcoded.

Run:  python3 eval/field_study.py <plugin-root> [<plugin-root> ...] [--json]
Label a root as name=path to control its display label:
      python3 eval/field_study.py official=/path/to/official thirdparty=/path/to/other
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agentguard.linter import Linter

ADVISORY = {"AL302", "AL306"}


def _rates(results) -> dict:
    seen: dict[str, object] = {}
    for r in results:
        h = hashlib.sha256(Path(r.path).read_bytes()).hexdigest()
        seen.setdefault(h, r)
    uniq = list(seen.values())
    n = len(uniq)
    if not n:
        return {"defs": 0, "al202": 0, "al300": 0, "al3xx": 0}
    al202 = sum("AL202" in {f.rule for f in r.findings} for r in uniq)
    al300 = sum("AL300" in {f.rule for f in r.findings} for r in uniq)
    al3xx = sum(any(f.rule.startswith("AL3") and f.rule not in ADVISORY for f in r.findings)
                for r in uniq)
    return {"defs": n, "al202": al202, "al300": al300, "al3xx": al3xx}


def _pct(a: int, b: int) -> str:
    return f"{a}/{b} ({a / b:.0%})" if b else "0/0 (—)"


def run(specs: list[tuple[str, Path]], as_json: bool) -> dict:
    linter = Linter()
    channels: dict[str, dict] = {}
    all_results = []
    for label, root in specs:
        rep = linter.lint([root])
        channels[label] = _rates(rep.results)
        all_results.extend(rep.results)
    combined = _rates(all_results)

    report = {"channels": channels, "combined": combined}
    if as_json:
        print(json.dumps(report, indent=2))
        return report

    print("AgentGuard field study — structural exposure by plugin corpus\n")
    hdr = f"{'channel':22s} {'defs':>5s} {'no-guard AL202':>16s} {'chain AL300':>14s} " \
          f"{'any-sec AL3xx':>14s}"
    print(hdr)
    print("-" * len(hdr))
    for label, r in channels.items():
        print(f"{label:22s} {r['defs']:5d} {_pct(r['al202'], r['defs']):>16s} "
              f"{_pct(r['al300'], r['defs']):>14s} {_pct(r['al3xx'], r['defs']):>14s}")
    print("-" * len(hdr))
    r = combined
    print(f"{'COMBINED':22s} {r['defs']:5d} {_pct(r['al202'], r['defs']):>16s} "
          f"{_pct(r['al300'], r['defs']):>14s} {_pct(r['al3xx'], r['defs']):>14s}")
    return report


def _parse(spec: str) -> tuple[str, Path]:
    if "=" in spec:
        label, _, path = spec.partition("=")
        return label, Path(path).expanduser()
    p = Path(spec).expanduser()
    return p.name or str(p), p


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("roots", nargs="+", help="plugin-corpus roots, optionally label=path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv[1:])
    specs = [_parse(s) for s in args.roots]
    missing = [str(p) for _, p in specs if not p.exists()]
    if missing:
        print(f"error: missing roots: {', '.join(missing)}", file=sys.stderr)
        return 2
    run(specs, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
