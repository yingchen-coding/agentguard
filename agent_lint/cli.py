"""Command-line entry point: `agent-lint [paths...] [options]`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .linter import Linter
from .models import Severity
from .report import render_human, render_json, render_sarif
from .rules import all_rules

_SEV_NAMES = {s.label: s for s in Severity}


def _parse_codes(value: str | None) -> set[str] | None:
    if not value:
        return None
    return {c.strip().upper() for c in value.split(",") if c.strip()}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-lint",
        description="Lint AI agent / command / skill definitions for the failure patterns "
                    "that make agents misbehave in production.",
    )
    p.add_argument("paths", nargs="*", default=["."],
                   help="files or directories to lint (default: current directory)")
    p.add_argument("-f", "--format", choices=["human", "json", "sarif"], default="human",
                   help="output format (default: human)")
    p.add_argument("--fail-at", choices=list(_SEV_NAMES), default="major",
                   help="minimum severity that makes the run fail (exit 1). default: major")
    p.add_argument("--select", metavar="CODES",
                   help="only run these rule codes (comma-separated, e.g. AL202,AL203)")
    p.add_argument("--ignore", metavar="CODES",
                   help="skip these rule codes (comma-separated)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument("-o", "--output", metavar="FILE", help="write report to FILE instead of stdout")
    p.add_argument("--publish-check", action="store_true", default=None,
                   help="also run repo-level distribution/supply-chain checks (AL5xx): LICENSE, "
                        "README, leftover placeholders, committed secrets, and malware signatures")
    p.add_argument("--baseline", metavar="FILE",
                   help="suppress findings recorded in FILE; report/fail only on new ones")
    p.add_argument("--update-baseline", metavar="FILE",
                   help="write the current findings to FILE as the new baseline and exit 0")
    p.add_argument("--no-config", action="store_true",
                   help="ignore any [tool.agent-lint] / .agent-lint.toml config")
    p.add_argument("--list-rules", action="store_true", help="print the rule catalog and exit")
    p.add_argument("--version", action="version", version=f"agent-lint {__version__}")
    return p


_PROJECT_RULES = [
    ("AL500", "no LICENSE file (repo legally unusable when public)"),
    ("AL501", "no README"),
    ("AL502", "unresolved placeholder (YOUR_USERNAME, CHANGEME, …)"),
    ("AL503", "hardcoded secret committed in the repo"),
    ("AL510", "pipe-to-shell execution (curl … | sh)"),  # agent-lint-allow AL510
    ("AL511", "dynamic exec of decoded/remote content"),
    ("AL512", "reverse-shell / raw-socket signature"),
    ("AL513", "install hook runs the shell/network (pre/postinstall)"),
]


def _list_rules() -> int:
    from .rules import TITLES
    print("agent-lint rules:\n")
    for code, _ in all_rules():
        print(f"  {code}  {TITLES.get(code, '')}")
    print("\n  -- AL5xx: repo-level, run with --publish-check --")
    for code, title in _PROJECT_RULES:
        print(f"  {code}  {title}")
    total = len(all_rules()) + len(_PROJECT_RULES)
    print(f"\n{total} rules. Disable inline with `<!-- agent-lint-disable AL202 -->` "
          f"(or `# agent-lint-allow AL510` in code), or globally with --ignore.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        return _list_rules()

    paths = [Path(p) for p in args.paths]
    missing = [p for p in paths if not p.exists()]
    if missing:
        print(f"agent-lint: path not found: {', '.join(str(m) for m in missing)}",
              file=sys.stderr)
        return 2

    # Common root for config discovery and tidy relative paths.
    root = paths[0].resolve() if (len(paths) == 1 and paths[0].is_dir()) else None

    # Config provides defaults; explicit CLI flags win.
    cfg = {}
    if not args.no_config:
        from .config import load_config
        cfg = load_config(root or Path("."))
    select = _parse_codes(args.select) if args.select else cfg.get("select")
    ignore = _parse_codes(args.ignore) if args.ignore else cfg.get("ignore", set())
    fail_at = args.fail_at if args.fail_at != "major" else cfg.get("fail_at", "major")
    publish_check = args.publish_check if args.publish_check is not None \
        else cfg.get("publish_check", False)
    if fail_at not in _SEV_NAMES:
        print(f"agent-lint: invalid fail-at: {fail_at}", file=sys.stderr)
        return 2

    linter = Linter(select=select, ignore=ignore or set())
    report = linter.lint(paths)

    if publish_check:
        from .project import scan_project
        scan_root = paths[0] if (len(paths) == 1 and paths[0].is_dir()) else Path(".")
        pf = scan_project(scan_root)
        if linter.select is not None:
            pf = [f for f in pf if f.rule in linter.select]
        pf = [f for f in pf if f.rule not in linter.ignore]
        report.project_findings = pf

    if args.update_baseline:
        from .baseline import write_baseline
        n = write_baseline(Path(args.update_baseline), report, root)
        print(f"agent-lint: wrote baseline with {n} findings to {args.update_baseline}",
              file=sys.stderr)
        return 0
    if args.baseline:
        from .baseline import load_baseline, apply_baseline
        suppressed = apply_baseline(report, load_baseline(Path(args.baseline)), root)
        if suppressed:
            print(f"agent-lint: {suppressed} baselined finding(s) suppressed", file=sys.stderr)

    color = not args.no_color and sys.stdout.isatty() and args.output is None
    if args.format == "json":
        text = render_json(report, root=root)
    elif args.format == "sarif":
        text = render_sarif(report, root=root)
    else:
        text = render_human(report, color=color, root=root)

    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"agent-lint: wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(text)

    return report.exit_code(_SEV_NAMES[fail_at])


if __name__ == "__main__":
    raise SystemExit(main())
