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
    p.add_argument("--list-rules", action="store_true", help="print the rule catalog and exit")
    p.add_argument("--version", action="version", version=f"agent-lint {__version__}")
    return p


def _list_rules() -> int:
    from .rules import TITLES
    print("agent-lint rules:\n")
    for code, _ in all_rules():
        print(f"  {code}  {TITLES.get(code, '')}")
    print(f"\n{len(all_rules())} rules. Disable inline with "
          f"`<!-- agent-lint-disable AL202 -->` or globally with --ignore.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        return _list_rules()

    linter = Linter(select=_parse_codes(args.select), ignore=_parse_codes(args.ignore) or set())
    paths = [Path(p) for p in args.paths]

    missing = [p for p in paths if not p.exists()]
    if missing:
        print(f"agent-lint: path not found: {', '.join(str(m) for m in missing)}",
              file=sys.stderr)
        return 2

    report = linter.lint(paths)

    # Common root for tidy relative paths.
    root = None
    if len(paths) == 1 and paths[0].is_dir():
        root = paths[0].resolve()

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

    return report.exit_code(_SEV_NAMES[args.fail_at])


if __name__ == "__main__":
    raise SystemExit(main())
