"""Command-line entry point: `agentguard [paths...] [options]`."""
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
        prog="agentguard",
        description="Lint AI agent / command / skill definitions for the failure patterns "
                    "that make agents misbehave in production.",
    )
    p.add_argument("paths", nargs="*", default=["."],
                   help="files or directories to lint (default: current directory)")
    p.add_argument("--discover", action="store_true",
                   help="auto-find every agent definition set (.claude dirs + ~/.claude) under the "
                        "given roots (default: ~/Documents) and scan them all. Machine-installed "
                        "third-party plugins (.claude/plugins/) are skipped like node_modules; "
                        "point agentguard at a plugin path directly to audit it.")
    p.add_argument("-f", "--format", choices=["human", "json", "sarif"], default="human",
                   help="output format (default: human)")
    p.add_argument("--fail-at", choices=list(_SEV_NAMES), default=None,
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
    p.add_argument("--fix", action="store_true",
                   help="auto-harden: append a 'treat read content as data, not instructions' "
                        "guard to definitions missing one (append-only, idempotent, reviewable)")
    p.add_argument("--score", action="store_true",
                   help="print a one-line security grade (A–F) after human-readable results")
    p.add_argument("--no-config", action="store_true",
                   help="ignore any [tool.agentguard] / .agentguard.toml config")
    p.add_argument("--list-rules", action="store_true", help="print the rule catalog and exit")
    p.add_argument("--version", action="version", version=f"agentguard {__version__}")
    return p


def _list_rules() -> int:
    from .frameworks import short_refs
    from .project import PROJECT_TITLES
    from .rules import TITLES

    def line(code: str, title: str) -> str:
        ref = short_refs(code)
        return f"  {code}  {title}" + (f"   ({ref})" if ref else "")

    print("agentguard rules:\n")
    for code, _ in all_rules():
        print(line(code, TITLES.get(code, "")))
    print("\n  -- AL5xx: repo-level, run with --publish-check --")
    for code, title in PROJECT_TITLES.items():
        print(line(code, title))
    total = len(all_rules()) + len(PROJECT_TITLES)
    print(f"\n{total} rules, mapped to OWASP LLM Top 10 (2025) & MITRE ATLAS. Disable inline with "
          f"`<!-- agentguard-disable AL202 -->`\n(or `# agentguard-allow AL510` in code), or "
          f"globally with --ignore. Full reference: docs/rules.md, docs/threat-mapping.md.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        return _list_rules()

    # Auto-discovery: find every agent definition set and scan them all, no paths needed.
    if args.discover:
        from .linter import discover_agent_roots
        if args.paths != ["."]:
            search_roots = [Path(p) for p in args.paths]
        else:
            search_roots = [Path.home() / "Documents"]
        roots = discover_agent_roots(search_roots)
        if not roots:
            print(f"agentguard: no agent definitions (.claude dirs) found under "
                  f"{', '.join(str(r) for r in search_roots)}", file=sys.stderr)
            return 2
        print(f"agentguard: discovered {len(roots)} agent location(s):", file=sys.stderr)
        for r in roots:
            print(f"  {r}", file=sys.stderr)
        return _run(args, roots)

    # Remote scan: a single `owner/repo` or git URL is cloned to a temp dir ("vet before install").
    remote_cleanup = None
    if len(args.paths) == 1:
        from .remote import looks_remote
        if looks_remote(args.paths[0]):
            from .remote import clone_to_temp
            try:
                dest = clone_to_temp(args.paths[0])
            except RuntimeError as e:
                print(f"agentguard: {e}", file=sys.stderr)
                return 2
            print(f"agentguard: scanning {args.paths[0]} (shallow clone)", file=sys.stderr)
            paths = [dest]
            remote_cleanup = dest
    if remote_cleanup is None:
        paths = [Path(p) for p in args.paths]
        missing = [p for p in paths if not p.exists()]
        if missing:
            print(f"agentguard: path not found: {', '.join(str(m) for m in missing)}",
                  file=sys.stderr)
            return 2

    try:
        return _run(args, paths)
    finally:
        if remote_cleanup is not None:
            from .remote import cleanup
            cleanup(remote_cleanup)


def _run(args: argparse.Namespace, paths: list[Path]) -> int:
    # Common root for config discovery and tidy relative paths.
    root = paths[0].resolve() if (len(paths) == 1 and paths[0].is_dir()) else None

    # Config provides defaults; explicit CLI flags win.
    cfg: dict[str, object] = {}
    if not args.no_config:
        from .config import load_config
        cfg = load_config(root or Path("."))

    def _codes(v: object) -> set[str] | None:
        return v if isinstance(v, set) else None

    select = _parse_codes(args.select) if args.select else _codes(cfg.get("select"))
    ignore = _parse_codes(args.ignore) if args.ignore else (_codes(cfg.get("ignore")) or set())
    cfg_fail = cfg.get("fail_at")
    fail_at = args.fail_at or (cfg_fail if isinstance(cfg_fail, str) else "major")
    publish_check = args.publish_check if args.publish_check is not None \
        else bool(cfg.get("publish_check", False))
    if fail_at not in _SEV_NAMES:
        print(f"agentguard: invalid fail-at: {fail_at}", file=sys.stderr)
        return 2

    linter = Linter(select=select, ignore=ignore or set())
    report = linter.lint(paths)

    if args.fix:
        from .fix import apply_fixes
        changed = apply_fixes(report.results)
        if changed:
            print(f"agentguard --fix: added an injection guard to {len(changed)} file(s):",
                  file=sys.stderr)
            for c in changed:
                print(f"  • {c}", file=sys.stderr)
            report = linter.lint(paths)  # re-lint to reflect the fixes
        else:
            print("agentguard --fix: nothing auto-fixable (the guard fix applies to "
                  "AL202/AL300/AL307).", file=sys.stderr)

    if publish_check:
        from .project import scan_project
        scan_root = paths[0] if (len(paths) == 1 and paths[0].is_dir()) else Path(".")
        pf = scan_project(scan_root)
        if linter.select is not None:
            pf = [f for f in pf if f.rule in linter.select]
        pf = [f for f in pf if f.rule not in linter.ignore]
        report.project_findings = pf

    if not report.results and not report.project_findings:
        scanned = args.paths[0] if args.paths else "."
        print(f"agentguard: no agent / command / skill definitions found in {scanned} "
              f"(looked for .md files under agents/ commands/ skills/, or with frontmatter).",
              file=sys.stderr)
        return 0

    if args.update_baseline:
        from .baseline import write_baseline
        n = write_baseline(Path(args.update_baseline), report, root)
        print(f"agentguard: wrote baseline with {n} findings to {args.update_baseline}",
              file=sys.stderr)
        return 0
    if args.baseline:
        from .baseline import apply_baseline, load_baseline
        suppressed = apply_baseline(report, load_baseline(Path(args.baseline)), root)
        if suppressed:
            print(f"agentguard: {suppressed} baselined finding(s) suppressed", file=sys.stderr)

    color = not args.no_color and sys.stdout.isatty() and args.output is None
    if args.format == "json":
        text = render_json(report, root=root)
    elif args.format == "sarif":
        text = render_sarif(report, root=root)
    else:
        text = render_human(report, color=color, root=root)

    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(f"agentguard: wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        print(text)

    if args.score and args.format == "human":
        from .report import render_grade
        print("\n" + render_grade(report, color=color, root=root))

    return report.exit_code(_SEV_NAMES[fail_at])


if __name__ == "__main__":
    raise SystemExit(main())
