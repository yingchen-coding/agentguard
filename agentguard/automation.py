"""macOS automation diagnostics for cron/launchd/TCC-style failures."""
from __future__ import annotations

import os
import plistlib
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, Severity

AUTOMATION_TITLES: dict[str, str] = {
    "AL607": "automation log missing, stale, or failing",
    "AL608": "automation path unreadable or missing",
    "AL609": "automation PATH is too small",
    "AL610": "crontab missing, unreadable, or empty",
    "AL611": "launch agent points to a missing executable",
}

_FAILURE_PHRASES = (
    "Operation not permitted",
    "Permission denied",
    "command not found",
    "No such file or directory",
    "not authenticated",
    "could not read",
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def check_log(path: Path, max_age_hours: float, *, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    path = path.expanduser()
    if not path.exists():
        return [_finding(
            "AL607",
            Severity.MAJOR,
            f"Automation log does not exist: {path}",
            "Confirm the job is installed and writes to the expected log path.",
            path,
        )]
    try:
        stat = path.stat()
        text = path.read_text(encoding="utf-8", errors="replace")[-20_000:]
    except PermissionError:
        return [_finding(
            "AL607",
            Severity.MAJOR,
            f"Automation log is not readable: {path}",
            "Grant terminal/cron/launchd Full Disk Access or move the log to a readable path.",
            path,
        )]
    age_hours = (now - datetime.fromtimestamp(stat.st_mtime, timezone.utc)).total_seconds() / 3600
    if age_hours > max_age_hours:
        return [_finding(
            "AL607",
            Severity.MAJOR,
            f"Automation log is stale: {age_hours:.1f}h old, expected <= {max_age_hours:.1f}h",
            "Check whether cron/launchd fired, then inspect auth and macOS permissions.",
            path,
        )]
    phrase = _failure_phrase(text)
    if phrase:
        return [_finding(
            "AL607",
            Severity.MINOR,
            f"Automation log contains failure phrase: {phrase}",
            "Read surrounding log lines before debugging application code.",
            path,
        )]
    return []


def check_path_readable(path: Path) -> list[Finding]:
    path = path.expanduser()
    try:
        if path.is_dir():
            next(path.iterdir(), None)
        else:
            path.open("rb").close()
    except PermissionError:
        return [_finding(
            "AL608",
            Severity.MAJOR,
            f"Automation path is not readable: {path}",
            "Check macOS Privacy & Security > Full Disk Access for terminal, cron, or launchd.",
            path,
        )]
    except FileNotFoundError:
        return [_finding(
            "AL608",
            Severity.MAJOR,
            f"Automation path does not exist: {path}",
            "Fix the path in the job definition or create the directory/file.",
            path,
        )]
    except OSError as exc:
        return [_finding(
            "AL608",
            Severity.MINOR,
            f"Automation path raised {type(exc).__name__}: {exc}",
            "Inspect the path manually; this may be a mount, symlink, or permission issue.",
            path,
        )]
    return []


def check_path_env(path_value: str | None = None) -> list[Finding]:
    path_value = path_value if path_value is not None else os.environ.get("PATH", "")
    parts = [part for part in path_value.split(os.pathsep) if part]
    if len(parts) <= 2 or {"/usr/bin", "/bin"} - set(parts):
        return [Finding(
            "AL609",
            Severity.MINOR,
            f"Automation PATH looks minimal: {path_value}",
            "Cron has a small default PATH. Use absolute paths or set PATH in the job.",
            path="PATH",
        )]
    return []


def check_crontab(
    command_runner: Callable[[list[str]], CommandResult] | None = None,
) -> list[Finding]:
    runner = command_runner or _run_command
    result = runner(["crontab", "-l"])
    if result.returncode != 0:
        return [Finding(
            "AL610",
            Severity.MINOR,
            "Could not read user crontab.",
            "Run `crontab -l` manually; if empty, the job may not be installed for this user.",
            path="crontab",
        )]
    if not result.stdout.strip():
        return [Finding(
            "AL610",
            Severity.MINOR,
            "User crontab is empty.",
            "Install the expected cron entry or check launchd instead.",
            path="crontab",
        )]
    return []


def check_launch_agents(directory: Path | None = None) -> list[Finding]:
    directory = (directory or (Path.home() / "Library" / "LaunchAgents")).expanduser()
    if not directory.exists():
        return [Finding(
            "AL611",
            Severity.MINOR,
            f"LaunchAgents directory does not exist: {directory}",
            "If the automation uses launchd, confirm the plist is installed.",
            path=str(directory),
        )]
    findings: list[Finding] = []
    for plist_path in sorted(directory.glob("*.plist")):
        findings.extend(_check_launch_agent(plist_path))
    if not findings and not any(directory.glob("*.plist")):
        findings.append(Finding(
            "AL611",
            Severity.MINOR,
            f"No LaunchAgent plist files found in {directory}",
            "If the automation uses launchd, install or load the expected plist.",
            path=str(directory),
        ))
    return findings


def scan_automation(
    *,
    logs: list[tuple[Path, float]],
    paths: list[Path],
    include_crontab: bool = True,
    include_launch_agents: bool = True,
    launch_agents_dir: Path | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_path_env())
    for path, max_age_hours in logs:
        findings.extend(check_log(path, max_age_hours))
    for path in paths:
        findings.extend(check_path_readable(path))
    if include_crontab:
        findings.extend(check_crontab())
    if include_launch_agents:
        findings.extend(check_launch_agents(launch_agents_dir))
    findings.sort(key=lambda f: (-f.severity, f.path, f.rule))
    return findings


def _check_launch_agent(plist_path: Path) -> list[Finding]:
    try:
        raw = plistlib.loads(plist_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        return [_finding(
            "AL611",
            Severity.MAJOR,
            f"Cannot read launch agent plist: {type(exc).__name__}: {exc}",
            "Repair or regenerate the plist.",
            plist_path,
        )]
    program = raw.get("Program")
    args = raw.get("ProgramArguments")
    executable = ""
    if isinstance(program, str):
        executable = program
    elif isinstance(args, list) and args and isinstance(args[0], str):
        executable = args[0]
    if not executable:
        return [_finding(
            "AL611",
            Severity.MINOR,
            "Launch agent has no Program or ProgramArguments executable.",
            "Add a Program or ProgramArguments entry.",
            plist_path,
        )]
    if not Path(executable).expanduser().exists():
        return [_finding(
            "AL611",
            Severity.MAJOR,
            f"Launch agent executable does not exist: {executable}",
            "Use an absolute path that exists in non-interactive launchd environments.",
            plist_path,
        )]
    return []


def _run_command(argv: list[str]) -> CommandResult:
    completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _failure_phrase(text: str) -> str:
    lower = text.lower()
    for phrase in _FAILURE_PHRASES:
        if phrase.lower() in lower:
            return phrase
    return ""


def _finding(rule: str, severity: Severity, message: str, fix: str, path: Path) -> Finding:
    return Finding(rule, severity, message, fix, path=str(path))
