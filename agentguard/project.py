"""Project-level (AL5xx) checks: distribution & supply-chain readiness.

Where the AL0xx–AL4xx rules judge a single agent/command/skill definition, these judge the *repo*
as a unit — the things that matter when you publish a plugin to a public marketplace or install
someone else's. Two jobs:

  * publish readiness — a public repo needs a LICENSE, a README, no leftover placeholders, and no
    secrets committed;
  * supply-chain safety — the code you ship (or are about to install) shouldn't contain malware
    signatures: pipe-to-shell installers, reverse shells, dynamic exec of decoded/remote payloads,
    or install hooks that run the network.

Run via `agentguard --publish-check <dir>`.
"""
from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterator
from pathlib import Path

from .models import Finding, Severity
from .rules import _SECRET_ASSIGN, _SECRET_LITERAL

PROJECT_TITLES = {
    "AL500": "no LICENSE file (repo legally unusable when public)",
    "AL501": "no README",
    "AL502": "unresolved placeholder shipped in",
    "AL503": "hardcoded secret committed in the repo",
    "AL504": "private/local data leaked in the repo",
    "AL510": "pipe-to-shell execution",
    "AL511": "dynamic exec of decoded/remote content",
    "AL512": "reverse-shell / raw-socket signature",
    "AL513": "install hook runs the shell/network",
}

# Inline escape hatch, e.g. `curl x | sh  # agentguard-allow AL510` (also honors -disable).
_ALLOW_RE = re.compile(r"agentguard-(?:allow|disable)\s+([A-Z0-9, ]+)")


def _line_allows(text: str, pos: int, rule: str) -> bool:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start:] if end == -1 else text[start:end]
    m = _ALLOW_RE.search(line)
    return bool(m and rule in {r.strip() for r in m.group(1).split(",")})


def _load_ignore(root: Path) -> list[str]:
    f = root / ".agentguardignore"
    if not f.is_file():
        return []
    pats = []
    for ln in f.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            pats.append(ln.rstrip("/"))
    return pats


def _ignored(rel: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, f"{pat}/*") or \
           any(fnmatch.fnmatch(seg, pat) for seg in Path(rel).parts):
            return True
    return False

_LICENSE_NAMES = {"license", "license.md", "license.txt", "licence", "licence.md",
                  "copying", "copying.md", "unlicense"}
_README_NAMES = {"readme", "readme.md", "readme.rst", "readme.txt"}

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__",
              ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "site-packages", ".eggs"}

# Files whose *code* we scan for malware signatures (NOT docs — a README discussing `curl | sh`
# is not malware, and scanning .md would false-positive on every security write-up).
_CODE_EXTS = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl",
              ".ps1", ".php", ".lua"}
_CODE_NAMES = {"package.json", "pyproject.toml", "setup.py", "setup.cfg", "makefile"}
# Files we scan for placeholders / secrets (shipped text, incl. docs & manifests).
_TEXT_EXTS = _CODE_EXTS | {".md", ".rst", ".txt", ".toml", ".json", ".yml", ".yaml", ".cfg", ".ini"}

_PLACEHOLDER = re.compile(
    r"(YOUR_USERNAME|YOUR_ORG|YOURNAME|YOUR_NAME_HERE|CHANGE_?ME|REPLACE_?ME|"
    r"<your-[a-z-]+>|TODO_USERNAME|INSERT_[A-Z_]+_HERE|example\.com/your)",
)

_PUBLIC_PERSONAL_INFO_MARKERS = re.compile(
    r"("
    # Local machine paths and temporary screenshot/cache paths.
    r"/Users/[^/\s]+/|/home/[^/\s]+/|/var/folders/[^\s\"')>]+|"
    r"TemporaryItems/|NSIRD_screencaptureui_|"
    # Private GitHub attachment URLs and common private workspace names.
    r"private-user-images\.githubusercontent\.com|"
    r"Documents/(?:"
    + "|".join([
        "mar" + "vin",
        "learn" + "ing",
        "medical" + "-agent",
        "personal" + "_medical_record",
        "noval" + "-agent",
    ])
    + r")|"
    # Credential assignment stubs and common token shapes.
    r"\b(?:"
    + "|".join([
        "OPEN" + "AI",
        "ANTH" + "ROPIC",
        "GOOGLE",
        "GITHUB",
        "AWS",
        "AZURE",
        "DATA" + "BRICKS",
    ])
    + r")_[A-Z0-9_]*(?:KEY|TOKEN|SECRET)\b\s*[:=]|"
    r"\bghp_[A-Za-z0-9_]+|"
    r"\bsk-[A-Za-z0-9_-]{20,}|"
    r"\bxox[baprs]-[A-Za-z0-9-]+|"
    # Human contact info shapes. Maintainers can allow intentional public project emails inline.
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|"
    r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"
    r")",
    re.IGNORECASE,
)

# ── malware / supply-chain signatures (high precision; low false-positive by design) ──
_PIPE_TO_SHELL = re.compile(
    r"(curl|wget)\b[^\n|>]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?)\b", re.IGNORECASE)
_REVERSE_SHELL = re.compile(
    r"(/dev/tcp/\d|/dev/udp/\d|\bnc(?:at)?\s+(?:-[a-z]*e|.*-e\b)|bash\s+-i\s*>&|"
    r"sh\s+-i\s*>&|mkfifo\b[^\n]*\|\s*nc\b|socket\.socket\([^\n]*\)[^\n]*\.connect\()",
    re.IGNORECASE)
_DYNAMIC_EXEC = re.compile(
    r"(eval|exec)\s*\(\s*(base64\.b64decode|atob|bytes\.fromhex|codecs\.decode)|"
    r"(eval|exec)\s*\(\s*(requests\.get|urllib|urlopen|fetch)\(|"
    r"base64\s+(?:-d|--decode)\b[^\n]*\|\s*(sh|bash)|"
    r"echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+(?:-d|--decode)\s*\|\s*(sh|bash)",
    re.IGNORECASE)
_INSTALL_HOOK = re.compile(
    r"\"(pre|post)install\"\s*:\s*\"[^\"]*(curl|wget|node\s+-e|python\s+-c|\bsh\b|\beval\b|\|\s*sh)",
    re.IGNORECASE)


def _walk(root: Path) -> Iterator[Path]:
    # Prune heavy dirs (node_modules, .git, .venv, …) during traversal rather than after — on a
    # repo with dependencies, rglob("*") would crawl thousands of files we'd only discard.
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            yield Path(dirpath) / fn


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def scan_project(root: Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    ignore = _load_ignore(root)
    names = {p.name.lower() for p in root.iterdir() if p.is_file()} if root.is_dir() else set()

    # ── publish readiness ──
    if not (names & _LICENSE_NAMES):
        findings.append(Finding(
            "AL500", Severity.MAJOR,
            "No LICENSE file — a public repo with no license is 'all rights reserved' by default: "
            "nobody may legally use, fork, or depend on it, which kills adoption.",
            "Add a LICENSE (MIT/Apache-2.0 are the usual permissive choices).", path="."))
    if not (names & _README_NAMES):
        findings.append(Finding(
            "AL501", Severity.MINOR,
            "No README — the first thing a visitor looks for; without it the repo "
            "reads as abandoned.",
            "Add a README.md describing what it does, install, and usage.", path="."))

    for p in _walk(root):
        rel = _rel(p, root)
        if _ignored(rel, ignore):
            continue
        ext = p.suffix.lower()
        name = p.name.lower()
        text = None

        # placeholders + secrets in any shipped text file
        if ext in _TEXT_EXTS or name in _CODE_NAMES:
            text = _read(p)
            pm = _PLACEHOLDER.search(text)
            if pm and not _line_allows(text, pm.start(), "AL502"):
                findings.append(Finding(
                    "AL502", Severity.MAJOR,
                    f'Unresolved placeholder "{pm.group(0)}" — publishing with template stubs left '
                    f"in looks unfinished and breaks links/badges.",
                    "Replace every placeholder with the real value before publishing.",
                    line=text[:pm.start()].count("\n") + 1, path=rel))
            for rx in (_SECRET_LITERAL, _SECRET_ASSIGN):
                sm = rx.search(text)
                if sm and not _line_allows(text, sm.start(), "AL503"):
                    findings.append(Finding(
                        "AL503", Severity.CRITICAL,
                        "Hardcoded secret committed in the repo — it will live in git history "
                        "forever and ships to everyone who clones it.",
                        "Remove it, rotate the credential, and load it from the environment.",
                        line=text[:sm.start()].count("\n") + 1, path=rel))
                    break
            lm = _PUBLIC_PERSONAL_INFO_MARKERS.search(text)
            if lm and lm.group(0).lower() == "git@github.com":
                lm = None
            if lm and not _line_allows(text, lm.start(), "AL504"):
                findings.append(Finding(
                    "AL504", Severity.MAJOR,
                    "Personal/private data marker committed in the repo — public packages should "
                    "not ship local user paths, temporary screenshot paths, private attachment "
                    "URLs, private workspace names, personal contact details, or credential stubs.",
                    "Replace it with a synthetic example, a redacted placeholder, or a documented "
                    "environment variable name with no value. If a maintainer email is "
                    "intentionally public metadata, add an inline agentguard-allow AL504 comment.",
                    line=text[:lm.start()].count("\n") + 1, path=rel))

        # malware signatures in code/scripts/manifests only
        if ext in _CODE_EXTS or name in _CODE_NAMES:
            if text is None:
                text = _read(p)
            for rule, rx, sev, what, fix in (
                ("AL510", _PIPE_TO_SHELL, Severity.CRITICAL,
                 "Pipe-to-shell execution (e.g. `curl … | sh`) — runs arbitrary remote code with "
                 "no review; the canonical supply-chain attack vector.",
                 "Download, checksum, and inspect before executing; never pipe a network response "
                 "straight into a shell."),
                ("AL512", _REVERSE_SHELL, Severity.CRITICAL,
                 "Reverse-shell / raw-socket signature — code that opens a shell back to a remote "
                 "host. Almost never legitimate in a published tool.",
                 "Remove it. If this is a security tool that needs it, isolate and document it "
                 "loudly."),
                ("AL511", _DYNAMIC_EXEC, Severity.CRITICAL,
                 "Dynamic execution of decoded/remote content (eval/exec of base64- or "
                 "network-sourced data) — classic payload obfuscation.",
                 "Never eval/exec decoded or fetched data; use explicit, auditable code paths."),
                ("AL513", _INSTALL_HOOK, Severity.MAJOR,
                 "Install hook runs the shell/network (pre/postinstall) — executes on every "
                 "`npm install`, before the user runs anything. A favorite malware foothold.",
                 "Remove network/shell from install hooks; do setup explicitly at runtime."),
            ):
                m = rx.search(text)
                if m and not _line_allows(text, m.start(), rule):
                    findings.append(Finding(
                        rule, sev, what, fix,
                        line=text[:m.start()].count("\n") + 1, path=rel))

    findings.sort(key=lambda f: (-f.severity, f.path, f.line, f.rule))
    return findings
