"""agent-lint — a deterministic linter for AI agent, command, and skill definitions.

ESLint for the prompts that drive your agents: it parses the markdown + frontmatter
definitions Claude Code (and similar harnesses) load, and flags the failure patterns that
make agents misbehave in production — missing triggers, vague instructions, unguarded
destructive actions, prompt-injection exposure, and assert-without-verify.
"""
from .models import Definition, Finding, Severity, parse_definition
from .linter import Linter, lint_path, lint_paths

__version__ = "0.1.0"

__all__ = [
    "Definition",
    "Finding",
    "Severity",
    "parse_definition",
    "Linter",
    "lint_path",
    "lint_paths",
    "__version__",
]
