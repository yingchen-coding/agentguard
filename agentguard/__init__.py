"""agentguard — a deterministic linter for AI agent, command, and skill definitions.

ESLint for the prompts that drive your agents: it parses the markdown + frontmatter
definitions Claude Code (and similar harnesses) load, and flags the failure patterns that
make agents misbehave in production — missing triggers, vague instructions, unguarded
destructive actions, prompt-injection exposure, and assert-without-verify.
"""
from .linter import Linter, lint_path, lint_paths
from .models import Definition, Finding, Severity, parse_definition

__version__ = "0.1.2"

__all__ = [
    "Definition",
    "Finding",
    "Linter",
    "Severity",
    "__version__",
    "lint_path",
    "lint_paths",
    "parse_definition",
]
