# Security Policy

agent-lint is a security tool, so we hold its own supply chain to the same bar it enforces.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Instead, report privately via GitHub
Security Advisories (**Security → Report a vulnerability**) on this repository, or email the
maintainer.

You can expect:

- an acknowledgement within **3 business days**,
- an assessment and, if confirmed, a fix targeted within **30 days** (sooner for high severity),
- credit in the release notes unless you prefer to stay anonymous.

## Supply-chain commitments

- **Zero runtime dependencies.** agent-lint is pure Python standard library — there is no
  third-party code in the install path to compromise.
- **No network, no telemetry.** The tool never makes a network call; it reads local files and
  prints findings. Nothing is uploaded.
- **No install-time execution.** There are no `setup.py` side effects, no post-install hooks.
- The CI pipeline runs the test suite, CodeQL, and agent-lint's own `--publish-check` on every
  push, so the repo is continuously scanned for secrets and malware signatures.

## Supported versions

The latest released minor version receives security fixes.
