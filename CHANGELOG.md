# Changelog

## 0.1.0

First release.

- 14 deterministic rules across three families: structure/discovery (AL0xx), clarity (AL1xx),
  robustness & safety (AL2xx).
- Highlight rules: **AL202** prompt-injection exposure, **AL203** unguarded destructive action,
  **AL204** assert-without-verify ("grep before you recommend").
- `agent-lint` CLI: human / JSON / SARIF output, `--select` / `--ignore`, `--fail-at`, exit codes.
- Inline `<!-- agent-lint-disable ALxxx -->` suppression.
- GitHub composite Action (`action.yml`) + CI workflow.
- Calibrated against 18 production agents (Anthropic `pr-review-toolkit` / `plugin-dev`,
  `understand-anything`); false positives found this way were fixed, not shipped.
