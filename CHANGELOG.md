# Changelog

## 0.1.0

First release. A capability-aware security & reliability scanner for agent definitions.

- **Capability model:** parses each agent's `tools:` grant (and the dangerous default — no
  `tools:` field means the agent inherits *every* tool) and reasons about reader/sink/network
  capabilities, not just prose.
- **19 deterministic rules** in four families: security/threat-model (AL3xx), robustness & safety
  (AL2xx), clarity (AL1xx), structure/discovery (AL0xx).
- **Security rules (AL3xx):** AL300 injection→action chain (untrusted input + exec/write sink, no
  guard), AL301 sensitive-data exfiltration path, AL302 no-least-privilege tool grant, AL303
  hardcoded secret, AL305 command/URL built from untrusted input.
- Reliability highlights: AL202 prompt-injection exposure, AL203 unguarded destructive action,
  AL204 assert-without-verify ("grep before you recommend").
- `agent-lint` CLI: human / JSON / SARIF output, `--select` / `--ignore`, `--fail-at`, severity
  exit codes. Inline `<!-- agent-lint-disable ALxxx -->` suppression.
- GitHub composite Action (`action.yml`) + CI workflow. 45 tests.
- Calibrated against 19 production agents (Anthropic `pr-review-toolkit` / `plugin-dev`,
  `understand-anything`): 17/19 show an injection→action exposure, 15/19 run with no tool
  restriction. The high-severity rules (AL301/303/305) produce **zero false positives** on that
  corpus — every FP found during calibration was fixed, not shipped.
