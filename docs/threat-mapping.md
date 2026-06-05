# Threat-framework mapping

agentguard's security rules aren't ad-hoc — each maps to the **OWASP Top 10 for LLM Applications
(2025)** and to **MITRE ATLAS** techniques. So a finding reads as "this is OWASP LLM01 / ATLAS
AML.T0051.001, here in your definition," not "a regex fired."

| Rule | What it catches | OWASP LLM Top 10 (2025) | MITRE ATLAS |
|------|-----------------|--------------------------|-------------|
| AL202 | reads external content with no data-not-instructions guard | LLM01 Prompt Injection | AML.T0051.001 Indirect Prompt Injection |
| AL300 | injection→action chain (untrusted input + exec/write sink) | LLM01 Prompt Injection · LLM06 Excessive Agency | AML.T0051.001 |
| AL301 | sensitive data + network sink (exfiltration path) | LLM02 Sensitive Information Disclosure | AML.T0057 LLM Data Leakage |
| AL303 | hardcoded secret in the definition | LLM02 Sensitive Information Disclosure | AML.T0057 |
| AL305 | command/URL built from untrusted input | LLM01 Prompt Injection · LLM05 Improper Output Handling | AML.T0051 |
| AL307 | injection propagation to spawned sub-agents | LLM01 Prompt Injection | AML.T0051.001 |
| AL310 | slash-command `$ARGUMENTS` spliced into a shell | LLM01 Prompt Injection | AML.T0051 |
| AL200 | no output-format spec / improper output handling | LLM05 Improper Output Handling | — |
| AL203 | unguarded destructive/outward action | LLM06 Excessive Agency | AML.T0053 LLM Plugin Compromise |
| AL302 | no least-privilege `tools:` (excessive permissions) | LLM06 Excessive Agency | — |
| AL306 | over-privilege (unused powerful tool) | LLM06 Excessive Agency | — |
| AL308 | human-in-the-loop disabled (excessive autonomy) | LLM06 Excessive Agency | — |
| AL204 | asserts/recommends without verifying | LLM09 Misinformation | — |
| AL503 | committed secret (repo-wide) | LLM02 Sensitive Information Disclosure | AML.T0057 |
| AL510 | pipe-to-shell installer | LLM03 Supply Chain | AML.T0011 User Execution |
| AL511 | dynamic exec of decoded/remote payloads | LLM03 Supply Chain | AML.T0011 |
| AL512 | reverse-shell / raw-socket signature | LLM03 Supply Chain | AML.T0011 |
| AL513 | malicious pre/postinstall hook | LLM03 Supply Chain | AML.T0010 ML Supply Chain Compromise · AML.T0011 |

Structure (AL0xx) and clarity (AL1xx) rules are reliability checks, not security findings, so they
carry no framework mapping by design.

## References

- OWASP Top 10 for LLM Applications (2025): <https://genai.owasp.org/llm-top-10/>
- MITRE ATLAS: <https://atlas.mitre.org/>

The machine-readable mapping lives in [`agentguard/frameworks.py`](../agentguard/frameworks.py);
the CLI surfaces it inline on every security finding and in `--list-rules`.
