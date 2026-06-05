# Contributing to agentguard

Thanks for helping make AI agents safer. Bug reports, false-positive reports, and new rules are all
welcome.

## Dev setup

```bash
git clone https://github.com/yingchen-coding/agentguard && cd agentguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

No third-party runtime dependencies — keep it that way. `pytest` is the only dev dependency.

## Adding a rule

A rule is a pure function `(Definition) -> list[Finding]`, registered with `@rule("ALxxx", "...")`
in `agentguard/rules.py` (or, for repo-level checks, in `agentguard/project.py`). The bar:

1. **It fires on its target.** Add a fixture/test that the rule catches.
2. **It stays quiet otherwise.** Add a test proving the obvious near-miss does *not* trip it.
3. **It survives the corpus.** Run it against real agents and confirm a low false-positive rate:
   ```bash
   agentguard ~/.claude/plugins/cache/*/*/*/agents --format json
   ```
   A false positive found this way is fixed by tightening the rule — **never shipped**. Precision
   is the whole product; a scanner that cries wolf gets uninstalled.

Pick the next free code in the right family: `AL0xx` structure, `AL1xx` clarity, `AL2xx`
robustness/safety, `AL3xx` security/threat-model, `AL5xx` distribution/supply-chain.

## Conventions

- Keep messages concrete: say what's wrong *and* give a one-line fix.
- Give every finding an inline escape hatch — `<!-- agentguard-disable ALxxx -->` (definitions) or
  `# agentguard-allow ALxxx` (project files).
- Run `pytest -q` before opening a PR. CI runs tests on 3.9–3.12, CodeQL, and agentguard on itself.

## Reporting a false positive

Open an issue with the smallest definition snippet that misfires and the rule code. Real-world
misfires are the most valuable bug reports — they're how the rules get calibrated.
