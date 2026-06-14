<!-- Thanks for contributing! Keep it focused — one logical change per PR. -->

## What & why

<!-- What does this change, and why? -->

## Trust boundary and evidence

<!-- What untrusted input, capability, sink, or failure mode changes? What reproducer proves it? -->

## User and cross-functional impact

<!-- Compatibility, docs/evidence changes, rollout concerns, or "none". -->

## Checklist

- [ ] `pytest -q` passes
- [ ] New/changed rule has a test that it **fires** and a test that it **stays quiet** on the near-miss
- [ ] If a rule changed, I ran it on a real corpus and confirmed no new false positives
- [ ] `python eval/benchmark.py` and `python eval/adversarial_review.py` pass without lowering the baseline
- [ ] `python tools/verify_contracts.py` passes; docs/evidence/skill changed with the code where needed
- [ ] Risk-based change-review packet has no missing evidence
- [ ] `python tools/workflow_audit.py` passes without hiding added workflow cost
- [ ] No new runtime dependencies (stdlib only)
