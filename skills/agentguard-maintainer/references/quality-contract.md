# Quality Contract

The maintainer skill and implementation live together so process changes are reviewed with code.

- `eval/quality-baseline.json`: minimum recall, precision, case inventory, and allowed known misses.
- `docs/evidence/marketplace-snapshot.json`: dated source of published marketplace measurements.
- `tools/verify_contracts.py`: detects drift across rules, tests, docs, mappings, release pins,
  evidence, and the maintainer skill.
- `tools/corpus_audit.py`: real-world multi-repository calibration and deduplication loop.

A change is incomplete if it updates one layer while leaving another stale.
