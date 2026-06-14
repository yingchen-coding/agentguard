# AgentGuard Agent Factory

The factory turns agent work into a maintained verification system. It is intentionally
deterministic at the trust boundary: agents may propose, but code, tests, baselines, schemas, and
human gates decide what ships.

## Layers

1. **Knowledge layer**
   - `skills/agentguard-maintainer/SKILL.md`
   - `skills/agentguard-corpus-analyst/SKILL.md`
   - `schemas/corpus-audit.schema.json`
   - `tools/query_audit.py`

   The workflow instructions and the data model live in the repository they govern, so a pull
   request can update both together. Structured query views provide self-service analytics without
   relying on the agent to infer joins or metrics from grep output. The automation view promotes a
   pattern only after it appears across at least three repositories.

2. **Fast PR verification**
   - unit and regression tests on Python 3.9–3.12;
   - strict mypy and ruff;
   - recall/precision baseline;
   - metamorphic adversarial review;
   - code/docs/evidence/skill drift contracts;
   - package build and metadata validation;
   - supply-chain self-scan;
   - a risk-based change-review packet assigning security, trust-boundary, release, data-model,
     documentation, and developer-experience review domains;
   - workflow-cost budgets for matrix expansion, duplicated expensive commands, cancellation, and
     job timeouts.

3. **Real-world corpus loop**
   - shallow-clones or copies manifest sources into disposable directories;
   - scans repositories concurrently;
   - preserves per-repository failures instead of hiding partial coverage;
   - collapses duplicate definitions into one stable finding with many occurrences;
   - compares fingerprints with prior state;
   - emits JSON, Markdown, state, and unified repair patches.

4. **Human-gated external action**
   - scheduled runs only upload artifacts;
   - a manual workflow input plus the protected `corpus-publish` environment is required to update
     the tracking issue;
   - the publisher searches for a marker and updates one issue rather than creating duplicates.

## Artifacts

`build/corpus-audit/` contains:

| File | Purpose |
|---|---|
| `audit.json` | Full versioned data product |
| `report.md` | Bounded human review summary with distributions and the first 100 new findings |
| `state.json` | Stable finding state for the next comparison |
| `<repo>.patch` | Reviewable safe auto-fix proposal |

## Success Metrics

- precision and recall do not regress;
- no new unreviewed benchmark misses;
- corpus success rate stays above the manifest threshold;
- unique risks resolve faster than new ones appear;
- duplicate copies do not inflate issue volume;
- repair patches are generated without pushing or opening remote changes;
- published evidence remains tied to dated machine-readable snapshots.

Raw token use, number of spawned workers, and raw finding volume are not success metrics.
Neither is workflow volume: `tools/workflow_audit.py` makes added CI cost and duplication an
explicit reviewed budget change.

## Failure Policy

- Parser or rule exceptions are major findings, not green scans.
- Unreadable and oversized definitions fail closed.
- Corpus failures remain visible and can fail the coverage gate.
- A quality-baseline reduction is a threat-model decision requiring human review.
- External issue publication is opt-in and environment-gated.
- Security, trust-boundary, release, and external-action PRs require human review even when all
  deterministic gates pass.
- Dated evidence expires; source revisions and failure-mode distributions prevent stale or partial
  retrieval from masquerading as current knowledge.
