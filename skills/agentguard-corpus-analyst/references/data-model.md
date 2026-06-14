# Corpus Audit Data Model

- `summary`: coverage, volume, deduplication, change, patch, and timing metrics.
- `repositories`: per-source status, scan volume, patch artifact, and failure reason.
- `diff`: stable fingerprints classified as new, unchanged, or resolved.
- `findings`: unique finding plus every repository/path/line occurrence.

The stable fingerprint is based on normalized rule/message and definition content, so duplicated
plugin-cache copies collapse while their occurrences remain visible.

## Failure Modes

- `ambiguity`: routing, output, verification, failure, or scope semantics are underspecified.
- `retrieval_failure`: the scanner could not fully retrieve or discover the definition.
- `execution_risk`: the retrieved definition creates a concrete security or unsafe-action path.
- `other_quality`: a concrete quality or distribution defect that is not one of the three primary
  analytics failure modes and does not create an execution path.
- `staleness`: an aggregate audit condition for expired evidence or failed stale sources; it is not
  assigned to an individual finding without source evidence.

Every repository result carries a content-derived `revision`. Do not compare scans as if they cover
the same source revision when those values differ.
