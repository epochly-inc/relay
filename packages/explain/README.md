# epochly-relay-explain

Explain pipeline primitives for Relay v0.2 OSS completeness (M05).

This package houses the deterministic, evidence-bound Explain object engine:

- `relay_explain.heuristic.v1` -- rule-based hypothesis generator
- `relay_explain.engine` -- ingestion path that enforces the spec invariants
  (taxonomy clamp, span_id cross-row check, dedupe-by-digest)
- `relay_explain.quality.harness` -- precision/recall/FPR evaluator over a
  labeled ground-truth corpus

The package is the sole writer of `root_cause_hypotheses`; SDKs, the CLI,
and replay/eval workers must NOT bypass the engine. See CLAUDE.md keystone
invariant #1 and spec section T (lines 4856-4896).

Spec anchors:

| Section | Topic |
|---------|-------|
| T 4856-4896 | Explain object behavior |
| A.15 3316-3328 | RootCauseHypothesis envelope |
| AJ 5733-5746 | Generator taxonomy and Explain pipeline |
| AL.2 5775-5785 | pass@N filter (lives in relay_evals; consumed here) |

Contract assertions covered: VAL-V2M05-001 through VAL-V2M05-027.
