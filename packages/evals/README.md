# epochly-relay-evals

Relay eval runner primitives (Python).

## Scope

W9.1 ships:

- A deterministic single-process eval runner that consumes a list of
  `EvalCase` objects and produces a single canonical `eval_runs` row
  plus per-case `eval_results` rows, each bound to the five evidence
  anchors required by CLAUDE.md keystone invariant #2 (artifact hash,
  command id, exit code, trace span ids, manifest commit hash) plus
  the assertion id.
- Pass/fail aggregation: `score = k/N`, `passed = (k == N AND no case
  has status='invalid')`. A single per-case `status='invalid'` forces
  the aggregate `status='invalid'`, NOT `passed=false`. The two states
  are distinct (VAL-W9-002).
- `compute_eval_delta(current, baseline, flake_window_n=5)`: classifies
  each case into one of the six delta classes from spec AM.3 line
  5886-5893 (`net_new_failure`, `net_new_success`, `unchanged_pass`,
  `unchanged_failure`, `flaky`, `baseline_absent`). Re-computation
  against the same baseline is idempotent (byte-identical row content).
- SQLite migration at `migrations/0001_eval_runs.sql` defining
  `eval_runs`, `eval_results`, and `eval_run_deltas` tables.
- Tier-3 pytest marker (`@pytest.mark.tier3`) gated on
  `RELAY_TIER3_RUNNER=linux-py3.14-node24` per eng plan A6.

## Forbidden

Per CLAUDE.md keystone invariant #1 and VAL-W9-008, this package MUST
NOT write `run_results` or `gate_decisions`. The CI grep guard
`tests/test_w9_1_invariants.py::test_no_run_results_or_gate_decisions_writes`
asserts this at build time.

Per CLAUDE.md keystone invariant #2 and VAL-W9-007, a per-case row
whose evidence binding is incomplete is written with `status='invalid'`,
NOT `status='passed'` or `status='failed'`.

## Deferred

- `w9.2` -- assertion template library (VAL-W9-009 .. VAL-W9-015). Not
  in this commit.
- `w9.3` -- LLM-judge stub (VAL-W9-016 .. VAL-W9-020). Not in this commit.

## Spec anchors

- A line 1899: `eval_runs` schema
- AM.3 line 5876: eval-delta discipline + `eval_run_deltas` schema
- AM.6 line 5941: tier-3 budget
- D.5 line 3860: `EvalAssertion` (consumed by w9.2/w9.3, not w9.1)
- K: evidence binding
- S: evals primitives row

## License

Apache-2.0.
