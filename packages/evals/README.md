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

## Deferred features

The following surfaces are **deferred** in v0.1 -- the schema slots
exist but the runtime explicitly refuses to register them as active:

### LLM-as-judge evaluator (W9.3; ships month 4+)

The LLM-as-judge evaluator (`evaluator.kind == "llm_judge"` on
EvalAssertion per spec D.5) is **deferred to month 4+**. The v0.1
surface ships only a stub at `relay_evals.llm_judge_evaluator` that:

1. Validates the canonical `relay.assertion.eval.v1` EvalAssertion
   schema (so schema breakage surfaces as `RelayTemplateInputError`
   before the deferred raise fires).
2. Raises `NotImplementedError` with the canonical message
   `"LLM-as-judge evaluator deferred to month 4+; see docs/roadmap.md"`.
3. Is **NOT** registered as an active evaluator -- the active-evaluator
   introspection surface (`relay_evals.list_active_evaluator_kinds()`,
   future `rly eval evaluators list`) returns an empty tuple. Customers
   who submit an EvalAssertion with `evaluator.kind == "llm_judge"`
   receive the wire code `RELAY-EVAL-EVALUATOR-DEFERRED` mapped to
   CLI exit code 8.

The deferred status is intentional. LLM-as-judge requires the
cassette-first replay hardening described in spec section AM.7 plus
the structured-output enforcement landing alongside the month-4+ work.
Shipping the slot at v0.1 without a runtime would create a path for
silent passes; the stub closes that path.

**Tracking issue:** see `docs/roadmap.md` once the OSS repo is
populated. Customer-facing product copy MUST NOT claim LLM-judge
support in v0.1 (forbidden per CLAUDE.md section J.5 carryover).

### Other deferrals

- `w9.2` -- assertion template library (VAL-W9-009 .. VAL-W9-015):
  **SHIPPED** in the preceding W9.2 worker pass.

## Sub-feature deltas vs initial scaffolding

- W9.2 has shipped: the assertion-template library now ships three
  signed templates (`coverage_assertion_template`,
  `tool_arg_assertion_template`, `schema_match_assertion_template`)
  via a closed-allow-list registry that refuses dynamic plugin loads.
- W9.3 ships ONLY the deferred LLM-as-judge stub described above.

## Spec anchors

- A line 1899: `eval_runs` schema
- AM.3 line 5876: eval-delta discipline + `eval_run_deltas` schema
- AM.6 line 5941: tier-3 budget
- D.5 line 3860: `EvalAssertion` (consumed by w9.2/w9.3, not w9.1)
- K: evidence binding
- S: evals primitives row

## License

Apache-2.0.
