# Relay review rubric (senior / PhD engineering review)

The scoring instrument for the "scored rubric" acceptance gate. Each dimension
is scored 0-10 against the stated evidence; the gate passes only when **every
dimension scores >= 8** with no unresolved P0/P1 finding. Scores must cite
reproducible evidence (a command + its exit code + an artifact digest), not
narrative -- a claim without bound evidence scores at most 5.

This rubric is itself reviewable: it is generated/maintained alongside the
architecture reference and traces to the keystone invariants
([`keystone-invariants.md`](keystone-invariants.md)) and the spec.

## Dimensions

### 1. Correctness (weight 0.25)

Does the code do what the spec says, on the happy path and the edges?

| Score | Bar |
|---|---|
| 10 | Every load-bearing invariant has a guard test AND a property test; mutation kill-rate >= threshold with zero un-triaged survivors on all parity-critical + control-plane modules; Py<->TS<->wasm parity proven by construction + a saturated differential corpus. |
| 8 | All invariants guarded; mutation threshold met on the parity-critical core; no known correctness defect. |
| <8 | Any un-triaged mutation survivor on a parity-critical module, any invariant without a guard test, or any open correctness finding. |

Evidence: `scripts/run-mutation.py --target <m>` (kill-rate, 0 survivors);
`scripts/gen-traceability-map.py --check`; the CEL conformance corpus + cross-host
byte-parity; `pytest -m plumbing` exit 0.

### 2. Security (weight 0.25)

Does the system fail closed, default-deny, and resist the threats in scope?

| Score | Bar |
|---|---|
| 10 | Verifier fails closed on every tamper vector; SSRF/egress classifier is Py<->TS byte-identical and mutation-complete; default-deny raw capture + replay egress enforced; no trust-anchor key material in-repo; secret-scan + banned-copy gates green. |
| 8 | All of the above except a documented, non-exploitable residual (e.g. an accepted unbounded IPv6 sub-block carve-out). |
| <8 | Any fail-open path, any Py<->TS verdict divergence on a security classifier, or any secret/keymaterial in-repo. |

Evidence: `network_policy` mutation (457/457 killed); verifier fail-closed tests;
`scripts/lint-banned-copy.py`; secret-scan; the sandbox threat model.

### 3. Reproducibility (weight 0.2)

Can an independent party reproduce every claim, byte-for-byte?

| Score | Bar |
|---|---|
| 10 | Every "done" is bound to command + exit code + artifact digest; `rly verify-self --json` exits 0 with all invariants green; the wasm artifact rebuilds to its pinned sha; generated artifacts (dep graph, traceability map) pass `--check` (no drift); no drop below the recorded test baseline. |
| 8 | All of the above; one generated artifact lacks a drift gate but is regenerable. |
| <8 | Any unreproducible claim, verify-self non-zero, or wasm sha drift. |

Evidence: `rly verify-self --json`; `scripts/gen-dependency-graph.py --check`;
`scripts/gen-traceability-map.py --check`; `scripts/check-baseline-counts.py`;
the reproducible wasm build.

### 4. Test rigor (weight 0.2)

Do the tests actually catch bugs (not just execute lines)?

| Score | Bar |
|---|---|
| 10 | Mutation kill-rate >= threshold with zero un-triaged survivors; property-based tests for the property-testable invariants; three-tier cadence green; cross-package test isolation verified (no inter-test state pollution). |
| 8 | Mutation threshold met on the core; property tests for the highest-risk invariants; tiers green. |
| <8 | Mutation below threshold, no property tests, or a known test-isolation defect. |

Evidence: mutation reports; Hypothesis/fast-check suites; `pytest -m plumbing`
+ `vitest`; the test-isolation finding's resolution.

### 5. Documentation (weight 0.1)

Can a new senior engineer understand and safely change the system?

| Score | Bar |
|---|---|
| 10 | ARCHITECTURE.md + the dep graph + traceability map are current and machine-validated against source (alignment audit 0/0/0); every keystone invariant's enforcement site is documented and verified to exist; the debt register is honest and tracked. |
| 8 | The above with at most a P2 doc-staleness item. |
| <8 | Any doc claim that does not resolve against source (alignment audit P0/P1). |

Evidence: `scripts/docs/audit-codebase-alignment.py` (0/0/0); the repo-root
`ARCHITECTURE.md` (not web-published); the [architecture overview](overview.md);
this rubric.

## Gate computation

```
gate_passes = all(dimension.score >= 8 for dimension in dimensions)
              and no_open_P0_or_P1_finding
weighted_score = sum(d.score * d.weight for d in dimensions)   # informational
```

The weighted score is reported for trend tracking; the **pass condition is the
per-dimension >= 8 floor**, because a single weak dimension (e.g. a fail-open
security path) is not redeemable by strength elsewhere.

## Current standing (updated as the loop converges)

Independently re-scored by a 5-agent panel (one scorer per dimension,
refute-by-default, every claim bound to a command + exit code) at HEAD
`a6408fb`. **Gate result: PASS** -- all dimensions clear the strict `>= 8`
floor and there are no open P0/P1 findings. Informational weighted score 9.0.

| Dimension | Score | Note |
|---|---|---|
| Correctness | 9 | 16/16 invariants guarded (`gen-traceability-map --check` 0 P0); 5 modules mutation-complete (0 un-triaged survivors); CEL conformance corpus + wasm byte-parity; Gate#2 0 findings. 10 needs a property test for *every* invariant. |
| Security | 9 | verify-self 9/9; egress SSRF Py<->TS parity (property + 53 edge tests); verifier fail-closed; no key material in-repo; banned-copy 0. The one real divergence (IPv6 zone-id) found+fixed at `45ccde0`. |
| Reproducibility | 9 | verify-self 0 (9/9); `gen-dependency-graph --check` 0 cycles (the prior 2-cycle blocker resolved); `gen-traceability-map --check` clean; `check-baseline-counts` exit 0 (5529 passing, 0 regressions); wasm pinned-sha guard. |
| Test rigor | 9 | 5 mutation-complete modules; 4 generative property suites (one caught the zone-id bug this session); three-tier cadence green; the historically-noted cross-package SSRF co-run pollution is NOT reproducible. |
| Documentation | 9 | ARCHITECTURE.md + dep graph + traceability map machine-validated; alignment audit P0=0/P1=0 (31 P2 are audit-tool coverage limits, not staleness). |

Re-score this table whenever the loop changes a load-bearing surface; it is
generated by the panel, not hand-asserted.

Spec: §S, §AM, §AK
