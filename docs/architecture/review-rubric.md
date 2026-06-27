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

Evidence: `scripts/docs/audit-codebase-alignment.py` (0/0/0);
[`ARCHITECTURE.md`](../../ARCHITECTURE.md); this rubric.

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

| Dimension | Score | Note |
|---|---|---|
| Correctness | pending | network_policy mutation-complete; other targets in progress |
| Security | pending | network_policy SSRF mutation-complete + Py<->TS parity proven |
| Reproducibility | partial | dep graph + traceability `--check` green; verify-self pending re-run |
| Test rigor | pending | mutation harness operational; property tests not yet authored |
| Documentation | 9 | ARCHITECTURE.md + dep graph + traceability map; audit 0/0/0 |

This table is advisory until the adversarial reviewer panel scores each
dimension independently (acceptance gate #2).

Spec: §S, §AM, §AK
