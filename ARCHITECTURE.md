# Relay Architecture (authoritative reference)

This is the top-level architectural reference for the public `relay` repository.
It is the document a reviewer (or a new contributor) reads first. It gives the
system model, the package dependency structure, where each keystone invariant is
enforced, the cross-language CEL parity model, the trust/threat boundaries, and
an honest register of known architectural findings.

The deep, section-level documentation lives under [`docs/architecture/`](docs/architecture/)
and is the canonical source for each topic; this file synthesizes and links it
rather than duplicating it. Everything here traces back to the product/engineering
spec (`planning/epochly-replay-spec.md`, sections A through AO, in the workspace
repo) and to [`CLAUDE.md`](CLAUDE.md).

## How to read this document

| You want to understand... | Read |
|---|---|
| The three-tier system and one run end-to-end | [`docs/architecture/overview.md`](docs/architecture/overview.md) |
| The 16 invariants that define the product | [`docs/architecture/keystone-invariants.md`](docs/architecture/keystone-invariants.md) |
| Scope states, the transition table, gate restart, three-anchor handoff | [`docs/architecture/state-machine.md`](docs/architecture/state-machine.md) |
| The replay sandbox threat model | [`docs/architecture/sandbox-threat-model.md`](docs/architecture/sandbox-threat-model.md) |
| The package dependency graph (generated) | [`docs/architecture/dependency-graph.md`](docs/architecture/dependency-graph.md) |

## 1. System model (three tiers)

Relay is a three-tier system; the boundary between tiers is enforced by code, by
guard tests, and by the OSS-vs-hosted repository split. Full detail in
[`overview.md`](docs/architecture/overview.md).

1. **Relay SDK** (`packages/sdk-python/`, `packages/sdk-typescript/`) -- runs
   inside the user's agent process, wraps provider calls, captures trace
   metadata, applies SDK-side redaction at the trace boundary, and submits
   **lifecycle metadata only** to the local sidecar over loopback HTTP. The SDK
   never writes canonical outcomes.
2. **Local sidecar (OSS)** (`apps/local-sidecar/`) -- a single per-host
   FastAPI + SQLite(WAL) daemon. Owns ingest, storage, the state engine,
   redaction-policy evaluation, evidence staging, and contract/gate evaluation.
   Hosts `compare_and_set_state`, which writes every canonical row.
3. **Hosted control plane** -- the commercial product, out of scope for this
   repo (lives in `relay-platform`). Adds tenancy, RBAC/SSO, the evidence
   registry, fleet-scale workers, compliance packs, and the trust-anchor
   signing service.

The verifier (`packages/verifier/`, `packages/verifier-typescript/`) is shipped
in OSS so any auditor can verify a bundle offline; its default trust anchor is
the hosted JWKS, overridable via `--trust-anchor`.

## 2. Package inventory and dependency layering

The dependency graph is generated -- do not hand-maintain it. Regenerate with:

```sh
python scripts/gen-dependency-graph.py            # write docs/architecture/dependency-graph.{json,md,dot}
python scripts/gen-dependency-graph.py --check     # CI: fail on drift OR on any dependency cycle
```

The generator (`scripts/gen-dependency-graph.py`) discovers every Python package
(a `pyproject.toml`) and TS workspace package (a named `package.json`) under
`packages/` and `apps/`, AST-resolves cross-package Python imports, and matches
`@epochly/*` TypeScript specifiers -- production source only (tests, vendored
crates, build output excluded). 16 packages, 23 cross-package edges at the time
of writing.

**Intended layering** (foundation at the bottom; each layer depends only on
those below it). At the file level qsense confirms an essentially clean,
downward-flowing layering (9 levels, 0 upward file edges); the package-level
exceptions are the cycles in section 7.

| Layer | Packages | Role |
|---|---|---|
| L0 foundation | `schemas` (+ `schemas/typescript`) | Canonical envelopes + error codes, generated from spec sec A / sec B. Fan-in 8, fan-out 0 -- the leaf everything binds to. |
| L1 domain | `contracts` (+ `cel-wasm`), `verifier`, `acef`, `explain`, `replay-sandbox-protocol`, `sdk-typescript`, `contracts-typescript`, `verifier-typescript` | Contract DSL + the single WASM CEL engine, evidence verification, ACEF wire format, Explain, sandbox protocol. Depend on schemas only. |
| L2 services | `gate`, `sdk-python`, `evals` | Gate decision engine, the Python SDK, eval primitives. |
| L3 host | `local-sidecar` | The OSS daemon: ingest, state engine, storage, evidence staging. |
| L4 surface | `cli`, `replay-proxy`, `sdk-typescript-sidecar-bundle` | The `rly` CLI, cassette replay proxy, packaged sidecar bundle. |

`cel-wasm` is special: it vendors a forked Rust CEL engine compiled to a single
`.wasm` artifact that is embedded byte-identically in both the Python host
(`contracts`) and the TypeScript host (`contracts-typescript`). See section 4.

## 3. Control-plane vs SDK write-path (keystone invariant #1)

The defining rule: **the control plane writes the result.** SDKs, eval workers,
and replay workers submit *evidence* (draft envelopes); they never write
canonical `run_results` or `gate_decisions`. The single chokepoint is
`compare_and_set_state` in
`apps/local-sidecar/relay_sidecar/state_engine/compare_and_set.py`, which
atomically appends one `event_log_entries` row and updates `scope_state`. Any
write that bypasses it is an invariant violation; guard tests enforce ownership.

## 4. The CEL parity model (keystone invariant #16, the P0)

Relay evaluates contract assertions with CEL. Byte-/verdict-identical evaluation
across the Python backend and the TypeScript/edge runtime is the load-bearing
correctness property (any divergence is a P0). This is achieved **by
construction**, not by reconciling two engines:

- A single CEL engine (forked `cel-rust`, vendored at
  `packages/cel-wasm/vendor/cel/`) is compiled to one reproducible `.wasm`
  artifact (pinned by sha; the pin moves only on a deliberate crate rebuild).
- The Python host (`packages/contracts/`) embeds it via `wasmtime`; the
  TypeScript host (`packages/contracts-typescript/`) embeds the same bytes.
- The three Relay UDFs (`relay.coverage`, `relay.tool_arg`, `relay.schema_match`),
  the Relay profile (disabled builtins), JCS canonicalization, and the
  `RELAY-CEL-*` error envelope all live *inside* the WASM, so they are
  byte-identical on both hosts.

cel-python and `@bufbuild/cel` have been fully removed. Parity is guarded by the
conformance corpus and cross-host byte-equality checks.

## 5. Trust and threat boundaries

- **OSS vs hosted source boundary** (invariants #13--#15): trust-anchor key
  material, the signing service, and transparency-log custody live only in
  `relay-platform`. The OSS verifier defaults to the hosted JWKS and supports
  BYO anchors. See [`overview.md` sec "OSS boundary"](docs/architecture/overview.md).
- **Default-deny raw capture** (invariant #7): hosted ingest does not persist
  raw prompts/outputs/tool-args unless `raw_capture` is enabled on the active
  redaction policy with a signed DPA + org-admin approver.
- **Replay sandbox** (invariants #9, #12): cassette playback is the default;
  network egress is default-deny; mutating / irreversible side effects are
  gated. Full model: [`sandbox-threat-model.md`](docs/architecture/sandbox-threat-model.md).

## 6. Where each keystone invariant is enforced

The 16 invariants and their rationale are in
[`keystone-invariants.md`](docs/architecture/keystone-invariants.md). The
enforcement map below points at the primary owning module(s); each invariant
additionally has a guard test (see section 8 of this doc for the test-mapping
work).

| # | Invariant | Primary enforcement site |
|---|---|---|
| 1 | Control plane writes the result | `apps/local-sidecar/relay_sidecar/state_engine/compare_and_set.py` |
| 2 | Pass without evidence is not a pass | `packages/gate/`, evidence staging in `apps/local-sidecar/` |
| 3 | Manifest is the source of truth | `packages/cli/src/relay_cli/commands/manifest.py`, gate runner |
| 4 | Three-anchor handoff | `apps/local-sidecar/relay_sidecar/state_engine/guards.py` (`_guard_three_anchor_handoff_valid`) |
| 5 | Gate restart on failure | `packages/gate/`, state-machine gate-restart rule |
| 6 | Side-effect idempotency | `apps/local-sidecar/relay_sidecar/side_effect_markers.py` |
| 7 | Default-deny raw capture | `apps/local-sidecar/relay_sidecar/validation/raw_capture.py`, redaction policy |
| 8 | Atomic persistence -- four primitives only | `apps/local-sidecar/relay_sidecar/primitives/`, CI lint |
| 9 | Cassette-first replay | `packages/replay-proxy/`, `apps/replay-proxy/` |
| 10 | Schema versioning on every envelope | `packages/schemas/` |
| 11 | Trust anchor is the moat | `packages/verifier/` (default JWKS), hosted signing (out of repo) |
| 12 | Live replay against irreversible effects is gated | replay sandbox + `side_effect_markers` |
| 13 | OSS default trust anchor change is board-level | `packages/verifier/` default config |
| 14 | No trust-anchor key material in OSS repo | repo policy + secret-scan CI |
| 15 | OSS/hosted source-boundary discipline | import-boundary + pack-boundary CI |
| 16 | CEL UDFs are deterministic; Py<->wasm<->TS parity | `packages/cel-wasm/`, conformance corpus |

## 7. Known architectural findings (debt register)

These are surfaced by `scripts/gen-dependency-graph.py` (package-level) and
qsense (file-level + complexity). They are recorded here for honesty and
remediation tracking; none is silently waved through.

### 7.1 Dependency cycles (2 in-scope; the 2 package-level cycles RESOLVED 2026-06-28)

Acyclicity is qsense's top structural bottleneck. The two PACKAGE-LEVEL cycles the
generator flagged were broken by relocating the shared module each back-edge
imported down to the lowest layer both packages already depend on:

- **Package-level** (generator) -- **RESOLVED**; `gen-dependency-graph.py --check`
  now reports **0 cycles**:
  - `cli <-> replay-proxy`: the cassette format/parse module that
    `apps/replay-proxy/.../cassette_server.py` imported from `relay_cli.cassette`
    moved to `relay_sidecar.cassette` (both packages already depend on the
    sidecar); the back-edge is gone.
  - `local-sidecar <-> sdk-python`: the ReDoS matcher-budget guard
    `local-sidecar/.../runtime.py` imported from `relay.redaction_budget` moved to
    `relay_schemas.redaction_budget` (the lowest shared layer); the back-edge is gone.
- **File-level** (qsense), intra-package, still tracked:
  - `acef`: `upstream/src/acef/export.py <-> package.py`.
  - `explain`: `src/relay_explain/api.py <-> engine.py`.

Status: the package-level cycles are RESOLVED (no lazy-import band-aid -- the
shared code was relocated to a lower layer); `gen-dependency-graph.py --check`
passes (0 cycles). The two intra-package file-level cycles remain tracked under
the shakedown loop. A fifth cycle inside the vendored `cel-rust` parser is
third-party and out of scope.

### 7.2 Complexity hotspots

- `apps/local-sidecar/relay_sidecar/runtime.py` -- 6057 lines; `build_runtime_app`
  is ~4707 lines, cyclomatic complexity 367, cognitive complexity 470. This is
  the single largest maintainability/review liability. The HTTP route handlers
  it defines are individually testable; the wrapper's size is the concern.
- `validateBundle` (`verifier-typescript`, cc 94) / `validate_bundle`
  (`verifier`, cc 80) -- the verification core; high but security-critical and
  heavily tested.
- `loadRedactionPolicy` / `redaction.load`, `compare_and_set_state`,
  `network_policy._classify` -- elevated complexity in load-bearing paths.

### 7.3 Test-coverage candidates

qsense's import-graph heuristic flags load-bearing modules that may be
under-covered (to be confirmed with real coverage + mutation testing, not the
heuristic): `cli/.../invariants/atomic_primitives.py`,
`verifier/.../transparency_log.py`, `state_engine/guards.py`,
`verifier/.../key_lifecycle.py`. These seed the mutation-testing loop's priority
list.

## 8. Reproducibility

- Dependency graph: `scripts/gen-dependency-graph.py` (deterministic; `--check`
  in CI).
- Structural metrics / cycles / complexity / test-gaps: qsense (scan, then the
  health / dsm / test-gaps tools). The committed `.qsense/rules.toml` codifies
  the layering + no-cycle + complexity constraints as a machine-checked gate
  (`qsense check`); 5 current violations match the section 7 debt register.
- Spec<->code<->test traceability: `scripts/gen-traceability-map.py` ->
  [`docs/architecture/traceability-map.md`](docs/architecture/traceability-map.md)
  -- the 16 keystone invariants mapped to their enforcement site + guard
  test(s) (all 16 enforced and guarded, 0 findings), 987 assertions bound to a
  test via `@pytest.mark.fulfills`, and coarse spec-section citation coverage.
  `--check` gates drift + any invariant with no enforcement site.
- Mutation testing (the loop's convergence signal): `scripts/run-mutation.py`
  (cosmic-ray). `network_policy.py` is mutation-complete: 457/457 mutants
  killed, 0 survivors, under its full SSRF + hardening test coverage.

## Cross-links

- [`docs/architecture/overview.md`](docs/architecture/overview.md)
- [`docs/architecture/keystone-invariants.md`](docs/architecture/keystone-invariants.md)
- [`docs/architecture/state-machine.md`](docs/architecture/state-machine.md)
- [`docs/architecture/sandbox-threat-model.md`](docs/architecture/sandbox-threat-model.md)
- [`docs/architecture/dependency-graph.md`](docs/architecture/dependency-graph.md)
- [`docs/architecture/traceability-map.md`](docs/architecture/traceability-map.md)
- [`CLAUDE.md`](CLAUDE.md) -- execution doctrine and the keystone invariants

Spec: §A, §B, §C, §AO
