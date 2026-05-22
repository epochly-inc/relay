# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Versioning note

Pre-v0.1.0 tags (`v3-mN-sealed`, `v0.3-*`, `v0.2-*`, `scaffold-base`)
correspond to internal operation milestones from the spec-conformance
audit-resolution workstreams. They are preserved here for traceability.
SemVer-tagged releases begin at v0.1.0.

The tag `v0.3-audit-resolution-complete` points at the same commit as
`v3-m5-sealed`; both are listed below at the same date for completeness.

## [Unreleased]

### Added
- Comprehensive user documentation effort (operation `relay-docs-v1`):
  landing page, install guide, first workflow walkthroughs, local Compose
  and devcontainer docs, plus generated CLI and error reference pages.
- Four-layer codebase-alignment audit script for documentation source,
  generated docs, package READMEs, and examples (m1-f01).
- Banned-copy scanner coverage extended across `docs/**/*.md`, excluding
  internal and release documentation surfaces (m1-f02).

## [v0.3-audit-resolution-complete] - 2026-05-19

Alias of `v3-m5-sealed`. See that entry for the full set of changes.

## [v3-m5-sealed] - 2026-05-19

### Added
- §G.8 hosted default redaction policy constant exported with a YAML
  fixture (v3m5-f09).
- §G.3 `json_path` redaction matcher kind in both the Python and
  TypeScript SDKs (v3m5-f08).
- §AI right-to-left override, zero-width, and BOM character rejection
  at identifier boundaries (v3m5-f03).
- §AM.6 baseline-counts persistence file and CI gate so passing test
  counts cannot regress (v3m5-f12).
- Server-side ReDoS regex budget enforced at contract publish time;
  §AI regression locks (v3m5-f01).
- Error-code naming convention doc and a CLI JSON-injection guard test
  (v3m5-f11).
- §U guard registry index doc and corresponding test (v3m5-f13).
- §F.6 manifest-to-`tool_side_effect_policies` binding guard test
  (v3m5-f10).
- §AM.6 W13/W14/W15 milestone test inventory documented (v3m5-f15).
- §J public EU AI Act readiness stub mapped to the ACEF template
  (v3m5-f14).
- §AI YAML hardening: `safe_load` lint and a `depth=16` parse cap
  (v3m5-f05).
- TypeScript TSA verifier parity with the Python implementation
  (v3m5-f07).
- §AI UTS-39 confusables guard on `trust_anchor` and manifest URLs
  (v3m5-f04).
- §G.5 JCS BMP-only object key guard with Python + TypeScript parity
  (v3m5-f02).
- §AI cross-platform symlink-safe bundle and manifest reads (v3m5-f06).

### Fixed
- §AI CLI `json.dumps` pinned to `ensure_ascii=False` and
  `allow_nan=False` (v3m5-f11-followup).

### Changed
- Banned-copy tokens scrubbed from the milestone-test-map meta-doc
  (v3m5-f15-followup).

## [v3-m4-sealed] - 2026-05-19

### Added
- §AJ per-`hypothesis_class` quality thresholds (v3m4-f01).
- §AJ generator auto-disable, promotion threshold, and versioning
  (v3m4-f02).
- §AJ reviewer SLA aging at 14 business days (v3m4-f03).

### Changed
- State-engine writes-only guard allowlist extended to include
  `explain/sla.py` (v3m4-f03-guard).

## [v3-m3-sealed] - 2026-05-19

### Added
- §AP.5.a `reconstruct_scope_state_at` temporal query (v3m3-f03).
- §AP.5.b `scope_state_snapshots` table with a 90-day retention policy
  (v3m3-f04).
- Canonical `gate` `scope_kind` and `gate.stalled` state per spec
  section AD (v3m3-f05).
- Section W deferred `CONSTRAINT TRIGGER` for `scope_state` co-insert
  (v3m3-f06).
- `{scope_kind}.transition` event emitted per successful state
  transition (v3m3-f02).

### Fixed
- Per-project manifest scoping in handoff guards (v3m3-f01).
- `scope_state_snapshots` CHECK extended to include the `gate`
  `scope_kind` (v3m3-sr-r1-001).

## [v3-m2-sealed] - 2026-05-19

### Added
- OpenAPI route fill, coverage script, and uniqueness check (v3m2-f01).
- Five hosted-only routes published as 501 stubs tagged
  `[OUT-OF-SCOPE-PRIVATE]` (v3m2-f02).
- `Idempotency-Key` ULID grammar enforcement per spec §B.6 (v3m2-f03).
- Pagination on every list endpoint plus a coverage script (v3m2-f04).
- `--json` flag on `rly sidecar start/stop/status` (v3m2-f05).

### Changed
- TypeScript schemas regenerated after m2-f02 OpenAPI additions
  (codegen refresh).

## [v3-m1-sealed] - 2026-05-18

### Added
- §A.1 `run_result_contract_results` and `run_result_gate_decisions`
  join tables (v3m1-f01).
- VAL-V3M1-004 RunResult no-array guard test (v3m1-f02).
- §K full `EvidenceClaim` shape with seven new or restructured fields
  (v3m1-f05).
- VAL-V3M1-016 guard test for `EvidenceClaim` flat-subject deprecation
  (v3m1-f06).
- §K rules: `supersedes` CHECK, signer restriction, `evidence_refs`
  binding, and unknown-namespace rejection (v3m1-f07).

### Changed
- Renamed sidecar `audit_log_entries` to `admin_override_audit` to free
  the §V name (v3m1-f03).
- CLI PyYAML dependency lockfile refreshed (audit-r3 BUG-E7).

### Fixed
- Audit-R4 P0 schema reconciliation: dropped stranded `gate.v1` and
  `eval_run.v1` DDL pins, and aligned sidecar `actors.kind` to the
  envelope enum.
- Audit-R4 P1 redaction-budget race fix and tighter Python verifier path
  parity.
- §Y FK chain repair across all six OSS foreign-key references to
  undefined orgs/users (v3m1-f04).
- Schema drift: `failed_assertion_ids` is now `text[]`,
  `gate_rounds.initiated_by` uses the spec four-value enum, and
  migration 0017 annotated (v3m1-f08).
- Production code now uses the spec-restricted `initiated_by` enum
  (v3m1-f08-followup-sut).
- Test helpers updated to the spec four-value `initiated_by` enum
  (v3m1-f08-followup).
- Paired-row trigger restored and runtime `initiated_by` enum
  compliance enforced (v3m1-sr-r1).

## [v0.2-post-r3-fixes] - 2026-05-18

### Added
- W9-3 real Rekor Merkle inclusion proof verification (VAL-V2M09 w9-3).
- W9-2 real TSA cryptographic verification (VAL-V2M09 w9-2).
- W9-1 real Sigstore cryptographic verification
  (VAL-V2M09-001..010, 020, 022).
- W9-4 no-private-key-material guard and default trust anchor
  immutability guards (VAL-V2M09 w9-4).
- W9-5 xfail baseline reconciliation and `verify-self` acceptance
  (VAL-V2M09-023..025).
- W8 AI hardening, five new error codes, SSRF allowlist, path
  traversal, and ReDoS timeout (VAL-V2M08-001..019).
- W8 trust-anchor four-signature cap, per-signature reporting, and a
  `local_dev` label (VAL-V2M08 trust-anchor).
- W8 replay determinism fields: `parallel_index`, `abort_after`,
  `page_index`, retry attempts (VAL-V2M08-replay-determinism).
- W8 Agent Definition Diff, per-attempt dirs, and tier-marker CI
  gating (VAL-V2M08 w8-tooling).
- W8 redaction: `json_pointer`, salt rotation, server-side
  `raw_capture` rejection, and validation harness.
- W7 consolidated CLI completeness and `cli_invocations`
  (VAL-V2M07-001..038).
- W6 TypeScript verifier port: TSA, transparency log, key lifecycle,
  Merkle proof, retention, JWKS loader, bundle validator
  (VAL-V2M06-001..025).
- W5 `RootCauseHypothesis`, `heuristic.v1`, promotion API, and
  `passN` filter (VAL-V2M05-001..027).
- W4 side-effect markers and proofs tables, server enforcement, and
  sandbox `Protocol` (VAL-V2M04-001..035).
- W3 state-engine per-transition guards and three-anchor handoff
  inside `compare_and_set_state` (VAL-V2M03-024..035).
- W3 manifest canonical schema, `command_hash`, and sidecar
  enforcement (VAL-V2M03-001..016).
- W3 atomic `local_two_layer_locked_write` primitive with a 5s
  timeout (VAL-V2M03-017..023).
- W2 ingest endpoints test coverage and `raw_capture` import wiring
  (w2-1).
- W2 runs read, replay, and eval HTTP endpoints
  (VAL-V2M02-010..036).
- W2 gates, evidence, manifest, and redaction-policy endpoints plus
  cross-cutting idempotency, pagination, rate-limit, and auth-scope
  (VAL-V2M02-037..084).
- W1 canonical SQL tables for v2 OSS completeness; ACEF oversight,
  data-quality, data-provenance tables; legal holds and
  `evidence_bundle_registry`; `evidence_timestamps` and
  `transparency_log_entries`; `scope_state` extension to six kinds
  plus a paired-row trigger; `GateMetricCatalog` v1 and compiler.

### Changed
- `KNOWN_SCHEMA_IDS` and `_SHARED_ENVELOPES` aligned with M01
  w1-4/w1-5/w1-6 additions (schemas chore).
- Style cleanups: SIM300 ruff cleanup on audit-R3 schema fixture
  comparison; SIM105/SIM117 in audit-P0 sidecar paths; SIM103
  single-return in `_is_vendored_file`.
- TS parity and codegen tests aligned with v0.2 envelope additions
  and M09 TSA crypto.
- `package-lock.json` refreshed after `contracts-typescript` npm
  install.

### Fixed
- Audit-R3 P0 control-plane fixes: idempotency lock + primitive +
  restart, PID-reuse, timing, error envelope.
- Audit-R3 P0 schema audit: DDL completeness, `schema_version` pins,
  enum drift.
- Audit-R3 P0 SSRF guard and `approval_required` CLI bypass.
- Audit-R3 P1 TS verifier parity: path screen, JCS, wire field.
- Audit-R3 P1 mixed: TS gate-draft validation, float parity, thread
  leak, salt rotate, heuristic determinism, gitleaks pin, contract
  YAML.
- Audit-R3 P2 replay: query canonicalization, session-dir isolation,
  abort-overshoot detection.
- Sidecar `runtime.py` contract correctness -- 11 P0 audit fixes.
- Wire `check_artifact_path` into `validate_bundle` and serialize
  `writer_loop` with the state-engine writer lock (audit P0).
- CLI `cmd_evidence_assess` and `cmd_eval_run` no longer fabricate
  IDs (keystone invariant #2; audit P0).
- TypeScript verifier port: four-signature cap, `trust_anchor`
  missing-rejection, `signatures_present`, and `trust_anchor_class`
  (audit P0).
- Marker `expires_at` default, cursor TTL, salt registry semver, and
  SSRF bracketed-IPv6 (audit P1/P2).
- Rate-limit verify test uses `evidence:write` (audit P0 follow-up).
- SDK `json_pointer` null/bool leaf canonical literal and
  `gate_draft` envelope parity.
- TS subprocess cwd pinned to the repo root; `__pycache__` ignored
  in vendor-drift check.
- Test signature tampered mid-byte rather than via trailing base64
  stuffing.

### Security
- Audit-R3 P0 SSRF guard hardened; CLI `approval_required` bypass
  closed.
- Verifier path traversal screen aligned across Python and
  TypeScript (audit-R3 P1).

## [v0.2-base] - 2026-05-16

### Added
- W1 schemas: canonical envelopes for `run_results`, `gate_decisions`,
  drafts, rounds, and actors (W1.1); control-plane envelopes --
  manifest, `scope_state`, idempotency, event log (W1.2); evidence
  and replay envelopes (W1.3); `redaction_policies` and
  `error_envelope` (W1.4); cross-language codegen pipeline with
  drift check (W1.5); cross-language golden corpus (W1.6).
- W2 sidecar: lockfile, spawn, and `/health` nonce challenge (W2.1);
  asyncio runtime and lifecycle (W2.2); SQLite WAL, single-writer
  queue, reader separation (W2.3); state engine --
  `compare_and_set_state`, three-anchor handoff, scope /
  `run_results` / `gate_decisions` schemas (W2.4); event-log
  constraints, retention, anti-bypass (W2.5); quiesce protocol
  (W2.6); startup recovery and structured exit codes (W2.7).
- W3 Python SDK: client, auto-spawn, nonce challenge (W3.1);
  lifecycle metadata, gate / replay / evidence, async flush (W3.2);
  SDK-side redaction at the trace boundary (W3.3); `RelayError`
  hierarchy aligned to the error envelope schema (W3.4);
  OpenAI/Anthropic adapters with replay-mode guards (W3.5).
- W4 TypeScript SDK: client, sidecar locator, npx bundle wrapper
  (W4.1); lifecycle parity (W4.2); redaction parity (W4.3); error
  envelope parity (W4.4); OpenAI + Anthropic + Vercel AI adapters
  and replay-mode parity (W4.5).
- W5 CLI: Typer skeleton, `rly` entrypoint, JSON + exit-code
  contract, error-envelope wrapping (W5.1); `rly sidecar`
  start/status/stop/restart/install (W5.2); `rly replay`
  list/record/run (W5.3); `rly evidence` list/show/verify (W5.4);
  `rly verify-self` invariant checker (W5.5).
- W6 contracts: cel-python evaluator (W6.1); cel-js TypeScript
  evaluator (W6.2); production UDFs `relay.coverage`,
  `relay.tool_arg`, `relay.schema_match` (W6.3); contract DSL
  parser and publish/runtime pipeline (W6.4); Relay-CEL conformance
  corpus (W6.5); `rly contract publish` and coverage invariant
  (W6.6).
- W7 replay: localhost mitmproxy harness for `rly replay run`
  (W7.1); `ReplayFixture-v1` cassette format (W7.2); Python SDK
  socket-deny gate extension (W7.3); TS undici interceptor and
  `HTTPS_PROXY` support (W7.4); egress denial test matrix (W7.5).
- W8 gates: gate evaluation pipeline (W8.1); control-plane-only
  `gate_decisions` writer (W8.2); gate restart on failure (W8.3);
  gate remediation circuit breaker and admin transitions (W8.4).
- W9 evals: runner primitives (W9.1); assertion-template library
  (W9.2); LLM-as-judge evaluator stub (deferred to month 4+) (W9.3).
- W10 verifier: offline JWKS resolver (W10.1); JWS RFC 7515
  conformance -- Python and TypeScript (W10.2); RFC 8785 JCS wiring
  into the OSS verifier (W10.3); full evidence bundle validator
  (W10.4).
- W11 ACEF: vendor-pinned ACEF v0.3 reference SDK and drift guard
  (W11.1); `x-relay` extension namespaces (W11.2); emit/parse
  roundtrip, corpus, and vendor docs (W11.3).
- W12 release engineering: PyPI trusted publish workflow and
  guards (W12.1); npm provenance trusted-publishing workflow and
  guards (W12.2); SLSA L3 provenance guard and fork-detection
  (W12.3); in-toto layout and link metadata pipeline (W12.4);
  sidecar bundle build, sign, and publish pipeline (W12.5);
  `rly verify-install` and release evidence bundle (W12.6).
- W13.1 trust-anchor governance doc and 13 VAL-W13 plumbing tests.
- W14.1 EU AI Act readiness internal draft and 13 VAL-W14 plumbing
  tests.
- W15.1 sandbox threat model doc and 13 fulfills tests.
- W16 examples: OpenAI tool-agent (Python + TypeScript) (W16.1);
  LangChain RAG-agent, Anthropic-backed (W16.2); Vercel AI
  tool-agent, TypeScript-only (W16.3); MCP tool-agent, Python
  (W16.4).
- W17 conformance: RFC 8785 JCS IETF corpus (W17.1); RFC 7515 JWS
  Appendix A corpus and test-only HS verifier (W17.2); cel-spec
  conformance corpus with cross-runtime parity and nightly drift
  (W17.3); Relay-CEL conformance corpus, cross-runtime parity,
  purity, and release block (W17.4).

### Fixed
- SDK cross-language redaction parity: JSON separators, raw bytes
  leak, `schema_version` alias, NFKC splice.
- Replay cassette path traversal, tampering, header case
  (security).
- Release pipeline: SHA-pin SLSA generator and pypa action,
  contributor-assistant, strengthened guards.
- Verifier fail-closed Sigstore, Rekor, and TSA cryptographic
  verification.
- Audit round 2: control-plane race, ECMA-262 Decimal,
  `schema_match` NaN/Inf, harness `RLock`, loopback parity.
- Audit round 3: 6 P1 structural fixes -- forced-stop primitive,
  `INVALID_TRANSITION` result, UDF capture, CEL thread bound, JCS
  BMP-only, anti-bypass shell-quote.
- Audit round 4: verifier `decided_at` fail-closed, first-ok
  signature lifecycle, unified canonical encoder.
- Sidecar `event_log` `ingest_sequence` under exclusive lock (P0).

### Security
- Replay cassette traversal and tampering closed.
- Verifier moved to fail-closed Sigstore, Rekor, and TSA paths.
- JCS BMP-only object key restriction enforced.

### Changed
- W1.5 codegen pipeline relocation: `codegen_pipeline.test.ts`
  moved into `sdk-typescript`.
- W1.5 manifest `test-tier-1` no longer carries the unknown
  `--tier=plumbing` flag.
- Resolved carried-forward findings post-W1.6 (M01 docs).
- Allocated `RELAY-SIDECAR-001..006` error codes for W2.1.
- W2 startup recovery wired into the production startup path
  (str-001); `recover_partial_lockfile` moved inside the spawn
  lock (str-002).
- `@pytest.mark.fulfills` markers added to W3.1 client tests.

## [scaffold-base] - 2026-05-12

### Added
- Initial public `relay` scaffold under Apache 2.0
  (`Initial public relay scaffold (Apache 2.0)`).
- Retroactive W0 workspace bootstrap (Python + Node).
- `.gitignore` for `.claude/` session artifacts.
