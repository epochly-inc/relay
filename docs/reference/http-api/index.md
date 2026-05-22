# HTTP API Reference

> Generated from `packages/schemas/raw/openapi.yaml`. Do not edit by hand.

These routes are exposed by the OSS local sidecar. Routes marked
`[OUT-OF-SCOPE-PRIVATE]` are stubs that return HTTP 501 with
`RELAY-HOSTED-ONLY` in the OSS sidecar; they are provided by the hosted
Relay control plane in the private `relay-platform` repository.

Once `mkdocs.yml` lands (m4-f04), this page will be replaced by a live
render of `packages/schemas/raw/openapi.yaml` via
`mkdocs-render-swagger-plugin`. The route enumeration below is the
plain-markdown placeholder used until that plugin is wired.

## Live routes (OSS sidecar)

### Diagnostics

| Method | Path | Description |
|---|---|---|
| `GET` | `/diagnostics/sqlite` | Read sidecar SQLite `journal_mode` + `busy_timeout` (W2.14 WAL diagnostic). |
| `GET` | `/diagnostics/runtime` | Read sidecar runtime diagnostics (start time, uptime, active connections, lock state). |
| `GET` | `/diagnostics/quiesce` | Read sidecar quiesce / draining state. |
| `GET` | `/diagnostics/db` | Read sidecar database connectivity diagnostics. |

See [Local-deploy / sidecar lifecycle](../../local-deploy/sidecar-lifecycle.md)
for how these endpoints are used by supervisors and self-test.

### Ingest

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/ingest` | Generic ingest probe endpoint (drain-path / in-flight-tracker test surface). |
| `POST` | `/v1/ingest/runs` | Ingest a `Run` / `RunResult`-draft lifecycle envelope. |
| `POST` | `/v1/ingest/spans:batch` | Batch-ingest spans (256 KiB per-envelope cap, depth <= 16). |
| `POST` | `/v1/ingest/contract-results:batch` | Batch-ingest `ContractResult` envelopes from the contract engine. |

See [Getting started / first agent](../../getting-started/first-agent.md)
for the ingest path used by the SDK.

### Runs

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/projects/{project_id}/runs` | List runs for a project (signed TTL cursor). |
| `GET` | `/v1/runs/{run_id}` | Read a single `Run` envelope. |
| `GET` | `/v1/runs/{run_id}/trace` | Read the paginated span trace for a run. |
| `GET` | `/v1/runs/{run_id}/result` | Read the canonical `run_result` row (control-plane authored). |
| `GET` | `/v1/runs/{run_id}/explain` | Read ranked root-cause hypotheses for a run. |

### Replay

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/replay-cases` | Create a `ReplayCase` envelope. |
| `GET` | `/v1/replay-cases/{case_id}` | Read a replay case by id. |
| `POST` | `/v1/replay-cases/{case_id}/fixtures` | Attach a `ReplayFixture` to the case. |
| `POST` | `/v1/replay-cases/{case_id}/run` | Execute a replay case (cassette mode default). |
| `GET` | `/v1/replay-results/{result_id}` | Read a `ReplayResult` envelope. |

See [How-to / debug replay failures](../../how-to/debug-replay-failures.md)
for the SRE workflow built on these routes.

### Eval

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/eval-datasets` | Register an eval dataset. |
| `POST` | `/v1/eval-runs` | Enqueue an eval run against a dataset. |
| `GET` | `/v1/eval-runs/{eval_run_id}` | Read an eval run envelope. |

### Gates

| Method | Path | Description |
|---|---|---|
| `PUT` | `/v1/gates/{gate_id}` | Upsert a gate definition. |
| `PUT` | `/v1/gate-policies/{policy_id}` | Upsert a gate-policy version. |
| `POST` | `/v1/gates/{gate_id}/drafts` | Submit a `GateDecisionDraft` (state engine resolves at most one into a canonical `gate_decision`). |
| `GET` | `/v1/gate-decisions/{decision_id}` | Read a canonical `GateDecision` envelope. |
| `GET` | `/v1/gates/{gate_id}/rounds` | List `gate_rounds` for a gate (signed TTL cursor). |

See [How-to / audit a gate decision](../../how-to/audit-gate-decision.md)
for the ML-safety-reviewer workflow.

### Evidence

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/evidence-bundles` | Create a signed evidence bundle (claim-binding rule enforced). |
| `GET` | `/v1/evidence-bundles/{bundle_id}` | Read an evidence bundle row. |
| `GET` | `/v1/evidence-bundles/{bundle_id}/download` | Download the signed bundle artifact bytes. |
| `POST` | `/v1/evidence-bundles/{bundle_id}/verify` | Verify a signed evidence bundle. |

See [Evidence / offline verification](../../evidence/offline-verification.md)
for the auditor workflow.

### Manifests

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/manifests` | Submit a new manifest version (`commit_hash` is canonical `sha256-` wire form). |
| `GET` | `/v1/manifests/{manifest_id}/versions/{commit_hash}` | Read a specific manifest version. |

See [Contracts / manifest binding](../../contracts/manifest-binding.md)
for how contracts bind to `manifest_commit_hash`.

### Redaction policies

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/redaction-policies` | Publish a new redaction-policy version (ReDoS budget enforced; `raw_capture: true` requires signed DPA + org-admin approver). |
| `GET` | `/v1/redaction-policies/{policy_id}` | Read a redaction policy version. |

### Auth

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/auth/tokens` | Create a bearer auth token (material returned once). |
| `DELETE` | `/v1/auth/tokens/{token_id}` | Revoke an auth token. |

### State engine

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/state/transition` | Apply a state-engine transition. Validates the three-anchor handoff (`scope_id`, `actor_identity_hash`, `manifest_commit_hash`) before forwarding to `compare_and_set_state`. |

## Hosted-only routes [OUT-OF-SCOPE-PRIVATE]

The following routes belong to the private `relay-platform` hosted control
plane. The OSS sidecar exposes them only as 501 stubs returning the
`RELAY-HOSTED-ONLY` error code with `blocked_surface=hosted_control_plane`.
Implementing the actual hosted logic in OSS would be a P0 boundary
violation.

| Method | Path | OSS behavior |
|---|---|---|
| `POST` | `/v1/evidence-bundles/{bundle_id}/assess` | Available on the hosted platform; OSS returns 501. |
| `GET` | `/v1/assessment-bundles/{bundle_id}` | Available on the hosted platform; OSS returns 501. |
| `GET` | `/v1/assessment-bundles/{bundle_id}/gaps` | Available on the hosted platform; OSS returns 501. |
| `GET` | `/v1/projects/{project_id}/compliance/readiness` | Available on the hosted platform; OSS returns 501. |
| `GET` | `/v1/orgs/{org_id}/usage` | Available on the hosted platform; OSS returns 501. |

See [Cloud upgrade / feature parity](../../cloud-upgrade/feature-parity.md)
for the OSS-vs-hosted comparison and
[Cloud upgrade / when to upgrade](../../cloud-upgrade/when-to-upgrade.md)
for the decision framework.

---

Spec: §B
