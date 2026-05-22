# Manifest Binding

A contract describes the *behavior* a workload must satisfy. It is meaningful
only in the context of the *runtime configuration* that workload runs under:
the declared commands, services, validation surfaces, redaction policy
version, and tool side-effect classifications. That runtime configuration is
captured in a Relay manifest (spec §F). Binding every contract evaluation to
the exact manifest in force at the moment of evaluation — by way of the
manifest's content-addressed commit hash — is what makes a gate decision
auditable later.

This page explains:

- How `manifest_commit_hash` is computed and where it appears.
- How the three-anchor handoff (§C.5) uses it to reject stale work.
- What "stale manifest" means and how to recover.
- How to publish a contract bundle that pins to a manifest.

## Why binding matters

A "PASS" claim against assertion `VAL-X-001` is not portable across manifest
revisions. If the manifest changes — a command's `argv` shifts, a service
swaps image digest, a validation surface is added, or a side-effect tool is
reclassified — the surface the assertion ran against is no longer the same
surface, and the prior PASS no longer holds. Pinning every gate decision,
every evidence claim, and every event-log entry to a specific
`manifest_commit_hash` makes this explicit. An auditor reading a bundle can
recover the exact manifest in force, recover the declared commands and their
`command_hash` values, and re-derive what the worker was permitted to do.

This is the source-of-truth invariant the spec calls out at §F:

> The manifest is the source of truth for what a worker is allowed to run.
> Workers REFUSE to execute commands not declared in the active manifest.
> Every event-log entry written by a worker carries `manifest_commit_hash`
> of the manifest under which it ran.

## The `manifest_commit_hash` field

`manifest_commit_hash` is the SHA-256 content hash of the active manifest
document at the moment of submission. It appears as a required or
recommended field on:

- `runs` (raw ingestion records)
- `run_results` (control-plane-owned canonical outcomes)
- `gate_decisions` and `gate_decision_drafts`
- `evidence_bundles` and per-claim evidence payloads
- `replay_cases`
- Every event-log entry written by a worker

The CLI surfaces it explicitly on every command that participates in the
three-anchor handoff. For example, `rly gate evaluate` accepts a
`--manifest <hash>` option whose value becomes the `manifest_commit_hash`
posted on the gate draft. The canonical manifest schema lives at
`packages/schemas/catalogs/manifest.v1.schema.json` and is described in
spec §F.

## Three-anchor handoff (§C.5)

Spec §C.5 defines the verification step every receiving actor (ingest,
validation, gate engine, result writer) MUST perform on every handoff:

```python
def verify_three_anchor_handoff(scope_kind, scope_id, payload) -> HandoffResult:
    # (1) Scope/run anchor: must match the scope ID in the URL/path.
    if payload["run_id"] != scope_id and scope_kind == "run":
        return HandoffResult(ok=False, reason="SCOPE_ID_MISMATCH")

    # (2) Actor identity anchor: actor_identity_hash must be registered.
    if not actor_registry.is_active(payload["actor_identity_hash"]):
        return HandoffResult(ok=False, reason="ACTOR_NOT_REGISTERED")

    # (3) Manifest/commit anchor: manifest_commit_hash must be current for this project,
    #     unless explicitly grandfathered for a deprecated rollout window.
    if not manifest_registry.is_active(payload["project_id"], payload["manifest_commit_hash"]):
        # Allow up to manifest.grace_window after a rotation.
        if not manifest_registry.is_in_grace(payload["project_id"], payload["manifest_commit_hash"]):
            return HandoffResult(ok=False, reason="MANIFEST_NOT_ACTIVE")

    return HandoffResult(ok=True)
```

The three anchors are:

1. **`scope_id`** — the run, gate, or feature identifier the handoff is
   scoped to. Must match the scope ID in the URL or path.
2. **`actor_identity_hash`** — the registered identity of the worker, CI
   runner, or SDK process performing the handoff. Must be active in the
   actor registry.
3. **`manifest_commit_hash`** — the manifest commit the worker computed
   against. Must be either the project's currently-active manifest OR a
   prior manifest still inside its `grace_window` (default 1800 seconds
   per §F).

If any anchor fails, the receiving actor rejects the submission with
`RELAY-GATE-021` (HTTP 422, exit code 4 in CLI surfaces) and the
contract evaluation does not produce a `gate_decision`. The draft is
marked `resolution_state = "rejected_handoff"` and consumes no
remediation round.

## Stale-manifest scenarios

A handoff is "stale on the manifest anchor" when the worker's
`manifest_commit_hash` is neither the active manifest nor inside the
grace window. The most common causes:

- The project rotated its manifest while the worker was running, AND
  the rotation completed more than `grace_window.seconds` (default
  1800 s) ago.
- The worker cached an old manifest from a prior CI build and never
  refreshed.
- The worker is targeting a different `project_id` than the manifest
  is registered under (often a copy-paste from a staging environment).
- The worker computed `manifest_commit_hash` from an uncommitted
  working tree edit.

When you observe `RELAY-GATE-021` with reason `MANIFEST_NOT_ACTIVE`:

1. **Re-fetch the active manifest** for the project from the control
   plane (or the local sidecar).
2. **Recompute `manifest_commit_hash`** from the freshly-fetched
   manifest body.
3. **Re-publish the contract bundle** with the updated hash inside the
   bundle's `manifest_commit_hash` field.
4. **Re-submit the gate draft** with the updated `--manifest <hash>`
   value.

Do not retry blindly. A stale handoff that retries with the same
anchors will be rejected the same way; the manifest registry's
verdict does not flap.

## Worked example

A minimal contract publish bundle (`relay.contract_publish_bundle.v1`)
pinning to a specific manifest looks like this:

```json
{
  "schema_version": "relay.contract_publish_bundle.v1",
  "manifest_commit_hash": "sha256-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "assertions": [
    {
      "schema_version": "relay.assertion.behavioral.v1",
      "assertion_id": "VAL-CLAIM-001",
      "kind": "behavioral",
      "severity": "p0",
      "title": "Claim decision must include rationale.",
      "applies_to": {
        "agent_name": "claims-agent",
        "span_kind": ["model_call"],
        "tool_filter": null
      },
      "expression": {
        "op": "json_path_exists",
        "path": "$.rationale"
      },
      "owner_email": "trust@example.com",
      "lifecycle_state": "active",
      "repair_policy": "none"
    }
  ],
  "gates": [
    {
      "schema_version": "relay.gate_policy.v1",
      "policy_version": "2026-05-12.001",
      "gates_assertion_ids": ["VAL-CLAIM-001"]
    }
  ]
}
```

Publish the bundle:

```bash
rly contract publish ./contract-bundle.json --out ./coverage-report.json
```

`rly contract publish` takes the bundle path as a positional argument; the
`manifest_commit_hash` value rides inside the bundle JSON rather than as a
separate flag. The CLI validates the bundle envelope, verifies the coverage
invariant (every active assertion has exactly one owning gate), and writes
a draft coverage report. The control plane resolves that draft into a
canonical `gate_decision` separately — workers never write `run_results` or
`gate_decisions` directly (CLAUDE.md keystone invariant 1).

To evaluate a gate after publish, supply the same manifest commit hash as
the manifest anchor of the three-anchor handoff:

```bash
rly gate evaluate \
  --gate-id 5f3e6c9b-1d2a-4f50-8d7e-7c8f9a0b1c2d \
  --manifest sha256-9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
  --actor sha256-actor-identity-hash-here \
  --project 8a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9 \
  --release-sha 2c4f1e8b9a7d6c5e3b2a1f0e9d8c7b6a5f4e3d2c1b0a9988776655443322110f
```

If the `--manifest` value is not the project's active manifest (and not
inside the grace window), the sidecar returns `RELAY-GATE-021` and the
CLI exits non-zero. See the error reference at
[../reference/errors/RELAY-GATE-021/index.md](../reference/errors/RELAY-GATE-021/index.md)
for the full envelope and recovery steps.

## See also

- [CEL primer](cel-primer.md) — CEL syntax and Relay's `pure=True`
  constraint for custom UDFs.
- [UDF reference](udf-reference.md) — the registered Relay CEL UDFs.
- Error reference: [`RELAY-GATE-021`](../reference/errors/RELAY-GATE-021/index.md)

Spec: §C.5, §F
