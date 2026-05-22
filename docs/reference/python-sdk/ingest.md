# `relay.Run` -- ingest lifecycle

> Generated from packages/sdk-python/relay/__init__.py. Do not edit by hand.

`Run` is the SDK-side, run-scoped lifecycle context returned by
`Relay.run(...)`. The user code inside the `with` block records
lifecycle metadata, evaluates gates, creates replay cases, and submits
evidence. On `__exit__` the SDK flushes the terminal lifecycle envelope
per the configured `FlushPolicy`.

Per CLAUDE.md keystone invariant #1, a `Run` instance NEVER writes
canonical results. It submits drafts and reads canonical decisions the
control plane wrote. The sidecar enforces the same invariant via wire
code `RELAY-ING-031`; the SDK enforces it locally via
`RelayCanonicalStatusForbidden` BEFORE the HTTP request leaves the
process.

## `FlushPolicy`

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Literal

FlushMode = Literal["sync", "async"]
OnErrorMode = Literal["raise", "drop_and_log"]


@dataclass(frozen=True)
class FlushPolicy:
    mode: FlushMode = "sync"
    on_error: OnErrorMode = "raise"

    @classmethod
    def from_mapping(cls, value: Any) -> FlushPolicy: ...
```

The SDK flush policy (spec line 2016). `FlushMode` is
`Literal["sync", "async"]`; `OnErrorMode` is
`Literal["raise", "drop_and_log"]`.

**Attributes**

- `mode` -- `sync`: `Run.__exit__` blocks on outbound HTTP I/O until
  the sidecar acknowledges. `async`: the call is enqueued onto a
  background dispatcher thread and `Run.__exit__` returns immediately
  (VAL-W3-018). The dispatcher's worker thread is a daemon; callers
  that need deterministic drainage MUST call `Run.flush()` before
  exiting the context.
- `on_error` -- `raise`: a transport failure propagates as a
  `RelayError` subclass. `drop_and_log`: a transport failure emits a
  single WARN log line and is otherwise swallowed (VAL-W3-019). The
  host application is never perturbed in `drop_and_log` mode.

**`from_mapping`** coerces a user-supplied value into a `FlushPolicy`:

- `None` -> defaults `(sync, raise)`.
- A `FlushPolicy` instance is returned as-is.
- A `dict` with `mode` and/or `on_error` keys; unknown keys raise
  `RelayConfigError`. Invalid `mode` or `on_error` values raise
  `RelayConfigError` at the SDK boundary.

## `Run`

```python
class Run:
    def __init__(
        self,
        *,
        relay: Relay,
        run_id: str,
        agent: dict[str, Any],
        actor_identity_hash: str,
        manifest_commit_hash: str,
        redaction_policy_version: str,
        project_id: str | None = None,
        flush_policy: FlushPolicy | None = None,
        endpoint_url: str | None = None,
    ) -> None: ...
```

Construction is performed by `Relay.run(...)`; user code does not
instantiate `Run` directly.

**Attributes**

- `run_id` -- the run's canonical ULID. Flows into the three-anchor
  handoff's `scope_id` slot.
- `agent` -- the caller-supplied agent descriptor dict.
- `actor_identity_hash`, `manifest_commit_hash`,
  `redaction_policy_version` -- the three-anchor handoff anchors
  (spec §C.5). A missing or empty anchor raises
  `RelayHandoffIncomplete` at envelope-build time.
- `project_id` -- caller-supplied or auto-generated UUID4.
- `trace_id` -- per-run trace identifier (UUID4).
- `flush_policy` -- the resolved `FlushPolicy` for this run.
- `idempotency_keys` -- list of ULID idempotency keys, one per
  lifecycle envelope dispatched. Tests inspect this for cross-language
  fixture comparison. Per VAL-W3-017, calling `trace()` twice with the
  same input MUST use distinct keys.

## `Run.capture`

```python
def capture(self, *, client_lifecycle_status: str) -> dict[str, Any]: ...
```

Submit a lifecycle-metadata envelope to the sidecar. The status MUST
be one of the values in `LIFECYCLE_STATUSES` -- any other value raises
`RelayLifecycleInvalid` at the SDK boundary BEFORE the HTTP request is
sent (VAL-W3-012).

A canonical-status value (such as a `run_results.status` field) raises
`RelayCanonicalStatusForbidden` per CLAUDE.md invariant #1.

## `Run.gate_evaluate`

```python
def gate_evaluate(
    self,
    *,
    gate_id: str,
    release_sha: str,
    eval_run_ids: list[str],
) -> dict[str, Any]: ...
```

Submit a gate-decision DRAFT and read the canonical decision. Per
VAL-W3-013 the SDK MUST submit an evidence-only draft, then read the
canonical `GateDecision` the control plane wrote. The SDK NEVER
computes pass/fail.

The return value is the canonical `GateDecision` envelope.

## `Run.replay_create`

```python
def replay_create(
    self,
    *,
    run_id: str,
    egress_allowlist: list[str] | None = None,
) -> dict[str, Any]: ...
```

Create a replay case bound to the canonical `RunResult`. Per VAL-W3-014
the SDK MUST first fetch the canonical `run_result` row; if it is
missing the sidecar returns `RELAY-REPLAY-002` and the SDK raises
`RelayReplayPrecondition`. The SDK does NOT derive a replay case from
raw SDK lifecycle.

When `egress_allowlist` is supplied, every entry is validated against
the SSRF guard at the SDK boundary BEFORE the request is sent. A
rejected entry raises `relay.network_policy.EgressDenied`
(audit-r3 BUG-B3).

## `Run.submit_evidence`

```python
def submit_evidence(
    self,
    *,
    artifact_digest_sha256: str,
    command_id: str,
    exit_code: int,
    span_ids: list[str],
    assertion_ids: list[str],
) -> dict[str, Any]: ...
```

Submit an evidence-bundle envelope bound to its claim. Per VAL-W3-015
every required field MUST be present and bound; a missing field raises
`RelayEvidenceIncomplete` at the SDK boundary BEFORE the request is
sent. Per spec §K a "pass" claim without these bindings is `invalid`,
not `accepted`.

## `Run.flush`

```python
def flush(self) -> None: ...
```

Block until any background-dispatched work has completed. Required in
`async` mode when the caller needs deterministic drainage before
exiting the context. Has no effect in `sync` mode.

## Context manager

`Run` implements `__enter__` / `__exit__`. The exit handler determines
the terminal lifecycle status (`client_succeeded` on clean exit,
`client_failed` if an exception propagated, or whatever was last
explicitly captured) and dispatches the terminal envelope per the
configured `FlushPolicy`.

Per VAL-W3-018, `__exit__` MUST NOT block on ingest network I/O when
`flush_policy.mode == 'async'`. The dispatcher's worker thread is a
daemon -- it continues after `__exit__` returns and is reaped at
interpreter shutdown.

## Example

```python
from relay import Relay, FlushPolicy


def run_example() -> None:
    with Relay("01JE6N2K8H5F0WZ8N1X3R7T0AB") as client:
        with client.run(
            agent={"name": "support-triage", "version": "0.1.0"},
            actor_identity_hash="sha256:" + "0" * 64,
            manifest_commit_hash="abc1234",
            redaction_policy_version="example.v1",
            flush_policy=FlushPolicy(mode="sync", on_error="raise"),
        ) as run:
            run.capture(client_lifecycle_status="in_progress")
            run.submit_evidence(
                artifact_digest_sha256="sha256:" + "1" * 64,
                command_id="cmd_smoke",
                exit_code=0,
                span_ids=["01JE6N2K8H5F0WZ8N1X3R7T0AC"],
                assertion_ids=["VAL-EXAMPLE-001"],
            )
            decision = run.gate_evaluate(
                gate_id="release-gate",
                release_sha="0123456789abcdef",
                eval_run_ids=[run.run_id],
            )
            print(decision)
```

Spec: §A.1
