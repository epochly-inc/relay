# `relay.Relay` -- client class

> Generated from packages/sdk-python/relay/__init__.py. Do not edit by hand.

`Relay` is the SDK entry point. Construction validates configuration and
stores it. It does NOT spawn the local sidecar, bind a port, or make any
HTTP request -- those side effects are deferred to the first operation
that needs the sidecar (VAL-W3-002, VAL-W3-003).

Per CLAUDE.md keystone invariant #1, the `Relay` client submits
lifecycle metadata only; it never writes canonical results.

## Constructor

```python
class Relay:
    def __init__(
        self,
        project_key: str,
        *,
        relay_home: Path | None = None,
        flush_policy: FlushPolicy | dict[str, Any] | None = None,
        actor_identity_hash: str | None = None,
        manifest_commit_hash: str | None = None,
        redaction_policy_version: str | None = None,
        endpoint_url: str | None = None,
    ) -> None: ...
```

**Args**

- `project_key` -- a 26-character Crockford-base32 ULID OR a
  `relay_pk_` project token (>= 16 URL-safe base64 chars). Validated
  synchronously before any network or sidecar interaction (VAL-W3-005).
  Invalid values raise `RelayConfigError` (`RELAY-SDK-001` /
  `RELAY-SDK-CONFIG-001`).
- `relay_home` -- optional override of the Relay home directory
  (`${RELAY_HOME}` or `~/.relay`). The sidecar lockfile, event log,
  and database live here. Mainly a test-injection seam.
- `flush_policy` -- a `FlushPolicy` or a `dict` with `mode` and/or
  `on_error` keys. Defaults to `FlushPolicy(mode="sync", on_error="raise")`.
- `actor_identity_hash`, `manifest_commit_hash`,
  `redaction_policy_version` -- three-anchor handoff defaults. May be
  supplied per-call on `Relay.run(...)` instead.
- `endpoint_url` -- override the sidecar's loopback endpoint URL.
  Mainly a test seam; production callers leave it `None`.

**Raises**

- `RelayConfigError` -- `project_key` is missing, empty, the wrong
  type, or not a recognised key shape.

## Properties

```python
@property
def project_key(self) -> str: ...

@property
def relay_home(self) -> Path: ...
```

## `Relay.trace`

```python
def trace(self, name: str, **attributes: Any) -> SidecarConnection: ...
```

Begin a trace -- the first W3.1 operation that needs the sidecar.
Calling `trace` lazily spawns or attaches to the sidecar and completes
the `/health` authentication handshake. Returns the live
`SidecarConnection`. Per CLAUDE.md invariant #1, this method carries
NO canonical-write path.

**Raises**

- `RelayConfigError` -- `name` is empty or not a string.
- `RelaySidecarNotReachable` -- `RELAY_NO_AUTOSPAWN=1` is set and no
  sidecar is reachable.
- `RelaySidecarVersionMismatch` -- the sidecar version is outside the
  SDK compatibility range.
- `RelayAuthMismatch` -- the `/health` nonce challenge failed.

## `Relay.run`

```python
def run(
    self,
    *,
    agent: dict[str, Any],
    run_id: str | None = None,
    actor_identity_hash: str | None = None,
    manifest_commit_hash: str | None = None,
    redaction_policy_version: str | None = None,
    flush_policy: FlushPolicy | dict[str, Any] | None = None,
    endpoint_url: str | None = None,
    project_id: str | None = None,
) -> Run: ...
```

Start a W3.2 lifecycle run. Returns a `Run` context manager. The caller's
`with` block records lifecycle events via `Run.capture`, evaluates gates
via `Run.gate_evaluate`, creates replay cases via `Run.replay_create`,
and submits evidence via `Run.submit_evidence`. On `__exit__` the SDK
flushes the lifecycle envelope per the configured `FlushPolicy`.

The three-anchor handoff anchors (`actor_identity_hash`,
`manifest_commit_hash`, `redaction_policy_version`) may be supplied
either on the `Relay` constructor or per-call here. A missing anchor
raises `RelayConfigError`. See `ingest.md` for the `Run` surface.

**Raises**

- `RelayConfigError` -- `agent` is missing/empty; one of the handoff
  anchors is missing and no client-level default is set;
  `flush_policy` is malformed.
- `RelayHandoffIncomplete` -- one of the three handoff anchors
  resolves to an empty/missing value at envelope-build time.

## `Relay.close`

```python
def close(self) -> None: ...
```

Release SDK-side resources (the shared httpx client). Does NOT stop the
sidecar -- the sidecar owns its own lifecycle via the W2.6 quiesce /
idle-shutdown protocol and `rly sidecar stop`. The SDK never kills the
sidecar.

## Context manager

`Relay` implements `__enter__` / `__exit__`. The exit handler calls
`close()`.

```python
from relay import Relay

with Relay("01JE6N2K8H5F0WZ8N1X3R7T0AB") as client:
    # Inside the `with` block, the SDK is ready; call `client.trace(...)`
    # or `client.run(agent=...)` to begin a W3.1 / W3.2 operation. Those
    # calls lazily spawn the sidecar (omitted here so the snippet is
    # side-effect-free and audit-executable in isolation).
    pass
```

Spec: §A.1, §C.5
