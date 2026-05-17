# epochly-relay-replay-sandbox-protocol

Public Python Protocol for Relay replay sandbox drivers.

## What this package is

This OSS package exports `ReplaySandboxDriver`, the `typing.Protocol`
every Relay replay sandbox driver must implement, plus the three
supporting dataclasses (`NetworkPolicy`, `ToolPolicy`,
`EphemeralCredential`) used to configure the sandbox at provisioning
time.

Spec anchors: section E.4 lines 3939-3987 of `planning/epochly-replay-spec.md`.

## What this package is NOT

This package does NOT contain any concrete driver implementations. The
canonical drivers (`e2b`, `modal`, `local-firecracker`, `local-docker`)
live in the private `relay-platform/services/replay-workers/` repository
and are licensed proprietarily. Third-party drivers may target this
Protocol under the package's Apache 2.0 license.

The CLAUDE.md repo-boundary rule "drivers stay private" applies: the
Protocol surface is public so the ecosystem can extend the driver layer,
but the production drivers run inside the hosted Relay control plane and
are not open-sourced.

## Why a dedicated package

- Zero runtime dependencies (stdlib `typing` + `dataclasses` only).
- Third-party driver authors add a single import without pulling the
  rest of the Relay OSS stack.
- The Protocol is `@runtime_checkable`: callers may use
  `isinstance(obj, ReplaySandboxDriver)` to dispatch.
- `EphemeralCredential.ttl_seconds` is validated at construction time
  against the P0 maximum of 900 seconds (spec line 3986).

## Public API

```python
from relay_replay_sandbox_protocol import (
    EphemeralCredential,
    NetworkPolicy,
    ReplaySandboxDriver,
    SandboxExecResult,
    SandboxHandle,
    SideEffectDecision,
    SideEffectRequest,
    ToolPolicy,
)
```

## License

Apache 2.0.
