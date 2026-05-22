# `relay.errors` -- exception hierarchy

> Generated from packages/sdk-python/relay/__init__.py. Do not edit by hand.

Every SDK-surfaced failure is a subclass of `RelayError`. The hierarchy
is two-deep: a base class, ten namespace intermediates (one per
`RELAY-{AREA}-*` code prefix), typed leaves for codes the SDK explicitly
maps, and a forward-compat fallback `RelayUnknownError` for codes the
SDK does not recognise (VAL-W3-035).

Every error carries `code`, `error_class`, `http_status`, `message`,
`blocked_surface`, `documentation_url`, `retry_advice` (a structured
dict per VAL-W3-031), `request_id`, `trace_id`, and a `details` payload.

## Base class

### `RelayError`

```python
from __future__ import annotations
from typing import Any, ClassVar

class RelayError(Exception):
    code: ClassVar[str] = "RELAY-SDK-001"
    error_class: ClassVar[str] = "RELAY-SDK-ERROR"
    http_status: ClassVar[int] = 500

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        http_status: int | None = None,
        blocked_surface: str | None = None,
        retry_advice: dict[str, Any] | str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
        documentation_url: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None: ...

    def to_envelope(self) -> dict[str, Any]: ...

    @classmethod
    def from_envelope(cls, envelope: dict[str, Any]) -> RelayError: ...
```

`to_envelope` returns a JSON-serialisable dict carrying
`schema_version` (`relay.sdk_error.v1`), the code/status/message/blocked
surface, the structured retry-advice dict, and request/trace ids
(VAL-W3-029). `from_envelope` parses a sidecar response back into the
correct typed subclass.

## Policy-violation leaves

### `RelayCanonicalStatusForbidden`

```python
from typing import ClassVar
from relay.errors import RelayIngestError

class RelayCanonicalStatusForbidden(RelayIngestError):
    code: ClassVar[str] = "RELAY-SDK-005"
    error_class: ClassVar[str] = "RELAY-SDK-CANONICAL-STATUS-FORBIDDEN"
    http_status: ClassVar[int] = 422
```

The SDK refused to submit an envelope containing a canonical-result
field (e.g. `run_results.status`). Per CLAUDE.md invariant #1 the
control plane is the sole writer of canonical results. The sidecar
enforces the same invariant via wire code `RELAY-ING-031`.

```python
from relay import RelayCanonicalStatusForbidden

try:
    raise RelayCanonicalStatusForbidden("blocked")
except RelayCanonicalStatusForbidden as exc:
    print(exc.code, exc.blocked_surface)
```

### `RelayLifecycleInvalid`

```python
from typing import ClassVar
from relay.errors import RelaySdkError

class RelayLifecycleInvalid(RelaySdkError):
    code: ClassVar[str] = "RELAY-SDK-006"
    error_class: ClassVar[str] = "RELAY-SDK-LIFECYCLE-INVALID"
    http_status: ClassVar[int] = 400
```

`client_lifecycle_status` value is outside the closed enum
(VAL-W3-012). Raised at the SDK boundary BEFORE the HTTP request.

### `RelayPolicyError`

```python
from typing import ClassVar
from relay.errors import RelayIngestError

class RelayPolicyError(RelayIngestError):
    code: ClassVar[str] = "RELAY-SDK-010"
    error_class: ClassVar[str] = "RELAY-SDK-POLICY-INVALID"
    http_status: ClassVar[int] = 422
```

Redaction policy failed to parse or violated a structural invariant.
The sidecar surfaces the W3.3 defense-in-depth wire code
`RELAY-ING-032` for the same condition; the transport preserves the
wire code in `details["code"]`.

## Configuration leaves

### `RelayConfigError`

```python
from typing import ClassVar
from relay.errors import RelaySdkError

class RelayConfigError(RelaySdkError):
    code: ClassVar[str] = "RELAY-SDK-001"
    error_class: ClassVar[str] = "RELAY-SDK-CONFIG-001"
    http_status: ClassVar[int] = 400
```

Invalid SDK configuration detected synchronously at construction
(`project_key`, `agent`, missing handoff anchor, malformed
`flush_policy`, malformed `endpoint_url`, etc.).

### `RelayAuthMismatch`

```python
from typing import ClassVar
from relay.errors import RelayAuthError

class RelayAuthMismatch(RelayAuthError):
    code: ClassVar[str] = "RELAY-SDK-004"
    error_class: ClassVar[str] = "RELAY-SDK-AUTH-MISMATCH"
    http_status: ClassVar[int] = 401
```

The sidecar rejected, or failed to satisfy, the nonce-challenge
authentication. `blocked_surface` defaults to `GET /health`.

## Connectivity leaves

### `RelaySidecarNotReachable`

```python
from typing import ClassVar
from relay.errors import RelaySidecarError

class RelaySidecarNotReachable(RelaySidecarError):
    code: ClassVar[str] = "RELAY-SDK-003"
    error_class: ClassVar[str] = "RELAY-SDK-NO-SIDECAR"
    http_status: ClassVar[int] = 503
```

No sidecar is reachable and auto-spawn is disabled
(`RELAY_NO_AUTOSPAWN=1`).

### `RelaySidecarVersionMismatch`

```python
from typing import ClassVar
from relay.errors import RelaySidecarError

class RelaySidecarVersionMismatch(RelaySidecarError):
    code: ClassVar[str] = "RELAY-SDK-002"
    error_class: ClassVar[str] = "RELAY-SDK-VERSION-MISMATCH"
    http_status: ClassVar[int] = 503
```

The attached sidecar reports a version outside the SDK compatibility
range.

## Evidence / replay leaves

### `RelayEvidenceIncomplete`

```python
from typing import ClassVar
from relay.errors import RelayEvidenceError

class RelayEvidenceIncomplete(RelayEvidenceError):
    code: ClassVar[str] = "RELAY-SDK-008"
    error_class: ClassVar[str] = "RELAY-SDK-EVIDENCE-INCOMPLETE"
    http_status: ClassVar[int] = 422
```

Evidence envelope is missing one or more required binding fields
(`artifact_digest_sha256`, `command_id`, `exit_code`, `span_ids`,
`assertion_ids`). Per spec §K a "pass" claim without these bindings is
`invalid`, not `accepted`. The wire equivalent is `RELAY-EVID-002`.

### `RelayHandoffIncomplete`

```python
from typing import ClassVar
from relay.errors import RelayIngestError

class RelayHandoffIncomplete(RelayIngestError):
    code: ClassVar[str] = "RELAY-SDK-007"
    error_class: ClassVar[str] = "RELAY-SDK-HANDOFF-INCOMPLETE"
    http_status: ClassVar[int] = 422
```

Three-anchor handoff is missing or stale. The wire equivalents are
`RELAY-ING-022` and the spec §B.4 stale-handoff code `RELAY-GATE-021`.

### `RelayReplayPrecondition`

```python
from typing import ClassVar
from relay.errors import RelayReplayError

class RelayReplayPrecondition(RelayReplayError):
    code: ClassVar[str] = "RELAY-SDK-009"
    error_class: ClassVar[str] = "RELAY-SDK-REPLAY-PRECONDITION"
    http_status: ClassVar[int] = 422
```

Replay creation precondition failed -- the canonical `run_result` row
has not yet been written. The wire equivalent is `RELAY-REPLAY-002`.

Spec: §H, §K
