# Python SDK Reference

> Generated from packages/sdk-python/relay/__init__.py. Do not edit by hand.

The Relay Python SDK (`relay`) is the client surface for the Relay agent
reliability OS. Importing the package is side-effect-free: no sidecar is
spawned, no port is bound, no HTTP request is made. All side effects are
deferred to the first `Relay` client operation that needs the sidecar
(VAL-W3-001, VAL-W3-002, VAL-W3-003).

Per CLAUDE.md keystone invariant #1, the SDK submits lifecycle metadata
ONLY. It never writes `run_results.status` or any canonical outcome --
the sidecar control plane is the sole writer of canonical results.

## Install

```
uv add relay
```

or

```
pip install relay
```

## Reference pages

| Page | Contents |
| --- | --- |
| [Client](client.md) | The `Relay` client class and its lifecycle methods. |
| [Errors](errors.md) | The `RelayError` hierarchy and every typed leaf the SDK surfaces. |
| [Redaction](redaction.md) | `RedactionPolicy`, `RedactionEngine`, and the canonical `redact_capture_payload` entry point. |
| [Ingest lifecycle](ingest.md) | The `Run` context manager, `FlushPolicy`, and lifecycle methods. |
| [Adapters](adapters.md) | `wrap_openai`, `wrap_anthropic`, `register_tool`, `normalize_error`, span and side-effect recorders. |

## Public surface (from `__init__.py` `__all__`)

```python
from relay import (
    DEFAULT_APPLIES_TO_FIELDS,
    FlushPolicy,
    RedactionEngine,
    RedactionPolicy,
    Relay,
    RelayAuthMismatch,
    RelayCanonicalStatusForbidden,
    RelayConfigError,
    RelayError,
    RelayEvidenceIncomplete,
    RelayHandoffIncomplete,
    RelayLifecycleInvalid,
    RelayPolicyError,
    RelayReplayPrecondition,
    RelaySidecarNotReachable,
    RelaySidecarVersionMismatch,
    Run,
    SaltProvider,
    redact_capture_payload,
)
```

Adapter exports live under `relay.adapters`:

```python
from relay.adapters import (
    MODEL_CONTEXT_OVERFLOW,
    MODEL_RATE_LIMIT,
    MODEL_TIMEOUT,
    MODEL_UNKNOWN,
    NormalizedError,
    SideEffectEvent,
    SideEffectMarkerMissing,
    SideEffectRecorder,
    Span,
    SpanRecorder,
    TOOL_BAD_ARGUMENTS,
    normalize_error,
    register_tool,
    validate_pairing,
    wrap_anthropic,
    wrap_openai,
)
```

Spec: §A.1, §A.5
