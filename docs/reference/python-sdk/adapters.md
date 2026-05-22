# `relay.adapters` -- provider wrappers and side-effect markers

> Generated from packages/sdk-python/relay/adapters/__init__.py. Do not edit by hand.

The adapter layer wraps provider SDKs (OpenAI, Anthropic, ...) so every
model call and embedded tool call is captured as a Relay `Span` on a
`SpanRecorder`. Adapters are duck-typed: they NEVER import the provider
package at module load, so installing the Apache-2.0 OSS Relay SDK does
NOT pull commercial provider SDKs as transitive dependencies.

Per CLAUDE.md keystone invariant #1, adapters NEVER write canonical
results -- they accumulate spans into a `SpanRecorder` for the W3.2
lifecycle ingest surface to ship to the sidecar.

## `wrap_openai`

```python
def wrap_openai(
    client: Any,
    *,
    recorder: SpanRecorder | None = None,
    sdk_version: str | None = None,
) -> _WrappedOpenAIClient: ...
```

Wrap an OpenAI client so every `client.chat.completions.create(...)`
invocation records Relay spans (a `model_call` parent plus one
`tool_call` child per embedded tool call, plus one `stream_chunk` per
chunk in streaming mode).

**Args**

- `client` -- an object exposing `.chat.completions.create(**kwargs)`.
  In production this is an `openai.OpenAI` instance; tests pass any
  duck-typed stand-in.
- `recorder` -- optional `SpanRecorder` to record into. When `None` a
  fresh recorder is created and made available via `wrapper.recorder`.
- `sdk_version` -- override the auto-detected SDK version string
  (`openai@<version>`, or `openai@unknown` when the package is not
  importable).

**Returns** a wrapped client mirroring the OpenAI client surface. Any
attribute the adapter does not own is forwarded to the underlying
client via `__getattr__`.

## `wrap_anthropic`

```python
def wrap_anthropic(
    client: Any,
    *,
    recorder: SpanRecorder | None = None,
    sdk_version: str | None = None,
) -> _WrappedAnthropicClient: ...
```

Wrap an Anthropic client so every `client.messages.create(...)` call
records Relay spans (a `model_call` parent, one `tool_call` child per
`tool_use` content block, plus one `stream_chunk` per streamed event).

Anthropic does not expose `system_fingerprint`, so the
`model_signature` is `anthropic:<model>` (VAL-W3-043). The refresh
policy detects drift by observing a change in this string.

Args mirror `wrap_openai`. `sdk_version` defaults to
`anthropic@<version>` (or `anthropic@unknown`).

## `register_tool`

```python
def register_tool(
    func: Callable[..., Any],
    *,
    name: str,
    side_effect: bool,
    recorder: SideEffectRecorder | None = None,
) -> Callable[..., Any]: ...
```

Wrap `func` so it emits pre/post side-effect markers when
`side_effect=True` (CLAUDE.md keystone invariant #6, spec §X,
VAL-W3-047). When `side_effect=False` the wrapper is a transparent
passthrough -- no markers are emitted.

**Args**

- `func` -- the tool function to wrap.
- `name` -- the tool's canonical name (e.g.
  `"crm.create_case_note"`). Embedded in markers so the gate engine
  can attribute the event to the right tool descriptor.
- `side_effect` -- when `True` the wrapped callable emits a
  `tool.pre_action` marker BEFORE calling `func` and (on success) a
  `tool.post_success_proof` marker AFTER. The markers carry
  `tool_name`, `idempotency_key`, and `args_hash` /
  `result_hash`.
- `recorder` -- where to write markers. When `None` and
  `side_effect=True`, a fresh `SideEffectRecorder` is created and
  exposed as `wrapped._recorder` for caller inspection (mostly for
  tests; production code passes the run-level recorder).

`idempotency_key` is the SHA-256 hex digest of the canonical
`(name, args, kwargs)` JSON bytes (sorted keys, `default=str`). It
is stable across identical invocations and differs for different
arguments.

## `normalize_error`

```python
def normalize_error(
    exc: BaseException, *, context: dict[str, Any] | None = None
) -> NormalizedError: ...
```

Translate a provider exception into a `NormalizedError` (VAL-W3-046).
Dispatch is duck-typed on `type(exc).__module__` + `__qualname__` plus
attribute hints (e.g. an OpenAI `BadRequestError` whose `.code ==
'context_length_exceeded'`).

**Args**

- `exc` -- the raised exception caught around the model/tool call.
- `context` -- optional adapter-supplied hints. Recognised keys:
  - `tool_call` (bool) -- the failure occurred while invoking a tool
    function rather than the model itself.

**Returns** a `NormalizedError` carrying `code`, `raw_type`,
`signature`, `message`.

Dispatch order:

1. `MODEL_RATE_LIMIT` -- provider raised `RateLimitError`.
2. `MODEL_TIMEOUT` -- provider raised `APITimeoutError`, a builtin
   `TimeoutError`, or an httpx timeout.
3. `MODEL_CONTEXT_OVERFLOW` -- OpenAI `.code ==
   'context_length_exceeded'`, or Anthropic
   `invalid_request_error` with `too long` / `context` in the
   message.
4. `TOOL_BAD_ARGUMENTS` -- when `context['tool_call'] is True` and
   the exception is a `ValueError` / `TypeError` (or the message
   names an argument); also matched on bare `ValueError` whose
   message mentions both `tool` and `argument`.
5. `MODEL_UNKNOWN` -- fallback. The original `raw_type` and a
   deterministic `signature` are still attached so downstream
   binders can attribute even unknown failure modes.

## `NormalizedError`

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizedError:
    code: str
    raw_type: str
    signature: str
    message: str
```

- `code` -- one of `MODEL_RATE_LIMIT`, `MODEL_TIMEOUT`,
  `MODEL_CONTEXT_OVERFLOW`, `TOOL_BAD_ARGUMENTS`, `MODEL_UNKNOWN`.
  Construction raises `ValueError` for any other value.
- `raw_type` -- `f"{module}.{qualname}"` of the original exception
  class.
- `signature` -- `SHA-256(raw_type + "|" + code)` truncated to 32 hex
  characters. Stable across runs so the refresh policy can detect
  signature drift.
- `message` -- the original exception's `str()`.

The closed set of code constants is exported at module scope:

```python
MODEL_RATE_LIMIT: Final[str] = "MODEL_RATE_LIMIT"
MODEL_TIMEOUT: Final[str] = "MODEL_TIMEOUT"
MODEL_CONTEXT_OVERFLOW: Final[str] = "MODEL_CONTEXT_OVERFLOW"
TOOL_BAD_ARGUMENTS: Final[str] = "TOOL_BAD_ARGUMENTS"
MODEL_UNKNOWN: Final[str] = "MODEL_UNKNOWN"
```

## `Span`

```python
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Span:
    span_id: str
    kind: str
    attributes: dict[str, Any] = field(default_factory=dict)
```

A single span emitted by an adapter.

- `span_id` -- a fresh ULID identifying this span; used as the
  `parent_span_id` reference for any child span.
- `kind` -- one of `"model_call"`, `"tool_call"`, `"stream_chunk"`.
- `attributes` -- span-kind-specific payload (provider/model/tokens
  for `model_call`; tool_name/args/result for `tool_call`;
  chunk_sequence/event_type for `stream_chunk`).

## `SpanRecorder`

```python
class SpanRecorder:
    def __init__(self) -> None: ...

    def new_span(self, kind: str, **attributes: Any) -> Span: ...

    @property
    def spans(self) -> list[Span]: ...

    def clear(self) -> None: ...
```

In-memory list of spans produced by an adapter. The transport layer
(`relay.run`) ships these spans to the sidecar; the adapter never
makes HTTP calls itself. Thread-safe -- a single recorder may be
passed to multiple adapter invocations and concurrent `new_span` calls
are serialised by an internal lock.

`new_span` raises `ValueError` for any `kind` outside
`{"model_call", "tool_call", "stream_chunk"}`. The `spans` property
returns a snapshot copy in insertion order.

## `SideEffectEvent`

```python
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SideEffectEvent:
    kind: str
    occurred_at: float
    attributes: dict[str, Any] = field(default_factory=dict)
```

One side-effect event_log entry.

- `kind` -- `"tool.pre_action"` or `"tool.post_success_proof"`.
- `occurred_at` -- `time.monotonic()`-derived timestamp (seconds,
  float). Monotonic guarantees strict ordering within a process; the
  wire envelope serialises this to `occurred_at` ISO-8601 at lifecycle
  ingest.
- `attributes` -- free-form per-event payload: `tool_name`,
  `idempotency_key`, `args_hash` for `pre_action`; `tool_name`,
  `idempotency_key`, `result_hash` for `post_success_proof`.

## `SideEffectRecorder`

```python
class SideEffectRecorder:
    def __init__(self) -> None: ...

    def record(self, kind: str, **attributes: Any) -> SideEffectEvent: ...

    @property
    def events(self) -> list[SideEffectEvent]: ...

    def clear(self) -> None: ...
```

In-memory store of side-effect event_log entries. Thread-safe.
`record` raises `ValueError` for any `kind` outside
`{"tool.pre_action", "tool.post_success_proof"}`.

## `SideEffectMarkerMissing`

```python
class SideEffectMarkerMissing(Exception): ...
```

Raised by `validate_pairing` when a `tool.post_success_proof` event
has no matching `tool.pre_action` marker (matched by
`idempotency_key`).

## `validate_pairing`

```python
def validate_pairing(events: list[dict[str, Any]]) -> None: ...
```

Verify every post-success proof has a preceding pre-action marker.
Used by the gate engine when consolidating event_log entries for a
run. Raises `SideEffectMarkerMissing` on the first orphan proof.

## Example

```python
from relay import Relay
from relay.adapters import wrap_openai


def adapter_example() -> None:
    with Relay("01JE6N2K8H5F0WZ8N1X3R7T0AB") as client:
        with client.run(
            agent={"name": "support-triage", "version": "0.1.0"},
            actor_identity_hash="sha256:" + "0" * 64,
            manifest_commit_hash="abc1234",
            redaction_policy_version="example.v1",
        ) as run:
            # The user's real openai.OpenAI() would go here; for the doc
            # snippet we show the wrap call shape.
            # wrapped = wrap_openai(openai.OpenAI())
            # response = wrapped.chat.completions.create(
            #     model="gpt-4o-mini",
            #     messages=[{"role": "user", "content": "hi"}],
            # )
            # spans = wrapped.recorder.spans
            run.capture(client_lifecycle_status="in_progress")
```

Spec: §A.5
