# OpenAI adapter

> Generated from packages/sdk-python/relay/adapters/ and packages/sdk-typescript/src/adapters/. Do not edit by hand.

The OpenAI adapter wraps an OpenAI client so every model call and
embedded tool call emits a Relay `Span` on a `SpanRecorder`. The Python
wrapper covers the `chat.completions.create(...)` surface; the
TypeScript wrapper covers both `chat.completions.create(...)` and
`responses.create(...)`. Both are duck-typed: they never import the
`openai` package at module load, so installing the Apache-2.0 Relay
SDK does not pull the commercial OpenAI SDK as a transitive
dependency.

Per CLAUDE.md keystone invariant #1 the adapter NEVER writes canonical
results. Spans accumulate in a `SpanRecorder` and the lifecycle ingest
surface ships them to the sidecar, which is the only writer of
`run_results`.

## Setup

### Python

The Python adapter lives at `packages/sdk-python/relay/adapters/openai_adapter.py`
and is exported via `relay.adapters.wrap_openai`.

```python
from relay.adapters import SpanRecorder, wrap_openai

# In production: client = wrap_openai(openai.OpenAI())
# The adapter is duck-typed; tests pass any stand-in exposing
# .chat.completions.create(**kwargs).
recorder = SpanRecorder()
assert callable(wrap_openai)
```

### TypeScript

The TypeScript adapter lives at `packages/sdk-typescript/src/adapters/openai.ts`.

```ts
import OpenAI from "openai";
import { wrapOpenAi } from "@epochly/relay/adapters";

const client = wrapOpenAi(new OpenAI());
const response = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "ping" }],
});
const spans = client.recorder.spans;
```

The TypeScript adapter exports `OPENAI_SUPPORTED_MAJOR_RANGE` (`">=5 <7"`)
and `assertOpenAiVersionSupported` so callers can refuse unsupported
provider SDK majors at construction time (VAL-W4-040). The Python
adapter does not enforce a major-range check; it falls back to the
sentinel `openai@unknown` when the package is not importable.

## API surface

### Python

```python
def wrap_openai(
    client: Any,
    *,
    recorder: SpanRecorder | None = None,
    sdk_version: str | None = None,
) -> _WrappedOpenAIClient: ...
```

- `client` -- any object exposing `.chat.completions.create(**kwargs)`.
  In production this is an `openai.OpenAI` instance; tests pass a
  duck-typed stand-in.
- `recorder` -- optional `SpanRecorder`. When omitted a fresh recorder
  is created and made available as `wrapper.recorder`.
- `sdk_version` -- override the auto-detected `openai@<version>` string
  the spans carry.

The returned wrapper forwards any other attribute to the underlying
client via `__getattr__`, so library code that reaches for
`client.api_key` or `client.with_options(...)` continues to work.

### TypeScript

```ts
export function wrapOpenAi(
  client: OpenAiClientLike,
  options?: WrapOpenAiOptions,
): WrappedOpenAiClient;
```

`WrappedOpenAiClient` exposes `recorder`, `chat.completions.create(args)`,
`responses.create(args)`, and `inner` (the wrapped underlying client).
`WrapOpenAiOptions` is `{ recorder?: SpanRecorder; sdkVersion?: string }`.

## Side-effect classification

The adapter never classifies tool calls itself. For every `tool_calls`
entry on a non-stream response and for every aggregated streamed
tool-call (TypeScript only, per VAL-W4-039), the wrapper emits a
`tool_call` span with `side_effect_marker: false` and `status: "pending"`.
The classification of the tool as `read_only`, `mutating`, or
`external_irreversible` lives in the example's manifest under the
`tools[].side_effect_class` field (per spec section E.3, VAL-W16-005).
Tools declared `side_effect: true` must additionally be wrapped with
`register_tool` from `relay.adapters` so the function emits the
`tool.pre_action` and `tool.post_success_proof` markers required by
keystone invariant #6.

Embedded tool arguments are scrubbed at the adapter boundary by
`_scrub` (Python) and `scrubSecretShape` (TypeScript): keys named
`api_key`, `apikey`, `secret`, `token`, `password`, `passphrase`,
`ssn`, or `credit_card` are masked, and string values prefixed with
`sk-` or `sk-ant-` are masked. The `args_hash` recorded on the span is
the SHA-256 of the canonical JSON of the redacted arguments, so a
captured cassette never round-trips a raw secret.

## Replay notes

The Python adapter emits one `stream_chunk` span per chunk during a
streaming call. The TypeScript adapter aggregates the entire stream
into a single `model_call` span (per VAL-W4-039) and emits one
`tool_call` span per aggregated invocation. Both shapes are
deterministic for a given input stream.

The span's `model_signature` is `openai:<model>:<system_fingerprint>`
when the provider returns a `system_fingerprint`, else a deterministic
SHA-256 prefix of the model name so the refresh policy can still
detect drift (VAL-W3-039). The fingerprint is what binds a cassette
to a specific provider model build; rotating fingerprints invalidates
the cassette and requires `rly replay record` to capture a fresh one.

Replay is cassette-first by default. The OpenAI adapter has no live
provider dependency during cassette replay because the underlying
client is never invoked -- the replay proxy serves the recorded
response shape directly.

## Brief example

The end-to-end runnable example lives at `examples/openai-tool-agent/`
and exercises both the Python and TypeScript wrappers against a
single deterministic tool (`get_current_weather`). The example's
manifest declares the tool's `side_effect_class: read_only` so
cassette replay runs offline with zero network egress and no audited
override.

```text
examples/openai-tool-agent/
|-- python/
|-- typescript/
`-- relay.manifest.yaml
```

Spec: §A.5, §E
