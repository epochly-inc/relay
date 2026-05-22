# Anthropic adapter

> Generated from packages/sdk-python/relay/adapters/ and packages/sdk-typescript/src/adapters/. Do not edit by hand.

The Anthropic adapter wraps an Anthropic client so every
`messages.create(...)` invocation emits a Relay `Span` on a
`SpanRecorder`. Both the Python and TypeScript wrappers are
duck-typed: they never import the provider package at module load, so
installing the Apache-2.0 Relay SDK does not pull
`anthropic` / `@anthropic-ai/sdk` as a transitive dependency.

Per CLAUDE.md keystone invariant #1 the adapter NEVER writes canonical
results. Spans accumulate in a `SpanRecorder` and the lifecycle ingest
surface ships them to the sidecar, which is the only writer of
`run_results`.

## Setup

### Python

The Python adapter lives at `packages/sdk-python/relay/adapters/anthropic_adapter.py`
and is exported via `relay.adapters.wrap_anthropic`.

```python
from relay.adapters import SpanRecorder, wrap_anthropic

# In production: client = wrap_anthropic(anthropic.Anthropic())
# The adapter is duck-typed; tests pass any stand-in exposing
# .messages.create(**kwargs).
recorder = SpanRecorder()
assert callable(wrap_anthropic)
```

### TypeScript

The TypeScript adapter lives at `packages/sdk-typescript/src/adapters/anthropic.ts`.

```ts
import Anthropic from "@anthropic-ai/sdk";
import { wrapAnthropic } from "@epochly/relay/adapters";

const client = wrapAnthropic(new Anthropic());
const response = await client.messages.create({
  model: "claude-3-5-sonnet",
  max_tokens: 64,
  messages: [{ role: "user", content: "ping" }],
});
const spans = client.recorder.spans;
```

The TypeScript adapter exports `ANTHROPIC_SUPPORTED_MAJOR_RANGE`
(`">=0 <2"`) and `assertAnthropicVersionSupported` so callers can
refuse unsupported provider SDK majors at construction time
(VAL-W4-040). The Python adapter has no major-range check; it falls
back to the sentinel `anthropic@unknown` when the package is not
importable.

## API surface

### Python

```python
def wrap_anthropic(
    client: Any,
    *,
    recorder: SpanRecorder | None = None,
    sdk_version: str | None = None,
) -> _WrappedAnthropicClient: ...
```

- `client` -- any object exposing `.messages.create(**kwargs)`. In
  production this is an `anthropic.Anthropic` instance; tests pass a
  duck-typed stand-in.
- `recorder` -- optional `SpanRecorder`. When omitted a fresh recorder
  is created and made available as `wrapper.recorder`.
- `sdk_version` -- override the auto-detected `anthropic@<version>`
  string the spans carry.

The wrapper forwards unknown attribute lookups to the underlying
client via `__getattr__`.

### TypeScript

```ts
export function wrapAnthropic(
  client: AnthropicClientLike,
  options?: WrapAnthropicOptions,
): WrappedAnthropicClient;
```

`WrappedAnthropicClient` exposes `recorder`, `messages.create(args)`,
and `inner`. `WrapAnthropicOptions` is `{ recorder?: SpanRecorder;
sdkVersion?: string }`.

## Side-effect classification

The adapter never classifies tool calls itself. For every
`tool_use` content block on a non-stream response the wrapper emits a
`tool_call` span with `side_effect_marker: false` and
`status: "pending"`. The classification of the tool as `read_only`,
`mutating`, or `external_irreversible` lives in the example's manifest
under the `tools[].side_effect_class` field (per spec section E.3,
VAL-W16-005). Tools declared `side_effect: true` must additionally be
wrapped with `register_tool` from `relay.adapters` so the function
emits the `tool.pre_action` and `tool.post_success_proof` markers
required by keystone invariant #6.

Embedded tool input is scrubbed at the adapter boundary by the same
`_scrub` helper the OpenAI adapter uses (Python imports it from
`relay.adapters.openai_adapter`; TypeScript imports
`scrubSecretShape` from `./openai.js`). The `args_hash` recorded on
the span is the SHA-256 of the canonical JSON of the redacted input
so a captured cassette never round-trips a raw secret.

## Replay notes

The Python adapter emits one `stream_chunk` span per Anthropic stream
event (`message_start`, `content_block_delta`, `message_delta`,
`message_stop`, ...). The TypeScript adapter aggregates the entire
stream into a single `model_call` span per VAL-W4-039 and emits one
`tool_call` span per aggregated `tool_use` invocation.

Anthropic does not currently expose a `system_fingerprint` analog.
The Python `model_signature` is `anthropic:<model>` (VAL-W3-043); the
TypeScript adapter substitutes `response.id` so the signature becomes
`anthropic:<model>:<response.id>` with a SHA-256 fallback when the id
is empty. The refresh policy detects drift by observing a change in
this string.

Replay is cassette-first by default. The Anthropic adapter has no
live provider dependency during cassette replay because the
underlying client is never invoked -- the replay proxy serves the
recorded response shape directly.

## Brief example

The Anthropic adapter is exercised end-to-end through the same
example manifest pattern used by the OpenAI tool-agent example.
Tools registered with the Anthropic tool-use surface declare their
`side_effect_class` in the manifest; replay refuses to execute
`mutating` or `external_irreversible` tools from a cassette without
an audited policy override (`RELAY-REPLAY-014`).

Spec: §A.5, §E
