# Vercel AI SDK adapter

> Generated from packages/sdk-typescript/src/adapters/vercel_ai.ts. Do not edit by hand.

The Vercel AI SDK (`ai` package, https://sdk.vercel.ai) is TypeScript-
native and has no Python equivalent. The Relay Vercel AI adapter is
therefore a TypeScript-only P0 surface; there is no Python
counterpart in `packages/sdk-python/relay/adapters/`.

The adapter wraps the three primary Vercel AI generation surfaces --
`generateText`, `streamText`, and `generateObject` -- so each
invocation emits a single `model_call` `Span` with
`provider: 'vercel-ai'`, the mapped underlying model identifier, and
aggregated tool-call spans. Per CLAUDE.md keystone invariant #1 the
adapter NEVER writes canonical results; the lifecycle ingest surface
ships spans to the sidecar, which is the only writer of
`run_results`.

The adapter is duck-typed: it never imports the `ai` package at module
load. Callers either pass a function bag to `wrapVercelAi` (the
recommended seam) or call the per-function wrappers
`wrapGenerateText`, `wrapStreamText`, and `wrapGenerateObject` on
individual exports they have already imported themselves.

## Setup

The TypeScript adapter lives at
`packages/sdk-typescript/src/adapters/vercel_ai.ts`. Python is not
supported.

```ts
import * as ai from "ai";
import { openai } from "@ai-sdk/openai";
import { wrapVercelAi } from "@epochly/relay/adapters";

const wrapped = wrapVercelAi(ai, { sdkVersion: "ai@4.0.0" });

const result = await wrapped.generateText!({
  model: openai("gpt-4o-mini"),
  prompt: "ping",
});
const spans = wrapped.recorder.spans;
```

The adapter exports `VERCEL_AI_SUPPORTED_MAJOR_RANGE` (`">=4 <6"`)
and `assertVercelAiVersionSupported` so callers can refuse
unsupported SDK majors at construction time (VAL-W4-040). Wrapped
functions that the surface does not expose are omitted from the
returned object, which keeps the type narrow when callers pass a
partial function bag.

## API surface

```ts
export function wrapVercelAi(
  surface: VercelAiSurface,
  options?: WrapVercelAiOptions,
): WrappedVercelAiSurface;
```

- `surface` -- an object exposing any subset of `generateText`,
  `streamText`, `generateObject`. In production callers pass
  `import * as ai from "ai"` (or destructured named imports).
- `options.recorder` -- optional `SpanRecorder`.
- `options.sdkVersion` -- override the SDK version string the spans
  carry. The default is `ai@unknown`.

`WrappedVercelAiSurface` exposes `recorder` plus the same function
names as the input surface with span recording enabled.

Per-function wrappers are also exported:

```ts
export function wrapGenerateText(
  inner: GenerateTextFn,
  recorder: SpanRecorder,
  sdkVersion: string,
): GenerateTextFn;

export function wrapStreamText(
  inner: StreamTextFn,
  recorder: SpanRecorder,
  sdkVersion: string,
): StreamTextFn;

export function wrapGenerateObject(
  inner: GenerateObjectFn,
  recorder: SpanRecorder,
  sdkVersion: string,
): GenerateObjectFn;
```

These are useful when the caller imports the Vercel AI surfaces
individually and wants to wrap exactly one of them.

## Side-effect classification

The adapter never classifies tool calls itself. For every entry in
the result's `toolCalls` array (non-stream) and for every
`tool-call` / `tool_call` part observed in the `streamText`
`fullStream` (aggregated by `toolCallId` per VAL-W4-039), the wrapper
emits a `tool_call` span with `side_effect_marker: false` and
`status: "pending"`. The classification of the tool as `read_only`,
`mutating`, or `external_irreversible` lives in the example's
manifest under `tools[].side_effect_class` per spec section E.3 and
VAL-W16-005.

Tool arguments are scrubbed at the adapter boundary by
`scrubSecretShape` (imported from `./openai.js`): keys named
`api_key`, `apikey`, `secret`, `token`, `password`, `passphrase`,
`ssn`, or `credit_card` are masked, and string values prefixed with
`sk-` or `sk-ant-` are masked. The `args_hash` on the span is the
SHA-256 of the canonical JSON of the redacted arguments.

## Replay notes

`streamText` exposes a `fullStream` async iterable. The wrapper
returns a `Proxy` over the result that replaces `fullStream` with a
wrapping async iterable; per-part events are aggregated into one
`model_call` span and one `tool_call` span per aggregated invocation
(VAL-W4-039). Other result surfaces (`textStream`, `text`, `usage`,
...) are passed through unchanged.

Vercel AI SDK v4 emits `usage` as `{ promptTokens, completionTokens }`;
v5 emits `{ inputTokens, outputTokens }`. The adapter accepts both
shapes and normalizes to `input_tokens` / `output_tokens` on the
span. The `model_signature` is `vercel-ai:<model>:<response.id>` when
`response.id` is present, else a SHA-256 prefix of the model name.

Replay is cassette-first by default. The Vercel AI adapter has no
live provider dependency during cassette replay because the wrapped
inner function is never invoked -- the replay proxy serves the
recorded result shape directly.

## Brief example

The end-to-end runnable example lives at
`examples/vercel-ai-tool-agent/` and exercises the `generateText`
integration pattern with the OpenAI provider via `@ai-sdk/openai`.
The example's manifest declares the tool's `side_effect_class:
read_only` so cassette replay runs offline with zero network egress
and no audited override.

```text
examples/vercel-ai-tool-agent/
|-- typescript/
`-- relay.manifest.yaml
```

Spec: §A.5, §E
