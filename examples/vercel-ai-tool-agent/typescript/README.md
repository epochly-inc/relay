# Vercel AI tool-agent example - TypeScript

TypeScript entry point for the Vercel AI SDK tool-agent example.
Implements the canonical Relay lifecycle through the W4 Relay
TypeScript SDK and the W4.5 Vercel AI adapter (`wrapVercelAi`,
`wrapGenerateText`).

See `../README.md` for the cross-cutting overview, manifest contract,
adapter status, and OpenTelemetry trace continuity rationale.

## Installation

```sh
# From the repo root
npm ci --workspaces --include-workspace-root
```

The example references the workspace Relay TypeScript SDK
(`@epochly/relay`) plus the upstream `ai` package and the
`@ai-sdk/openai` provider for live mode. Local development uses `tsx`
(already declared as a devDependency) so the TypeScript source runs
without an explicit build step.

## Running live mode

Requires `OPENAI_API_KEY` in the environment. The smoke harness uses
the manifest-declared command surface:

```sh
export OPENAI_API_KEY=sk-...
uv run rly run --manifest examples/vercel-ai-tool-agent/relay.manifest.yaml --language typescript --mode live
```

Local iteration:

```sh
npx tsx examples/vercel-ai-tool-agent/typescript/main.ts --live
```

Direct `tsx ...` invocation is for local development only; CI and the
smoke harness MUST go through `rly run` (`VAL-W16-018`).

## Recording a cassette

Records to `typescript/cassettes/vercel-ai-tool-agent.jsonl`:

```sh
export OPENAI_API_KEY=sk-...
uv run rly replay record --manifest examples/vercel-ai-tool-agent/relay.manifest.yaml --language typescript
```

The TypeScript path uses an `undici` interceptor plus an
`HTTPS_PROXY` environment variable to route OpenAI traffic through
the replay proxy (per spec section A4, layer 3 - Node fetch
interception). The Vercel AI SDK delegates HTTP to the provider
package (`@ai-sdk/openai`), which uses the same global fetch surface
that the interceptor catches.

## Replaying from cassette

```sh
uv run rly replay run --manifest examples/vercel-ai-tool-agent/relay.manifest.yaml --language typescript --cassette typescript/cassettes/vercel-ai-tool-agent.jsonl
```

Local iteration:

```sh
npx tsx examples/vercel-ai-tool-agent/typescript/main.ts --cassette
```

The replay sandbox enforces default-deny network egress; any outbound
attempt against `api.openai.com` during replay surfaces a sandbox
violation and fails the run (`VAL-W16-012`).

## Expected output

```text
[cassette] replayed 3 fixtures: model_call -> tool_call -> model_call
[cassette] tool_call: get_current_weather (read_only) parent_span_id=01931f4c-0003-7000-8000-00000000c003 args_hash=sha256-5e6f70819203... result_hash=sha256-6f70819203040...
[cassette] trace continuity OK: model_call -> tool_call parent/child verified
[cassette] OK - cassette replay completed with zero network egress
```

## Module API

The TypeScript entry point exposes:

- `runLiveMode(): Promise<number>` - live run against the Vercel AI
  SDK (default provider: OpenAI).
- `runCassetteMode(): Promise<number>` - deterministic cassette replay
  with trace-continuity validation.
- `computeManifestCommitHash(): string` - SHA-256 over
  `relay.manifest.yaml`.
- `actorIdentityHashForExample(): string` - derived identity hash for
  the three-anchor handoff.
- `main(argv?: string[]): Promise<number>` - CLI dispatch.

All exports are importable from
`examples/vercel-ai-tool-agent/typescript/main.ts` via standard ESM
`import { ... } from "..."` syntax.

## Platform support

The TypeScript entry point runs on macOS, Linux, and Windows (per
`VAL-W16-021`). All path handling uses `node:path` so platform
separators are normalised. ES Module imports use `node:` builtin
prefixes for `crypto`, `fs`, `path`, and `url`.

## OpenTelemetry trace continuity (VAL-W16-011)

The cassette records `parent_span_id` on every `tool_call` fixture,
binding it to the originating `model_call`'s `source_span_id`. The
cassette loader (`validateTraceContinuity` in `main.ts`) refuses to
play back a cassette with orphan or missing parent links. This
addresses the historical Vercel AI SDK trace-loss pain noted in
spec "Evidenced pain-to-product traceability" (line 23).
