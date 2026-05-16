# OpenAI tool-agent example - TypeScript

TypeScript entry point for the cross-language Relay OpenAI tool-agent
example. Implements the canonical Relay lifecycle through the W4 Relay
TypeScript SDK and the W4.5 OpenAI adapter.

See `../README.md` for the cross-language overview, manifest contract,
and spec cross-references.

## Installation

```sh
# From the repo root
npm ci --workspaces --include-workspace-root
```

The example references the workspace Relay TypeScript SDK
(`@epochly/relay`) plus the upstream `openai` package. Local
development uses `tsx` (already declared as a devDependency) so the
TypeScript source runs without an explicit build step.

## Running live mode

Requires `OPENAI_API_KEY` in the environment. The smoke harness uses
the manifest-declared command surface:

```sh
export OPENAI_API_KEY=sk-...
uv run rly run --manifest examples/openai-tool-agent/relay.manifest.yaml --language typescript --mode live
```

Local iteration:

```sh
npx tsx examples/openai-tool-agent/typescript/main.ts --live
```

Direct `tsx ...` invocation is for local development only; CI and the
smoke harness MUST go through `rly run` (`VAL-W16-018`).

## Recording a cassette

Records to `typescript/cassettes/openai-tool-agent.jsonl`:

```sh
export OPENAI_API_KEY=sk-...
uv run rly replay record --manifest examples/openai-tool-agent/relay.manifest.yaml --language typescript
```

The TypeScript path uses an `undici` interceptor plus an
`HTTPS_PROXY` environment variable to route OpenAI traffic through
the replay proxy (per spec section A4, layer 3 - Node fetch
interception).

## Replaying from cassette

```sh
uv run rly replay run --manifest examples/openai-tool-agent/relay.manifest.yaml --language typescript --cassette typescript/cassettes/openai-tool-agent.jsonl
```

Local iteration:

```sh
npx tsx examples/openai-tool-agent/typescript/main.ts --cassette
```

The replay sandbox enforces default-deny network egress; any outbound
attempt against `api.openai.com` during replay surfaces a sandbox
violation and fails the run (`VAL-W16-004`).

## Expected output

```text
[cassette] replayed 3 fixtures: model_call -> tool_call -> model_call
[cassette] tool_call: get_current_weather (read_only) -> forecast=clear temperature=13
[cassette] OK - cassette replay completed with zero network egress
```

## Module API

The TypeScript entry point exposes:

- `runLiveMode(): Promise<number>` - live run against OpenAI.
- `runCassetteMode(): Promise<number>` - deterministic cassette replay.
- `computeManifestCommitHash(): string` - SHA-256 over
  `relay.manifest.yaml`.
- `actorIdentityHashForExample(): string` - derived identity hash for
  the three-anchor handoff.
- `main(argv?: string[]): Promise<number>` - CLI dispatch.

All exports are importable from `examples/openai-tool-agent/typescript/main.ts`
via standard ESM `import { ... } from "..."` syntax.

## Platform support

The TypeScript entry point runs on macOS, Linux, and Windows (per
`VAL-W16-021`). All path handling uses `node:path` so platform
separators are normalised. ES Module imports use `node:` builtin
prefixes for `crypto`, `fs`, `path`, and `url`.
