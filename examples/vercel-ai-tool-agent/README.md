# Relay example: Vercel AI tool-agent

Single-language Relay example that exercises the
[Vercel AI SDK](https://sdk.vercel.ai) (`ai` package) `generateText`
surface with a deterministic tool call. The example is TypeScript-only
(per `VAL-W16-009`): the Vercel AI SDK is TS-native and has no Python
equivalent, so the canonical W16 example layout for this adapter ships
only the `typescript/` subdirectory.

The example demonstrates the canonical Relay lifecycle through the W4
Relay TypeScript SDK and the W4.5 Vercel AI adapter
(`wrapVercelAi` / `wrapGenerateText`):

1. Open a Relay run with the three-anchor handoff
   (`actor_identity_hash`, `manifest_commit_hash`, `redaction_policy_version`).
2. Call the Vercel AI SDK's `generateText` through the wrapped adapter;
   the adapter records `model_call` and `tool_call` spans into the
   run's trace, with explicit `parent_span_id` linkage so the
   OpenTelemetry parent/child graph is preserved (`VAL-W16-011`).
3. Dispatch the tool call deterministically (a stub `get_current_weather`).
4. Feed the result back to the model for a final response.
5. The local sidecar's control plane writes the canonical `run_results`
   row (the SDK never writes a canonical row -- CLAUDE.md keystone
   invariant #1).

## Adapter status

The Vercel AI SDK adapter (`packages/sdk-typescript/src/adapters/vercel_ai.ts`)
ships as part of the W4 / W4.5 TypeScript SDK. The adapter wraps
`generateText`, `streamText`, and `generateObject` and emits one
`model_call` span per logical call with provider `vercel-ai`, plus
one aggregated `tool_call` span per invoked tool (`VAL-W4-039`). The
supported Vercel AI SDK major range is `>=4 <6` (eng plan A6 weekly
packaging matrix; `assertVercelAiVersionSupported` rejects versions
outside that band).

## Installation

Prerequisites:

- Node 22+ (matrix: 22, 24, 26)
- `npm` for the TypeScript side
- `uv` for the `rly` CLI

From the repo root:

```sh
# Install the Node workspace (which installs the @epochly/relay SDK
# this example links against via "workspace:*")
npm ci --workspaces --include-workspace-root

# Install the Python workspace for the rly CLI used by the manifest
uv sync --all-packages
```

The example itself is not a workspace member; it ships its own
`package.json` so contributors can copy it into a fresh project as a
starting point.

## Running live mode

Live mode hits the real OpenAI API through the Vercel AI SDK. Requires
an `OPENAI_API_KEY` in the environment. Live runs produce a canonical
`run_results` row in the local sidecar (per `VAL-W16-010`).

```sh
export OPENAI_API_KEY=sk-...
uv run rly run --manifest examples/vercel-ai-tool-agent/relay.manifest.yaml --language typescript --mode live
```

This command dispatches through the manifest-declared command surface
per `VAL-W16-018`. Direct `node examples/...` or `tsx examples/...`
invocations are not the supported CI path.

## Recording a cassette

A cassette is a deterministic record of a session's model and tool
fixtures. The Relay replay proxy records cassettes by spawning a
per-session localhost mitmproxy that captures provider traffic and
writes one `ReplayFixture` per request/response under
`examples/vercel-ai-tool-agent/typescript/cassettes/`.

```sh
export OPENAI_API_KEY=sk-...
uv run rly replay record --manifest examples/vercel-ai-tool-agent/relay.manifest.yaml --language typescript
```

The command writes `typescript/cassettes/vercel-ai-tool-agent.jsonl`.
Each line is a JSON-encoded `ReplayFixture v1` record per spec section
E.2. To regenerate a stale cassette after an upstream change (model
rotation, adapter update, Vercel AI SDK response shape drift), re-run
`rly replay record` and commit the updated JSONL.

## Replaying from cassette

Cassette replay is the default and offline; no provider key required.

```sh
uv run rly replay run --manifest examples/vercel-ai-tool-agent/relay.manifest.yaml --language typescript --cassette typescript/cassettes/vercel-ai-tool-agent.jsonl
```

Replay runs inside the sandbox with default-deny network egress.
Provider traffic is served from the cassette; any egress attempt
against `api.openai.com` fails the run and surfaces in the trace as
a sandbox violation (`VAL-W16-012`).

## Expected output

A successful cassette replay prints:

```text
[cassette] replayed 3 fixtures: model_call -> tool_call -> model_call
[cassette] tool_call: get_current_weather (read_only) parent_span_id=01931f4c-0003-7000-8000-00000000c003 args_hash=sha256-5e6f70819203... result_hash=sha256-6f70819203040...
[cassette] trace continuity OK: model_call -> tool_call parent/child verified
[cassette] OK - cassette replay completed with zero network egress
```

The recorded trace contains exactly one `model_call` -> `tool_call` ->
`model_call` chain. The `tool_call` fixture carries `parent_span_id`
pointing at the originating `model_call`'s `source_span_id` so the
OpenTelemetry parent/child graph is reproducible offline (`VAL-W16-011`
trace continuity). The tool's `side_effect_class` is `read_only`
(per the manifest's `tools[].side_effect_class` declaration); replay
serves the fixture directly without any audited policy override.

## Tool side-effect classes

Every tool the example registers declares its `side_effect_class` in
the manifest (`VAL-W16-005`):

| Tool | side_effect_class | Notes |
| --- | --- | --- |
| `get_current_weather` | `read_only` | Stub forecast; deterministic, no I/O |

A tool with `side_effect_class: mutating` could not be replayed without
an audited override; the replay engine would surface `RELAY-REPLAY-014`
and mark the run blocked.

## OpenTelemetry trace continuity

Per spec "Evidenced pain-to-product traceability" (line 23) the Vercel
AI SDK has historically lost trace continuity due to OpenTelemetry
version pinning drift. The Relay W4.5 Vercel AI adapter addresses this
by:

1. Emitting one `model_call` span per logical `generateText` /
   `streamText` / `generateObject` call (`VAL-W4-039`).
2. Aggregating tool invocations into one `tool_call` span per call,
   each carrying `parent_span_id` referencing the originating
   `model_call`.
3. Recording the same parent/child linkage into cassette fixtures so
   the trace graph is byte-stable across replay and live runs.

The example's cassette explicitly records `parent_span_id` on the
`tool_call` fixture; the `runCassetteMode` entry point validates the
graph at load time and refuses to play back a cassette with orphan
spans (`VAL-W16-011`).

## Manifest commit hash binding

The example computes the SHA-256 of `relay.manifest.yaml` at run time
and passes it as the third anchor in the Relay handoff (per
`VAL-W16-022`, spec section C.5). A run whose `manifest_commit_hash`
does not match the on-disk manifest produces `RELAY-GATE-021` and is
rejected by the sidecar's three-anchor verifier.

## Files

```text
examples/vercel-ai-tool-agent/
- README.md                       # this file
- relay.manifest.yaml             # commands, tools, ports, test entries
- package.json                    # TypeScript example package definition
- typescript/
  - README.md                     # TypeScript-specific run notes
  - main.ts                       # TypeScript entry point (runLiveMode / runCassetteMode)
  - cassettes/
    - vercel-ai-tool-agent.jsonl  # ReplayFixture v1 records
```

## See also

- `planning/epochly-replay-spec.md` sections A.1 (RunResult), B.1 (span
  schema), C.5 (three-anchor handoff), E.1-E.4 (replay), F (manifest),
  S (adapter P0/P1 placement), X (side-effect classes).
- `docs/architecture/` for high-level Relay architecture diagrams.
- `examples/openai-tool-agent/`, `examples/langchain-rag-agent/`,
  `examples/mcp-tool-agent/` for the other W16 examples.
