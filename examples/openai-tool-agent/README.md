# Relay example: OpenAI tool-agent

Cross-language Relay example that exercises the OpenAI Chat Completions
API with a deterministic tool call. Ships in both Python and TypeScript
so the W3 / W4 SDK + W3.5 / W4.5 OpenAI adapter parity is verified at
the example surface.

The example demonstrates the canonical Relay lifecycle:

1. Open a Relay run with the three-anchor handoff
   (`actor_identity_hash`, `manifest_commit_hash`, `redaction_policy_version`).
2. Call OpenAI through the wrapped adapter; the adapter records
   `model_call` and `tool_call` spans into the run's trace.
3. Dispatch the tool call deterministically (a stub `get_current_weather`).
4. Feed the result back to the model for a final response.
5. The local sidecar's control plane writes the canonical `run_results`
   row (the SDK never writes a canonical row -- CLAUDE.md keystone
   invariant #1).

## Installation

Prerequisites:

- Python 3.12+ (matrix: 3.12, 3.13, 3.14)
- Node 22+ (matrix: 22, 24, 26)
- `uv` for Python workspace management
- `npm` for the TypeScript side

From the repo root:

```sh
# Install the Python workspace including the Relay SDK
uv sync --all-packages

# Install the Node workspace
npm ci --workspaces --include-workspace-root
```

The example itself is not a workspace member; it ships its own
`pyproject.toml` and `package.json` so contributors can copy it into a
fresh project as a starting point.

## Running live mode

Live mode hits the real OpenAI API. Requires an OPENAI_API_KEY in the
environment. Live runs produce a canonical `run_results` row in the
local sidecar (per `VAL-W16-001` for Python and `VAL-W16-002` for
TypeScript).

Python:

```sh
export OPENAI_API_KEY=sk-...
uv run rly run --manifest examples/openai-tool-agent/relay.manifest.yaml --language python --mode live
```

TypeScript:

```sh
export OPENAI_API_KEY=sk-...
uv run rly run --manifest examples/openai-tool-agent/relay.manifest.yaml --language typescript --mode live
```

Both commands dispatch through the manifest-declared command surface
per `VAL-W16-018`. Direct `python examples/...` or `node examples/...`
invocations are not the supported path.

## Recording a cassette

A cassette is a deterministic record of a session's model and tool
fixtures. The Relay replay proxy records cassettes by spawning a
per-session localhost mitmproxy that captures provider traffic and
writes one `ReplayFixture` per request/response under
`examples/openai-tool-agent/{python,typescript}/cassettes/`.

```sh
export OPENAI_API_KEY=sk-...
uv run rly replay record --manifest examples/openai-tool-agent/relay.manifest.yaml --language python
```

The command writes `python/cassettes/openai-tool-agent.jsonl` (or the
TypeScript equivalent). Each line is a JSON-encoded `ReplayFixture v1`
record per spec section E.2.

To regenerate a stale cassette after an upstream change (model rotation,
adapter update, OpenAI response shape drift), re-run `rly replay record`
and commit the updated JSONL.

## Replaying from cassette

Cassette replay is the default and offline; no provider key required.

Python:

```sh
uv run rly replay run --manifest examples/openai-tool-agent/relay.manifest.yaml --language python --cassette python/cassettes/openai-tool-agent.jsonl
```

TypeScript:

```sh
uv run rly replay run --manifest examples/openai-tool-agent/relay.manifest.yaml --language typescript --cassette typescript/cassettes/openai-tool-agent.jsonl
```

Replay runs inside the sandbox with default-deny network egress.
Provider traffic is served from the cassette; an egress attempt against
`api.openai.com` fails the run and surfaces in the trace as a sandbox
violation (`VAL-W16-004`).

## Expected output

A successful cassette replay prints:

```text
[cassette] replayed 3 fixtures: model_call -> tool_call -> model_call
[cassette] tool_call: get_current_weather (read_only) -> forecast=clear temperature=13
[cassette] OK - cassette replay completed with zero network egress
```

The recorded trace contains exactly one `model_call` -> `tool_call` ->
`model_call` chain. The tool's `side_effect_class` is `read_only` (per
the manifest's `tools[].side_effect_class` declaration); replay
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

## Manifest commit hash binding

The example computes the SHA-256 of `relay.manifest.yaml` at run time
and passes it as the third anchor in the Relay handoff (per
`VAL-W16-022`, spec section C.5). A run whose `manifest_commit_hash`
does not match the on-disk manifest produces `RELAY-GATE-021` and is
rejected by the sidecar's three-anchor verifier.

## Files

```text
examples/openai-tool-agent/
├── README.md                       # this file
├── relay.manifest.yaml             # commands, tools, ports, test entries
├── pyproject.toml                  # Python example package definition
├── package.json                    # TypeScript example package definition
├── python/
│   ├── README.md                   # Python-specific run notes
│   ├── main.py                     # Python entry point (run_live_mode / run_cassette_mode)
│   └── cassettes/
│       └── openai-tool-agent.jsonl # ReplayFixture v1 records
└── typescript/
    ├── README.md                   # TypeScript-specific run notes
    ├── main.ts                     # TypeScript entry point (runLiveMode / runCassetteMode)
    └── cassettes/
        └── openai-tool-agent.jsonl # ReplayFixture v1 records
```

## See also

- `planning/epochly-replay-spec.md` sections A.1 (RunResult), B.1 (span
  schema), C.5 (three-anchor handoff), E.1-E.4 (replay), F (manifest),
  S (adapter P0/P1 placement), X (side-effect classes).
- `docs/architecture/` for high-level Relay architecture diagrams.
- `examples/langchain-rag-agent/`, `examples/vercel-ai-tool-agent/`,
  `examples/mcp-tool-agent/` for the other W16 examples.
