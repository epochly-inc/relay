# Relay example: MCP tool-agent

Relay example exercising the Model Context Protocol (MCP) client
surface. The example opens an MCP `ClientSession` to a pinned MCP
server (live mode) or replays the recorded MCP-protocol envelope from a
cassette (cassette mode). Ships in Python only (per the W16.4 feature
definition the v0.1 deliverable is the Python MCP client example;
there is no TypeScript subdirectory).

The example demonstrates the canonical Relay MCP lifecycle:

1. Open a Relay run with the three-anchor handoff
   (`actor_identity_hash`, `manifest_commit_hash`,
   `redaction_policy_version`).
2. Connect an MCP client to the pinned MCP server (`relay-example-mcp-server`)
   over stdio (live mode) or replay the recorded MCP-protocol envelope
   from the cassette (cassette mode).
3. Dispatch a single MCP tool call (`relay_example.echo`); the Relay
   SDK records a `tool_call` span whose `tool_name` follows the MCP
   `server.tool` form, with redacted args, `args_hash`, `result_hash`,
   `status`, and `duration_ms` populated per spec section B.1
   tool-call flight recorder.
4. The local sidecar's control plane writes the canonical
   `run_results` row (the SDK never writes a canonical row -- CLAUDE.md
   keystone invariant #1).

## Adapter status

The full MCP client adapter is shipped as part of the W3.5 Python
adapter set. This example uses a small **manual instrumentation**
helper (`build_mcp_tool_call_span`) to surface the tool_call span's
field shape offline so the cassette replay is testable without
spawning the MCP server. Live mode exercises the real
`mcp.ClientSession` surface end-to-end.

The pinned MCP server for this example is `relay-example-mcp-server`
(vendored at a documented SHA in the example's pyproject.toml). The
server exposes a single read-only `relay_example.echo` tool that
returns the supplied payload back to the caller.

## Installation

Prerequisites:

- Python 3.12+ (matrix: 3.12, 3.13, 3.14)
- `uv` for Python workspace management
- A pinned MCP server binary on PATH (live mode only). The reference
  binary used in CI is `relay-example-mcp-server`; alternative servers
  can be substituted via the `MCP_SERVER_COMMAND` environment variable.

From the repo root:

```sh
# Install the Python workspace including the Relay SDK
uv sync --all-packages
```

The example itself is not a workspace member; it ships its own
`pyproject.toml` so contributors can copy it into a fresh project as a
starting point.

## Running live mode

Live mode hits a real MCP server. Requires `MCP_SERVER_COMMAND` to be
set in the environment to the command used to spawn the server. Live
runs produce a canonical `run_results` row in the local sidecar.

```sh
export MCP_SERVER_COMMAND="relay-example-mcp-server"
uv run rly run --manifest examples/mcp-tool-agent/relay.manifest.yaml --language python --mode live
```

The command dispatches through the manifest-declared command surface
per VAL-W16-018. Direct `python examples/...` invocations are not the
supported path.

## Recording a cassette

A cassette is a deterministic record of the session's LLM and MCP
server fixtures. The Relay replay proxy records cassettes by capturing
the MCP-protocol JSON-RPC envelope and writing one `ReplayFixture` per
request/response under `examples/mcp-tool-agent/python/cassettes/`.

```sh
export MCP_SERVER_COMMAND="relay-example-mcp-server"
uv run rly replay record --manifest examples/mcp-tool-agent/relay.manifest.yaml --language python
```

The command writes `python/cassettes/mcp-tool-agent.jsonl`. Each line
is a JSON-encoded `ReplayFixture v1` record per spec section E.2. The
cassette MUST contain at least one `kind: model_call` fixture and at
least one `kind: tool_call` fixture (per VAL-W16-014: both the LLM
responses AND the MCP server responses are captured).

To regenerate a stale cassette after an upstream change (MCP server
version bump, tool schema drift, model rotation), re-run
`rly replay record` and commit the updated JSONL.

## Replaying from cassette

Cassette replay is the default and offline; no provider key required
and no MCP server child process is spawned during replay.

```sh
uv run rly replay run --manifest examples/mcp-tool-agent/relay.manifest.yaml --language python --cassette python/cassettes/mcp-tool-agent.jsonl
```

Replay runs inside the sandbox with default-deny network egress.
Per VAL-W16-014 cassette replay runs with **zero network egress** and
does NOT spawn an MCP server child process; the MCP-protocol envelope
is served directly from the recorded fixtures. An egress attempt or a
subprocess spawn during replay fails the run and surfaces in the
trace as a sandbox violation.

## Expected output

A successful cassette replay prints:

```text
[cassette] mcp tool_call: relay_example.echo (read_only) status=ok duration_ms=2
[cassette] mcp args_hash=sha256-... result_hash=sha256-...
[cassette] replayed 3 fixtures: model_call -> tool_call -> model_call
[cassette] OK - cassette replay completed with zero network egress and no MCP server spawn
```

The recorded trace contains exactly one `model_call` -> `tool_call`
-> `model_call` chain. The `tool_call` fixture carries `tool_name` in
MCP `server.tool` form (`relay_example.echo`), provider in MCP form
(`mcp:relay-example-mcp-server`), `args_hash`, `result_hash`,
`status`, `duration_ms`, and `side_effect_marker: false` per spec
section B.1.

## Tool side-effect classes

Every tool the example registers declares its `side_effect_class` in
the manifest (per VAL-W16-005):

| Tool | side_effect_class | Notes |
| --- | --- | --- |
| `relay_example.echo` | `read_only` | Deterministic echo over the MCP transport; no I/O |

A tool with `side_effect_class: mutating` could not be replayed without
an audited override; the replay engine would surface
`RELAY-REPLAY-014` and mark the run blocked.

## Manifest commit hash binding

The example computes the SHA-256 of `relay.manifest.yaml` at run time
and passes it as the third anchor in the Relay handoff (per
VAL-W16-022, spec section C.5). A run whose `manifest_commit_hash`
does not match the on-disk manifest produces `RELAY-GATE-021` and is
rejected by the sidecar's three-anchor verifier.

## Files

```text
examples/mcp-tool-agent/
|-- README.md                       # this file
|-- relay.manifest.yaml             # commands, tools, ports, test entries
|-- pyproject.toml                  # Python example package definition
|-- .gitignore
`-- python/
    |-- README.md                   # Python-specific run notes
    |-- main.py                     # entry point (run_live_mode / run_cassette_mode / build_mcp_tool_call_span)
    `-- cassettes/
        `-- mcp-tool-agent.jsonl    # ReplayFixture v1 records (model_call + tool_call + model_call)
```

## See also

- `planning/epochly-replay-spec.md` sections A.1 (RunResult), B.1
  (span schema + tool-call flight recorder), C.5 (three-anchor
  handoff), E.1-E.4 (replay), F (manifest), S (adapter P0/P1 placement
  including MCP), X (side-effect classes).
- `examples/openai-tool-agent/` for the W16.1 OpenAI tool-agent example
  (cross-language Python + TypeScript parity exercise).
- `examples/langchain-rag-agent/`, `examples/vercel-ai-tool-agent/`
  for the other W16 examples.
