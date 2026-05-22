# MCP adapter

> Generated from packages/sdk-python/relay/adapters/ and examples/mcp-tool-agent/. Do not edit by hand.

The Model Context Protocol (MCP) adapter surface covers MCP client
sessions that dispatch tool calls to a pinned MCP server. There is
no first-class `wrap_mcp(...)` wrapper in `relay.adapters` for v0.1
OSS; the canonical MCP integration pattern is exercised end-to-end by
the `examples/mcp-tool-agent/` example, which combines the
`mcp.ClientSession` live surface (or its cassette replay) with the
manual `build_mcp_tool_call_span` helper to surface the tool-call
span shape offline.

Per CLAUDE.md keystone invariant #1 the integration NEVER writes
canonical results. Spans accumulate in a `SpanRecorder` and the
sidecar's lifecycle ingest surface is the only writer of
`run_results`.

## Setup

The MCP example is Python-only for v0.1 (per the W16.4 feature
definition). There is no TypeScript subdirectory under
`examples/mcp-tool-agent/`.

Prerequisites:

- Python 3.12+
- `uv` for workspace management
- A pinned MCP server binary on `PATH` for live mode (the reference
  binary used in CI is `relay-example-mcp-server`); cassette mode
  requires no server.

Install:

```sh
uv sync --all-packages
```

## API surface

The example exposes the following Python entry points in
`examples/mcp-tool-agent/python/main.py`:

```python
def run_live_mode(*, project_key: str | None = None) -> int: ...
def run_cassette_mode(*, project_key: str | None = None) -> int: ...
def build_mcp_tool_call_span(message: str = ...) -> dict[str, Any]: ...
def dispatch_mcp_tool_call(
    tool_name: str, raw_arguments: str | None
) -> dict[str, Any]: ...
def compute_manifest_commit_hash() -> str: ...
def actor_identity_hash_for_example() -> str: ...
```

`build_mcp_tool_call_span` is the manual instrumentation helper that
produces a `tool_call` span dict matching spec section B.1: it
populates `tool_name` in MCP `server.tool` form
(`relay_example.echo`), `provider` in MCP form
(`mcp:relay-example-mcp-server`), `args_hash`, `result_hash`,
`status`, `duration_ms`, and `side_effect_marker: false`. The helper
exists so cassette replay is testable without spawning the MCP
server.

Tools that perform real side effects must still be wrapped with
`register_tool` from `relay.adapters` so the function emits the
`tool.pre_action` and `tool.post_success_proof` markers required by
keystone invariant #6.

## Side-effect classification

MCP tools declare their `side_effect_class` in the example's
manifest under `tools[].side_effect_class` per spec section E.3 and
VAL-W16-005. The reference tool `relay_example.echo` is declared
`read_only` -- a deterministic echo over the MCP transport with no
I/O -- so cassette replay runs offline without an audited override.

A tool declared `mutating` or `external_irreversible` cannot be
replayed from a cassette without an audited policy override; the
replay engine surfaces `RELAY-REPLAY-014` and blocks the run.

## Replay notes

Cassette replay is the default and runs offline. Per VAL-W16-014
cassette replay produces zero network egress and does NOT spawn an
MCP server child process; the MCP-protocol JSON-RPC envelope is
served directly from the recorded fixtures under
`examples/mcp-tool-agent/python/cassettes/`. Each cassette line is a
`ReplayFixture v1` record per spec section E.2. A successful
cassette replay traces exactly one `model_call -> tool_call ->
model_call` chain.

Recording a cassette:

```sh
export MCP_SERVER_COMMAND="relay-example-mcp-server"
uv run rly replay record --manifest examples/mcp-tool-agent/relay.manifest.yaml --language python
```

Replaying:

```sh
uv run rly replay run --manifest examples/mcp-tool-agent/relay.manifest.yaml --language python --cassette python/cassettes/mcp-tool-agent.jsonl
```

A sandbox egress attempt or subprocess spawn during replay fails the
run and surfaces as a sandbox violation in the trace.

## Brief example

The example is invoked through the manifest-declared command surface
per VAL-W16-018; direct `python main.py` invocation is not the
supported path. The Python entry-point shapes are illustrated below
(import-checked at audit time against `relay.adapters`):

```python
from relay.adapters import SideEffectRecorder, register_tool

# Side-effect markers required by keystone invariant #6 for any tool
# declared side_effect=True (including MCP tools that mutate state).
recorder = SideEffectRecorder()
assert callable(register_tool)
```

Running the example via the CLI:

```sh
uv run rly replay run --manifest examples/mcp-tool-agent/relay.manifest.yaml --language python --cassette python/cassettes/mcp-tool-agent.jsonl
```

The example computes the SHA-256 of `relay.manifest.yaml` at run time
via `compute_manifest_commit_hash` and passes it as the third anchor
in the Relay handoff (per VAL-W16-022, spec section C.5). A run whose
`manifest_commit_hash` does not match the on-disk manifest produces
`RELAY-GATE-021` and is rejected by the sidecar's three-anchor
verifier.

Spec: §A.5, §E
