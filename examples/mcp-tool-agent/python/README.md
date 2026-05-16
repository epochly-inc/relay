# MCP tool-agent example - Python

Python entry point for the Relay MCP tool-agent example. Implements
the canonical Relay MCP lifecycle (open run, connect MCP client to
the pinned MCP server, dispatch a deterministic MCP tool call,
sidecar's control plane writes the canonical `run_results` row).

See `../README.md` for the cross-cutting overview, architecture, the
"Adapter status" section, manifest contract, and spec cross-references.

## Installation

```sh
# From the repo root
uv sync --all-packages
```

The example depends on the workspace Relay Python SDK (`relay`), the
upstream `mcp` package (Model Context Protocol Python SDK), and
`pyyaml`.

## Running live mode

Requires `MCP_SERVER_COMMAND` in the environment, set to the command
used to spawn the pinned MCP server. The smoke harness uses the
manifest-declared command surface:

```sh
export MCP_SERVER_COMMAND="relay-example-mcp-server"
uv run rly run --manifest examples/mcp-tool-agent/relay.manifest.yaml --language python --mode live
```

Local development can also invoke the example directly through the
module's `main()` entry point:

```sh
uv run python examples/mcp-tool-agent/python/main.py --live
```

Note: direct `python ...` invocation is for local iteration only; CI
and the smoke harness MUST go through `rly run` (per VAL-W16-018).

## Recording a cassette

Records to `python/cassettes/mcp-tool-agent.jsonl`:

```sh
export MCP_SERVER_COMMAND="relay-example-mcp-server"
uv run rly replay record --manifest examples/mcp-tool-agent/relay.manifest.yaml --language python
```

The recorded cassette MUST contain at least one `kind: model_call`
fixture and at least one `kind: tool_call` fixture so the MCP trace
is fully reproducible (VAL-W16-014). The tool_call fixture records
the MCP tool name in `server.tool` form, the redacted MCP-protocol
envelope, `args_hash`, `result_hash`, `status`, and `duration_ms`.

## Replaying from cassette

Cassette replay runs offline, with zero network egress, and does NOT
spawn an MCP server child process during replay:

```sh
uv run rly replay run --manifest examples/mcp-tool-agent/relay.manifest.yaml --language python --cassette python/cassettes/mcp-tool-agent.jsonl
```

For local iteration without `rly`:

```sh
uv run python examples/mcp-tool-agent/python/main.py --cassette
```

Cassette mode uses the sandbox's default-deny network egress policy;
the trace's egress counter MUST equal zero. The replay engine refuses
to spawn the MCP server binary -- the MCP-protocol envelope is served
directly from the recorded fixtures.

## Expected output

```text
[cassette] mcp tool_call: relay_example.echo (read_only) status=ok duration_ms=2
[cassette] mcp args_hash=sha256-... result_hash=sha256-...
[cassette] replayed 3 fixtures: model_call -> tool_call -> model_call
[cassette] OK - cassette replay completed with zero network egress and no MCP server spawn
```

## Module API

The Python entry point exposes:

- `run_live_mode(*, project_key=None)`: live run against a real MCP
  server.
- `run_cassette_mode(*, project_key=None)`: deterministic cassette
  replay; no network, no MCP server child process.
- `compute_manifest_commit_hash()`: SHA-256 over `relay.manifest.yaml`.
- `actor_identity_hash_for_example()`: derived identity hash for the
  three-anchor handoff.
- `build_mcp_tool_call_span(message=None)`: manual instrumentation
  helper that constructs the MCP tool_call span attribute dict per
  spec section B.1 (tool_name in `server.tool` form, args_hash,
  result_hash, status, duration_ms, side_effect_marker,
  redacted_args, redaction_policy_version).
- `dispatch_mcp_tool_call(tool_name, raw_arguments)`: MCP tool
  dispatcher for the example's pinned read-only echo tool.

All entry points are importable via `importlib`; smoke harness tests
load the module without executing the example to inspect its static
shape.

## Platform support

The Python entry point runs on macOS, Linux, and Windows (per
VAL-W16-021). No POSIX-only APIs are invoked unconditionally;
`pathlib` is used for all path handling so backslash separators on
Windows are handled correctly. The MCP client spawn (live mode only)
goes through the upstream `mcp.client.stdio` adapter which itself
abstracts the POSIX vs Windows subprocess primitives.
