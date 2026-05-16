# OpenAI tool-agent example - Python

Python entry point for the cross-language Relay OpenAI tool-agent
example. Implements the canonical Relay lifecycle (open run, wrap
OpenAI, dispatch deterministic tool call, return result, sidecar's
control plane writes the canonical `run_results` row).

See `../README.md` for the cross-language overview, including
architecture, manifest contract, and cross-references to the spec.

## Installation

```sh
# From the repo root
uv sync --all-packages
```

The example depends on the workspace Relay Python SDK (`relay`) and on
the upstream `openai` package. `pyyaml` is used by the smoke harness
to read `relay.manifest.yaml`.

## Running live mode

Requires `OPENAI_API_KEY` in the environment. The smoke harness uses
the manifest-declared command surface:

```sh
export OPENAI_API_KEY=sk-...
uv run rly run --manifest examples/openai-tool-agent/relay.manifest.yaml --language python --mode live
```

Local development can also invoke the example directly through the
module's `main()` entry point:

```sh
uv run python examples/openai-tool-agent/python/main.py --live
```

Note: direct `python ...` invocation is for local iteration only; CI
and the smoke harness MUST go through `rly run` (per `VAL-W16-018`).

## Recording a cassette

Records to `python/cassettes/openai-tool-agent.jsonl`:

```sh
export OPENAI_API_KEY=sk-...
uv run rly replay record --manifest examples/openai-tool-agent/relay.manifest.yaml --language python
```

The replay proxy spawns a per-session localhost mitmproxy with a
short-lived CA cert; the Python entry point picks up `HTTPS_PROXY` and
`SSL_CERT_FILE` from the manifest's `run-python-live` command's
environment and routes OpenAI traffic through the proxy.

## Replaying from cassette

The cassette replay path runs offline and is the default:

```sh
uv run rly replay run --manifest examples/openai-tool-agent/relay.manifest.yaml --language python --cassette python/cassettes/openai-tool-agent.jsonl
```

For local iteration without `rly`:

```sh
uv run python examples/openai-tool-agent/python/main.py --cassette
```

Cassette mode uses the sandbox's default-deny network egress policy;
the trace's egress counter MUST equal zero (per `VAL-W16-004`).

## Expected output

```text
[cassette] replayed 3 fixtures: model_call -> tool_call -> model_call
[cassette] tool_call: get_current_weather (read_only) -> forecast=clear temperature=13
[cassette] OK - cassette replay completed with zero network egress
```

## Module API

The Python entry point exposes:

- `run_live_mode(*, project_key=None)`: live run against OpenAI.
- `run_cassette_mode(*, project_key=None)`: deterministic cassette
  replay; no network.
- `compute_manifest_commit_hash()`: SHA-256 over `relay.manifest.yaml`.
- `actor_identity_hash_for_example()`: derived identity hash for the
  three-anchor handoff.
- `dispatch_tool_call(tool_name, raw_arguments)`: tool dispatcher.
- `get_current_weather(location, unit)`: deterministic stub tool.

All entry points are importable via `importlib`; smoke harness tests
load the module without executing the example to inspect its static
shape.

## Platform support

The Python entry point runs on macOS, Linux, and Windows (per
`VAL-W16-021`). No POSIX-only APIs are invoked unconditionally;
`pathlib` is used for all path handling so backslash separators on
Windows are handled correctly.
