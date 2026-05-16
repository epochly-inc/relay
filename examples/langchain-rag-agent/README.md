# Relay example: LangChain RAG-agent

Relay example exercising a retrieval-augmented generation (RAG) loop
backed by Anthropic Claude. Ships in Python only (the W3.5 Python
Anthropic adapter underpins the canonical assertion); there is no
TypeScript subdirectory.

The example demonstrates the canonical Relay RAG lifecycle:

1. Open a Relay run with the three-anchor handoff
   (`actor_identity_hash`, `manifest_commit_hash`,
   `redaction_policy_version`).
2. Retrieve documents from a deterministic in-memory corpus and emit a
   retrieval span carrying spec section B.1 retrieval-diagnostics
   fields (retriever name, top-k documents, document IDs, scores,
   ranks, duplicate signatures).
3. Call Anthropic Claude through the W3.5 `wrap_anthropic` adapter;
   the adapter records the `model_call` span into the run's trace.
4. The local sidecar's control plane writes the canonical
   `run_results` row (the SDK never writes a canonical row -- CLAUDE.md
   keystone invariant #1).

## Adapter status

The full LangChain adapter for Relay is **P1-deferred** in v0.1. This
example does NOT exercise a LangChain adapter; it uses **manual
instrumentation** via the W3 Python SDK primitives and the W3.5
Anthropic adapter (`relay.adapters.wrap_anthropic`). The retrieval span
is constructed by hand in `python/main.py::build_retrieval_span` per
the spec section B.1 retrieval-diagnostics field set.

When the full LangChain adapter lands (post v0.1), the manual
instrumentation in this example will be replaceable by adapter-driven
spans without changing the example's lifecycle shape; until then the
manual-SDK-calls path is the only supported way to exercise the RAG
trace surface from a LangChain-flavoured workflow.

The example backs onto **Anthropic Claude** (per VAL-W16-024 / CW-002)
to exercise the W3.5 Python Anthropic adapter end-to-end. Live mode
requires `ANTHROPIC_API_KEY`; cassette mode replays a recorded
Claude-backed session offline.

## Installation

Prerequisites:

- Python 3.12+ (matrix: 3.12, 3.13, 3.14)
- `uv` for Python workspace management

From the repo root:

```sh
# Install the Python workspace including the Relay SDK
uv sync --all-packages
```

The example itself is not a workspace member; it ships its own
`pyproject.toml` so contributors can copy it into a fresh project as a
starting point.

## Running live mode

Live mode hits the real Anthropic API. Requires an `ANTHROPIC_API_KEY`
in the environment. Live runs produce a canonical `run_results` row in
the local sidecar.

```sh
export ANTHROPIC_API_KEY=sk-ant-...
uv run rly run --manifest examples/langchain-rag-agent/relay.manifest.yaml --language python --mode live
```

The command dispatches through the manifest-declared command surface
per VAL-W16-018. Direct `python examples/...` invocations are not the
supported path.

## Recording a cassette

A cassette is a deterministic record of a session's retrieval and
model fixtures. The Relay replay proxy records cassettes by spawning a
per-session localhost mitmproxy that captures provider traffic and
writes one `ReplayFixture` per request/response under
`examples/langchain-rag-agent/python/cassettes/`.

```sh
export ANTHROPIC_API_KEY=sk-ant-...
uv run rly replay record --manifest examples/langchain-rag-agent/relay.manifest.yaml --language python
```

The command writes `python/cassettes/langchain-rag-agent.jsonl`. Each
line is a JSON-encoded `ReplayFixture v1` record per spec section E.2.
The cassette MUST contain at least one `kind: retrieval` fixture and
at least one `kind: model_call` fixture (per VAL-W16-008 RAG
invariant).

To regenerate a stale cassette after an upstream change (Anthropic
model rotation, prompt drift, retriever update), re-run
`rly replay record` and commit the updated JSONL.

## Replaying from cassette

Cassette replay is the default and offline; no provider key required.

```sh
uv run rly replay run --manifest examples/langchain-rag-agent/relay.manifest.yaml --language python --cassette python/cassettes/langchain-rag-agent.jsonl
```

Replay runs inside the sandbox with default-deny network egress.
Provider traffic is served from the cassette; an egress attempt
against `api.anthropic.com` fails the run and surfaces in the trace
as a sandbox violation.

## Expected output

A successful cassette replay prints:

```text
[cassette] retrieval span_id=ret-... retriever=in_memory_bm25_stub document_count=3 duplicates=0
[cassette] model_call model_signature=anthropic/claude-3-5-sonnet-20241022@msgs_2024_10_22
[cassette] replayed 2 fixtures: retrieval -> model_call
[cassette] OK - cassette replay completed with zero network egress
```

The recorded trace contains a `retrieval` span followed by a
`model_call` span. The retrieval span carries the spec section B.1
diagnostics fields (retriever name, top-k document IDs, scores, ranks,
duplicate signatures); the model_call span's `model_signature` begins
with `anthropic/claude-` (VAL-W16-024 backing-model invariant).

## Tool side-effect classes

Every tool the example registers declares its `side_effect_class` in
the manifest (per VAL-W16-005):

| Tool | side_effect_class | Notes |
| --- | --- | --- |
| `retrieve_top_k` | `read_only` | Deterministic in-memory BM25-flavoured retriever; no I/O |

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
examples/langchain-rag-agent/
|-- README.md                         # this file
|-- relay.manifest.yaml               # commands, tools, ports, test entries
|-- pyproject.toml                    # Python example package definition
|-- .gitignore
`-- python/
    |-- README.md                     # Python-specific run notes
    |-- main.py                       # entry point (run_live_mode / run_cassette_mode / build_retrieval_span)
    `-- cassettes/
        `-- langchain-rag-agent.jsonl # ReplayFixture v1 records (retrieval + model_call)
```

## See also

- `planning/epochly-replay-spec.md` sections A.1 (RunResult), B.1
  (span schema + retrieval diagnostics), C.5 (three-anchor handoff),
  E.1-E.4 (replay), F (manifest), S (adapter P0/P1 placement),
  X (side-effect classes).
- `examples/openai-tool-agent/` for the W16.1 OpenAI tool-agent example
  (cross-language Python + TypeScript parity exercise).
- `examples/vercel-ai-tool-agent/`, `examples/mcp-tool-agent/` for the
  other W16 examples.
