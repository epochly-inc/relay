# LangChain RAG-agent example - Python

Python entry point for the Relay LangChain RAG-agent example.
Implements the canonical Relay RAG lifecycle (open run, retrieve
documents with manual instrumentation, call Anthropic Claude through
the W3.5 `wrap_anthropic` adapter, sidecar's control plane writes the
canonical `run_results` row).

See `../README.md` for the cross-cutting overview, architecture
diagram, manifest contract, the "Adapter status" caveat
(the full LangChain adapter is P1-deferred in v0.1 and this example
uses manual SDK calls), and spec cross-references.

## Installation

```sh
# From the repo root
uv sync --all-packages
```

The example depends on the workspace Relay Python SDK (`relay`), the
upstream `anthropic` provider SDK, `langchain-core` (used minimally;
the full LangChain adapter is P1-deferred), and `pyyaml`.

## Running live mode

Requires `ANTHROPIC_API_KEY` in the environment. The smoke harness
uses the manifest-declared command surface:

```sh
export ANTHROPIC_API_KEY=sk-ant-...
uv run rly run --manifest examples/langchain-rag-agent/relay.manifest.yaml --language python --mode live
```

Local development can also invoke the example directly through the
module's `main()` entry point:

```sh
uv run python examples/langchain-rag-agent/python/main.py --live
```

Note: direct `python ...` invocation is for local iteration only; CI
and the smoke harness MUST go through `rly run` (per VAL-W16-018).

## Recording a cassette

Records to `python/cassettes/langchain-rag-agent.jsonl`:

```sh
export ANTHROPIC_API_KEY=sk-ant-...
uv run rly replay record --manifest examples/langchain-rag-agent/relay.manifest.yaml --language python
```

The replay proxy spawns a per-session localhost mitmproxy with a
short-lived CA cert; the Python entry point picks up `HTTPS_PROXY` and
`SSL_CERT_FILE` from the manifest's `run-python-live` command's
environment and routes Anthropic traffic through the proxy.

The recorded cassette MUST contain at least one `kind: retrieval`
fixture and at least one `kind: model_call` fixture so the RAG trace
is fully reproducible (VAL-W16-008).

## Replaying from cassette

Cassette replay runs offline and is the default:

```sh
uv run rly replay run --manifest examples/langchain-rag-agent/relay.manifest.yaml --language python --cassette python/cassettes/langchain-rag-agent.jsonl
```

For local iteration without `rly`:

```sh
uv run python examples/langchain-rag-agent/python/main.py --cassette
```

Cassette mode uses the sandbox's default-deny network egress policy;
the trace's egress counter MUST equal zero.

## Expected output

```text
[cassette] retrieval span_id=ret-... retriever=in_memory_bm25_stub document_count=3 duplicates=0
[cassette] model_call model_signature=anthropic/claude-3-5-sonnet-20241022@msgs_2024_10_22
[cassette] replayed 2 fixtures: retrieval -> model_call
[cassette] OK - cassette replay completed with zero network egress
```

## Module API

The Python entry point exposes:

- `run_live_mode(*, project_key=None)`: live run against Anthropic
  Claude.
- `run_cassette_mode(*, project_key=None)`: deterministic cassette
  replay; no network.
- `compute_manifest_commit_hash()`: SHA-256 over `relay.manifest.yaml`.
- `actor_identity_hash_for_example()`: derived identity hash for the
  three-anchor handoff.
- `build_retrieval_span(query, *, top_k=3)`: manual instrumentation
  helper that constructs the retrieval span attribute dict per spec
  section B.1 (retriever_name, query_digest, document_count,
  documents with document_id/score/rank, duplicate signatures,
  duplicate_document_count).
- `retrieve_top_k(query, *, top_k=3)`: deterministic in-memory
  retriever over the static corpus.

All entry points are importable via `importlib`; smoke harness tests
load the module without executing the example to inspect its static
shape.

## Platform support

The Python entry point runs on macOS, Linux, and Windows (per
VAL-W16-021). No POSIX-only APIs are invoked unconditionally;
`pathlib` is used for all path handling so backslash separators on
Windows are handled correctly.
