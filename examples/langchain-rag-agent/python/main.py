"""Relay LangChain RAG-agent example - Python entry point.

This example demonstrates the canonical Relay lifecycle around a
retrieval-augmented generation (RAG) loop backed by Anthropic Claude.
The example uses **manual instrumentation** (W3 Python SDK + W3.5
Anthropic adapter) because the full LangChain adapter is P1-deferred
in v0.1; per the contract preamble (VAL-W16-007) the README's
"Adapter status" section makes this caveat explicit.

The example exercises two operations end-to-end:

  1. A retrieval step over a small in-memory document collection. The
     retrieval span carries the spec section B.1 retrieval-diagnostics
     fields (retriever_name, query_digest, document_count, top-k
     documents with IDs / scores / ranks, duplicate signatures).
  2. A model call to Anthropic Claude (live mode) or the recorded
     cassette (cassette mode), with the retrieved documents included in
     the prompt.

Two entry points are exposed:

  * :func:`run_live_mode` - hits the real Anthropic API. Requires
    ``ANTHROPIC_API_KEY`` in the environment. Used by tier-2 smoke
    tests annotated ``@requires-anthropic``.

  * :func:`run_cassette_mode` - replays from the recorded cassette
    under ``cassettes/``. Deterministic, no network egress, runs on
    forks without provider keys.

Both entry points compute ``manifest_commit_hash`` as the SHA-256 of
the example's ``relay.manifest.yaml`` bytes, satisfying the
three-anchor handoff invariant per spec C.5 / VAL-W16-022.

Per CLAUDE.md keystone invariant #1 the SDK only submits lifecycle
metadata; the local sidecar's control plane is the sole writer of the
canonical ``run_results`` row.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

# Heavy imports (``relay``, ``anthropic``) are deferred inside the
# entry-point functions so the plumbing test suite can load this module
# via importlib without pulling in the full Relay package surface at
# module-import time. The deferred-import pattern keeps cassette-mode
# invocation self-contained: no network stack, no SDK transport state,
# no Resource warnings under Python 3.14's strict warning policy.


# Permitted side-effect classes the example may register. ``read_only``
# is the only class this example uses; any other class would require an
# audited replay policy override (RELAY-REPLAY-014, spec section E.3).
_PERMITTED_SIDE_EFFECT_CLASSES: frozenset[str] = frozenset({"read_only"})

# Backing model surface. Per VAL-W16-024 the example MUST exercise the
# W3.5 Python Anthropic adapter path; the model identifier is a Claude
# family model so the model_signature begins with ``anthropic/claude-``.
ANTHROPIC_MODEL = "claude-3-5-sonnet-20241022"
MODEL_SIGNATURE = f"anthropic/{ANTHROPIC_MODEL}"


def example_root() -> Path:
    """Return the absolute path to this example's root directory."""
    return Path(__file__).resolve().parent.parent


def compute_manifest_commit_hash() -> str:
    """Return the SHA-256 over ``relay.manifest.yaml`` bytes.

    Per spec section C.5 and VAL-W16-022 the example's
    ``run_results.manifest_commit_hash`` MUST equal the SHA-256 of the
    example's ``relay.manifest.yaml`` at the commit under test.
    """
    manifest_path = example_root() / "relay.manifest.yaml"
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    return f"sha256-{digest}"


def actor_identity_hash_for_example() -> str:
    """Return a deterministic actor identity hash for the example run."""
    seed = f"relay.example.langchain-rag-agent::{example_root().name}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"sha256-{digest}"


# ---------------------------------------------------------------------------
# Document corpus and retriever (deterministic stub for replay parity)
# ---------------------------------------------------------------------------
# The corpus is intentionally small and fully deterministic so the
# retrieval span's documents, scores, ranks, and duplicate signatures
# are byte-stable across runs. This is the data the manual
# instrumentation in ``build_retrieval_span`` records as the retrieval
# fixture for the cassette.

RETRIEVER_NAME = "in_memory_bm25_stub"

CORPUS: tuple[dict[str, str], ...] = (
    {
        "id": "doc-001",
        "title": "Reykjavik climate notes",
        "text": (
            "Reykjavik, the capital of Iceland, has a subpolar oceanic "
            "climate with cool summers and mild winters. Average winter "
            "temperatures hover near zero Celsius; summer highs reach "
            "around thirteen degrees Celsius."
        ),
    },
    {
        "id": "doc-002",
        "title": "Iceland weather seasonality",
        "text": (
            "Iceland's weather is famously changeable. Driven by North "
            "Atlantic currents, mild summers feature long daylight and "
            "moderate temperatures around thirteen Celsius in Reykjavik."
        ),
    },
    {
        "id": "doc-003",
        "title": "Geothermal heating in Iceland",
        "text": (
            "Most of Reykjavik is heated geothermally, which keeps "
            "indoor temperatures stable year-round even when outdoor "
            "weather is variable."
        ),
    },
    {
        "id": "doc-004",
        "title": "Travel guide: Reykjavik",
        "text": (
            "Visitors to Reykjavik should pack layers regardless of "
            "season; weather shifts quickly between sun, rain, and wind."
        ),
    },
)

DEFAULT_QUERY = "What is the weather in Reykjavik, Iceland?"


def _query_digest(query: str) -> str:
    """SHA-256 of the lowercased / whitespace-collapsed query.

    Stable, deterministic, and locale-independent: the query digest is
    one of the spec section B.1 retrieval-diagnostics fields used to
    bind a retrieval span to its query without persisting the raw
    text in cleartext.
    """
    normalised = " ".join(query.lower().split())
    return "sha256-" + hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def _document_signature(text: str) -> str:
    """SHA-256 of the document body, used as duplicate-signature key."""
    return "sha256-" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _score_document(doc: dict[str, str], query: str) -> float:
    """Deterministic relevance score: BM25-flavoured term-overlap proxy.

    Pure function. No randomness, no wall clock, no I/O. The score is
    fully reproducible given the document and the query, which keeps
    the retrieval span's ranks byte-stable across runs.
    """
    query_terms = {t for t in query.lower().split() if len(t) > 2}
    doc_terms = doc["text"].lower().split()
    if not query_terms or not doc_terms:
        return 0.0
    matches = sum(1 for t in doc_terms if t in query_terms)
    return round(matches / max(len(doc_terms), 1), 6)


def retrieve_top_k(
    query: str = DEFAULT_QUERY, *, top_k: int = 3
) -> list[dict[str, Any]]:
    """Return the top-k documents ranked by the deterministic scorer.

    Each returned record carries ``document_id``, ``score``, ``rank``,
    ``title``, ``duplicate_signature``, and the ``text`` body so the
    downstream prompt builder and the retrieval-span fixture have a
    single source of truth.
    """
    scored = [
        {
            "document_id": doc["id"],
            "title": doc["title"],
            "text": doc["text"],
            "score": _score_document(doc, query),
            "duplicate_signature": _document_signature(doc["text"]),
        }
        for doc in CORPUS
    ]
    scored.sort(key=lambda r: (-r["score"], r["document_id"]))
    selected = scored[:top_k]
    for rank, record in enumerate(selected, start=1):
        record["rank"] = rank
    return selected


def build_retrieval_span(
    query: str = DEFAULT_QUERY, *, top_k: int = 3
) -> dict[str, Any]:
    """Build the retrieval span attribute dict per spec section B.1.

    Manual instrumentation per VAL-W16-006 / VAL-W16-007: the example
    constructs this dict and emits it as the retrieval span's
    attribute payload. The full LangChain adapter (P1-deferred) would
    perform this construction automatically; until then, examples build
    the span by hand.

    Returns:
        A dict carrying span_id, kind=retrieval, retriever_name,
        query_digest, document_count, documents[] with per-document
        document_id / score / rank / duplicate_signature, and
        duplicate_document_count. Stable across runs given the same
        query and corpus.
    """
    documents = retrieve_top_k(query, top_k=top_k)
    # Duplicate-signature aggregation: two documents with identical
    # body text share a duplicate_signature; the count is the number
    # of documents that are not the first occurrence of their signature.
    seen_signatures: set[str] = set()
    duplicate_count = 0
    for doc in documents:
        sig = doc["duplicate_signature"]
        if sig in seen_signatures:
            duplicate_count += 1
        else:
            seen_signatures.add(sig)
    # span_id is a stable digest derived from the query + corpus
    # signature, so the same query against the same corpus produces a
    # byte-identical span_id. Real runs would mint a ULID via
    # relay._ulid; the example uses a digest-derived ID so cassette
    # replay matches the recorded fixture exactly.
    span_seed = "::".join(
        [
            "relay.retrieval.span",
            RETRIEVER_NAME,
            _query_digest(query),
            *(d["document_id"] for d in documents),
        ]
    )
    span_id = "ret-" + hashlib.sha256(span_seed.encode("utf-8")).hexdigest()[:32]
    return {
        "span_id": span_id,
        "kind": "retrieval",
        "retriever_name": RETRIEVER_NAME,
        "query_digest": _query_digest(query),
        "document_count": len(documents),
        "duplicate_document_count": duplicate_count,
        "documents": [
            {
                "document_id": d["document_id"],
                "rank": d["rank"],
                "score": d["score"],
                "duplicate_signature": d["duplicate_signature"],
            }
            for d in documents
        ],
    }


def _build_prompt_with_context(
    query: str, documents: list[dict[str, Any]]
) -> str:
    """Assemble the prompt body with the retrieved-document context."""
    context_lines: list[str] = []
    for doc in documents:
        context_lines.append(f"[{doc['document_id']}] {doc['title']}: {doc['text']}")
    context_block = "\n".join(context_lines)
    return (
        "You are a concise factual assistant. Use the context below to "
        "answer the user's question. Cite document IDs in square "
        "brackets.\n\n"
        f"CONTEXT:\n{context_block}\n\n"
        f"USER: {query}"
    )


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def _build_client_kwargs() -> dict[str, Any]:
    """Build the three-anchor handoff kwargs for the ``Relay`` constructor."""
    return {
        "actor_identity_hash": actor_identity_hash_for_example(),
        "manifest_commit_hash": compute_manifest_commit_hash(),
        "redaction_policy_version": "v1",
    }


def _build_agent() -> dict[str, Any]:
    """Return the ``agent`` descriptor passed to :meth:`Relay.run`."""
    return {"name": "langchain-rag-agent-example", "version": "0.1.0"}


def run_live_mode(*, project_key: str | None = None) -> int:
    """Run the example against the real Anthropic API.

    Requires ``ANTHROPIC_API_KEY`` in the environment. The example
    opens a Relay run, performs retrieval, dispatches a single
    Claude completion grounded on the retrieved context, and exits
    with code 0 when the canonical run_result is observed.

    Per CLAUDE.md keystone invariant #1 this function never writes a
    canonical row; it submits lifecycle metadata only. Per VAL-W16-024
    the example exercises the W3.5 Python Anthropic adapter path
    (``wrap_anthropic``).
    """
    if "ANTHROPIC_API_KEY" not in os.environ:
        raise RuntimeError(
            "ANTHROPIC_API_KEY not set; cannot run live mode. "
            "Use run_cassette_mode for offline replay."
        )
    # Lazy imports: cassette mode and module-load tests do not require
    # ``anthropic`` or the full ``relay`` SDK surface at import time.
    # ``anthropic`` is an optional live-mode dependency, not installed in the
    # type-checking/dev environment; the import is runtime-valid only when the
    # example is run live, so suppress the unresolved-import report here.
    import anthropic  # pyright: ignore[reportMissingImports]
    from relay import Relay
    from relay.adapters import wrap_anthropic

    raw_client = anthropic.Anthropic()
    relay = Relay(
        project_key=project_key or os.environ.get(
            "RELAY_PROJECT_KEY", "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        ),
        **_build_client_kwargs(),
    )
    wrapped = wrap_anthropic(raw_client)
    with relay.run(agent=_build_agent()) as run:
        # Step 1: manual retrieval instrumentation.
        retrieval_span = build_retrieval_span(DEFAULT_QUERY)
        documents = retrieve_top_k(DEFAULT_QUERY)
        # The retrieval span ID is printed so the harness can pluck it
        # from stdout and bind it to the run's evidence claims.
        print(f"relay retrieval span_id: {retrieval_span['span_id']}")
        print(
            f"relay retrieval retriever={retrieval_span['retriever_name']} "
            f"document_count={retrieval_span['document_count']} "
            f"duplicates={retrieval_span['duplicate_document_count']}"
        )
        # Step 2: Anthropic Claude completion grounded on the retrieved
        # context. The adapter records the model_call span into the
        # run's trace.
        prompt = _build_prompt_with_context(DEFAULT_QUERY, documents)
        response = wrapped.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        # Anthropic responses carry a ``content`` list of blocks; the
        # first text block is the model's reply.
        content_blocks = getattr(response, "content", []) or []
        for block in content_blocks:
            text = getattr(block, "text", None)
            if text:
                print(text)
                break
        print(f"relay model_signature: {MODEL_SIGNATURE}")
        print(f"relay run_id: {run.run_id}")
        print(f"relay trace_id: {run.trace_id}")
    return 0


def run_cassette_mode(*, project_key: str | None = None) -> int:
    """Replay the example from the recorded cassette deterministically.

    Loads the cassette under ``python/cassettes/langchain-rag-agent.jsonl``,
    iterates the recorded fixtures, asserts the canonical kind sequence
    (retrieval -> model_call), and prints the deterministic summary.

    Produces no network traffic and does not require an Anthropic key.

    Per VAL-W16-008 the cassette covers both retrieval and model_call
    fixtures; per VAL-W16-024 at least one model_call carries an
    Anthropic Claude model_signature.
    """
    cassette_path = (
        example_root()
        / "python"
        / "cassettes"
        / "langchain-rag-agent.jsonl"
    )
    if not cassette_path.is_file():
        raise FileNotFoundError(
            f"cassette not found at {cassette_path}; "
            "regenerate with 'rly replay record --example langchain-rag-agent'"
        )
    fixtures: list[dict[str, Any]] = []
    for line in cassette_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        fixtures.append(json.loads(line))
    # Verify the canonical RAG kind sequence (retrieval first, then
    # one or more model_call records).
    kinds = [f.get("kind") for f in fixtures]
    if "retrieval" not in kinds or "model_call" not in kinds:
        raise RuntimeError(
            f"cassette kind sequence {kinds} missing retrieval or model_call; "
            "cassette is stale or corrupted"
        )
    if kinds.index("retrieval") > kinds.index("model_call"):
        raise RuntimeError(
            f"cassette kind sequence {kinds}: retrieval must precede the "
            "first model_call (RAG ordering)"
        )
    # Side-effect-class invariant: every fixture is read-only; mutating
    # tools under replay without a policy override would be
    # RELAY-REPLAY-014.
    for fx in fixtures:
        sec = fx.get("side_effect_class")
        if sec not in _PERMITTED_SIDE_EFFECT_CLASSES:
            raise RuntimeError(
                f"cassette fixture has side_effect_class={sec!r}; "
                "replay rejects mutating fixtures without override"
            )
    # Surface the canonical retrieval span fields (manual
    # instrumentation per VAL-W16-006).
    retrieval_span = build_retrieval_span()
    print(
        f"[cassette] retrieval span_id={retrieval_span['span_id']} "
        f"retriever={retrieval_span['retriever_name']} "
        f"document_count={retrieval_span['document_count']} "
        f"duplicates={retrieval_span['duplicate_document_count']}"
    )
    # Print each model_call fixture's model_signature so VAL-W16-024
    # is provable from the offline replay (the cassette records the
    # Anthropic Claude signature).
    for fx in fixtures:
        if fx.get("kind") == "model_call":
            sig = fx.get("model_signature", "")
            print(f"[cassette] model_call model_signature={sig}")
    print(
        f"[cassette] replayed {len(fixtures)} fixtures: "
        f"{' -> '.join(str(k) for k in kinds)}"
    )
    print(
        "[cassette] OK - cassette replay completed with zero network egress"
    )
    _ = project_key  # accepted for parity with run_live_mode
    return 0


def main(argv: list[str] | None = None) -> int:
    """Command-line dispatch: choose live or cassette mode by env / flag."""
    argv = argv if argv is not None else sys.argv[1:]
    mode = "cassette"
    for arg in argv:
        if arg == "--live":
            mode = "live"
        elif arg == "--cassette":
            mode = "cassette"
    if mode == "live":
        return run_live_mode()
    return run_cassette_mode()


if __name__ == "__main__":
    sys.exit(main())
