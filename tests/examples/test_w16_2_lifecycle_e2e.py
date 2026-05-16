"""End-to-end lifecycle assertions for the LangChain RAG example.

Covers:
  VAL-W16-006: example produces retrieval spans -- the example exposes
               an entry point that emits at least one retrieval span
               with retriever_name, document_count, document IDs, scores,
               rank, and duplicate signature fields populated per spec
               section B.1 retrieval diagnostics.
  VAL-W16-022: example traces bind to manifest_commit_hash (three-anchor
               handoff per spec section C.5).
  VAL-W16-024: example backs onto Anthropic Claude and exercises the
               W3.5 Python Anthropic adapter path. The cassette-mode
               entry point surfaces a model_signature beginning with
               ``anthropic/claude-`` so the live-mode invariant is
               provable from the offline replay.

Per the W16 contract notes (gap #1) live-mode tier-2 assertions only
run on the upstream repo's CI where provider keys are available, so
this tier-1 plumbing surface exercises the structural and SDK-level
invariants. The cassette-mode entry point is exercised directly here
(no provider key required); the live entry point is asserted to exist
and to reference the Anthropic adapter surface.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def langchain_example_root() -> Path:
    return REPO_ROOT / "examples" / "langchain-rag-agent"


def _load_main_module(python_dir: Path) -> Any:
    """Import examples/langchain-rag-agent/python/main.py as a module.

    Uses importlib.util so the example does not need to be a package
    on the workspace path. Mirrors the W16.1 lifecycle test helper.
    """
    main_py = python_dir / "main.py"
    spec = importlib.util.spec_from_file_location(
        "langchain_rag_agent_example_main", main_py
    )
    assert spec is not None and spec.loader is not None, (
        f"could not load spec for {main_py}"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-006")
def test_langchain_python_main_module_loads_and_has_expected_callables(
    langchain_example_root: Path,
) -> None:
    """The example's main.py is importable and exposes the cassette-mode
    entry point + a retrieval-span helper.
    """
    python_dir = langchain_example_root / "python"
    assert python_dir.is_dir(), "examples/langchain-rag-agent/python/ missing"
    module = _load_main_module(python_dir)
    assert hasattr(module, "run_cassette_mode"), (
        "examples/langchain-rag-agent/python/main.py must expose "
        "run_cassette_mode() (VAL-W16-006 cassette path)."
    )
    assert hasattr(module, "run_live_mode"), (
        "examples/langchain-rag-agent/python/main.py must expose run_live_mode()"
    )
    # Manual instrumentation exposes a retrieval-span builder. Per
    # VAL-W16-006 the example MUST be able to produce a retrieval span;
    # exposing a callable that builds the span attribute dict makes the
    # assertion testable offline.
    assert hasattr(module, "build_retrieval_span"), (
        "main.py must expose build_retrieval_span() -- manual "
        "instrumentation helper per VAL-W16-006/007."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-006")
def test_langchain_build_retrieval_span_produces_required_fields(
    langchain_example_root: Path,
) -> None:
    """Per VAL-W16-006 the retrieval span MUST carry retriever_name,
    top-k documents (document IDs + scores + ranks), duplicate
    signatures, and document_count per spec section B.1 retrieval
    diagnostics. We exercise the offline builder directly.
    """
    module = _load_main_module(langchain_example_root / "python")
    span = module.build_retrieval_span()
    assert isinstance(span, dict), "build_retrieval_span must return a dict"
    # Spec section B.1 retrieval-diagnostics required fields.
    required_fields = {
        "span_id",
        "kind",
        "retriever_name",
        "query_digest",
        "document_count",
        "documents",
        "duplicate_document_count",
    }
    missing = required_fields - span.keys()
    assert not missing, (
        f"retrieval span missing required fields: {sorted(missing)}. "
        f"Required: {sorted(required_fields)} (spec B.1)."
    )
    assert span["kind"] == "retrieval", (
        f"span kind must be 'retrieval'; got {span['kind']!r}"
    )
    # documents[] MUST carry document IDs, scores, and ranks per spec B.1.
    documents = span["documents"]
    assert isinstance(documents, list) and documents, (
        "retrieval span must declare at least one document"
    )
    doc_required = {"document_id", "score", "rank"}
    for idx, doc in enumerate(documents):
        missing_doc = doc_required - doc.keys()
        assert not missing_doc, (
            f"document[{idx}] missing required fields: {sorted(missing_doc)}. "
            f"Required per spec B.1: {sorted(doc_required)}."
        )
    # document_count MUST equal len(documents) so the field is internally
    # consistent (eliminates a class of off-by-one bugs).
    assert span["document_count"] == len(documents), (
        f"document_count={span['document_count']} but len(documents)="
        f"{len(documents)}; fields must be consistent."
    )
    # duplicate_document_count MUST be in [0, document_count].
    dup = span["duplicate_document_count"]
    assert isinstance(dup, int) and 0 <= dup <= len(documents), (
        f"duplicate_document_count={dup!r} must be int in "
        f"[0, {len(documents)}]"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-006")
def test_langchain_run_cassette_mode_returns_zero(
    langchain_example_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Cassette-mode entry point runs end-to-end without a provider key
    and exits 0; stdout contains the deterministic summary including
    the retrieval span identifier so the smoke harness can verify the
    "expected output snippet" from the README.
    """
    module = _load_main_module(langchain_example_root / "python")
    rc = module.run_cassette_mode()
    assert rc == 0, f"run_cassette_mode exit code {rc} != 0"
    captured = capsys.readouterr()
    assert "retrieval" in captured.out.lower(), (
        "cassette mode stdout must mention 'retrieval' (the retrieval "
        "span line) per VAL-W16-006 / README expected-output snippet."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-022")
def test_langchain_python_main_carries_manifest_commit_hash(
    langchain_example_root: Path,
) -> None:
    """The example main.py computes manifest_commit_hash from the
    manifest file and passes it as the third anchor in the Relay
    handoff (spec section C.5 / VAL-W16-022).
    """
    python_dir = langchain_example_root / "python"
    main_text = (python_dir / "main.py").read_text(encoding="utf-8")
    assert "manifest_commit_hash" in main_text, (
        "main.py must reference manifest_commit_hash (VAL-W16-022)"
    )
    assert "relay.manifest.yaml" in main_text, (
        "main.py must read relay.manifest.yaml to compute manifest_commit_hash"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-022")
def test_langchain_compute_manifest_commit_hash_matches_file_sha256(
    langchain_example_root: Path,
) -> None:
    """compute_manifest_commit_hash() MUST equal sha256(manifest bytes).

    Per spec section C.5 the third anchor in the three-anchor handoff
    is the SHA-256 of the example's on-disk relay.manifest.yaml. The
    test computes the expected digest directly and compares.
    """
    import hashlib

    module = _load_main_module(langchain_example_root / "python")
    manifest_path = langchain_example_root / "relay.manifest.yaml"
    expected = (
        "sha256-" + hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    )
    actual = module.compute_manifest_commit_hash()
    assert actual == expected, (
        f"compute_manifest_commit_hash() returned {actual!r}; "
        f"expected {expected!r} (sha256 of relay.manifest.yaml bytes; "
        "VAL-W16-022)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-024")
def test_langchain_python_main_imports_anthropic_adapter(
    langchain_example_root: Path,
) -> None:
    """Per VAL-W16-024 the example MUST exercise the W3.5 Python
    Anthropic adapter path. The live-mode entry point MUST reference
    ``wrap_anthropic`` so the adapter is exercised at the example surface.
    """
    main_text = (
        langchain_example_root / "python" / "main.py"
    ).read_text(encoding="utf-8")
    assert "wrap_anthropic" in main_text, (
        "main.py must import wrap_anthropic from relay.adapters "
        "(VAL-W16-024 Anthropic adapter exercise)."
    )
    # ANTHROPIC_API_KEY env var must be referenced (not OPENAI_API_KEY).
    assert "ANTHROPIC_API_KEY" in main_text, (
        "main.py must reference ANTHROPIC_API_KEY (VAL-W16-024 live-mode)."
    )
    # The model identifier MUST be a Claude model.
    assert "claude" in main_text.lower(), (
        "main.py must reference an Anthropic Claude model "
        "(VAL-W16-024 backing-model invariant)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-024")
def test_langchain_cassette_mode_surfaces_anthropic_model_signature(
    langchain_example_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Per VAL-W16-024 the cassette-mode entry point MUST surface the
    Anthropic Claude model_signature in stdout so the offline replay
    proves the backing-model invariant without requiring live API
    access.
    """
    module = _load_main_module(langchain_example_root / "python")
    rc = module.run_cassette_mode()
    assert rc == 0
    captured = capsys.readouterr()
    assert "anthropic/claude-" in captured.out, (
        "cassette mode stdout must print the Anthropic Claude "
        "model_signature prefix (VAL-W16-024)."
    )
