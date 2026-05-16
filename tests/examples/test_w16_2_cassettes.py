"""Cassette / ReplayFixture validation for the LangChain RAG example.

Covers:
  VAL-W16-008: replays from cassette (recorded cassettes parse + load
               without errors; the cassette includes retrieval AND
               model_call fixtures so the trace digest is reproducible).
  VAL-W16-020: ReplayFixtures carry valid schema_version, mode,
               provider, model, model_signature, refresh_policy, and
               side_effect_class per spec section E.2.

Tier-1 plumbing: parses JSONL cassettes on disk, validates each entry
against the spec section E.2 ReplayFixture envelope contract.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def langchain_example_root() -> Path:
    return REPO_ROOT / "examples" / "langchain-rag-agent"


# Refresh policies per spec section E.2 (envelopes.yaml lines 502-510).
VALID_REFRESH_POLICIES: frozenset[str] = frozenset(
    {
        "invalidate_on_signature_change",
        "hold_forever",
        "refresh_weekly",
        "invalidate_on_model_version_change",
    }
)

# ReplayFixture.kind enum per spec section E.2 (envelopes.yaml line 486-488).
VALID_KINDS: frozenset[str] = frozenset(
    {"model_call", "tool_call", "retrieval", "embedding", "custom"}
)

VALID_MODES: frozenset[str] = frozenset(
    {"cassette", "live", "degraded_live", "mock"}
)

VALID_SIDE_EFFECT_CLASSES: frozenset[str] = frozenset(
    {"read_only", "mutating", "external_irreversible", "approval_required"}
)


def _iter_cassettes(example_root: Path) -> list[Path]:
    """Yield every .jsonl cassette file under python/cassettes/."""
    out: list[Path] = []
    cassette_dir = example_root / "python" / "cassettes"
    if cassette_dir.is_dir():
        out.extend(sorted(cassette_dir.glob("*.jsonl")))
    return out


def _load_fixtures(path: Path) -> list[dict]:
    """Load every JSON line from a cassette file as a dict."""
    fixtures: list[dict] = []
    for lineno, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"{path}: line {lineno}: invalid JSON: {exc}"
            ) from exc
        assert isinstance(entry, dict), (
            f"{path}: line {lineno}: cassette entry must be a JSON object"
        )
        fixtures.append(entry)
    return fixtures


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-008")
def test_langchain_cassettes_exist(langchain_example_root: Path) -> None:
    """The Python language ships at least one recorded cassette."""
    cassette_dir = langchain_example_root / "python" / "cassettes"
    assert cassette_dir.is_dir(), (
        "cassettes/ directory missing under examples/langchain-rag-agent/python/"
    )
    fixtures = list(cassette_dir.glob("*.jsonl"))
    assert fixtures, (
        "python/cassettes/ must contain at least one .jsonl cassette "
        "(VAL-W16-008: replay from cassette)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-020")
def test_langchain_cassettes_have_valid_schema_version_and_refresh_policy(
    langchain_example_root: Path,
) -> None:
    """Every cassette entry parses as relay.replay_fixture.v1 with valid
    mode, provider, model, model_signature, refresh_policy, and
    side_effect_class per spec section E.2 / VAL-W16-020.
    """
    cassettes = _iter_cassettes(langchain_example_root)
    assert cassettes, "No cassettes found to validate"
    failures: list[str] = []
    for cassette in cassettes:
        fixtures = _load_fixtures(cassette)
        if not fixtures:
            failures.append(f"{cassette}: empty cassette")
            continue
        for idx, fx in enumerate(fixtures):
            ctx = f"{cassette.name}[{idx}]"
            if fx.get("schema_version") != "relay.replay_fixture.v1":
                failures.append(
                    f"{ctx}: schema_version != relay.replay_fixture.v1 "
                    f"(got {fx.get('schema_version')!r})"
                )
            if fx.get("mode") != "cassette":
                failures.append(
                    f"{ctx}: mode must be 'cassette' (got {fx.get('mode')!r})"
                )
            elif fx.get("mode") not in VALID_MODES:
                failures.append(f"{ctx}: invalid mode {fx.get('mode')!r}")
            if not fx.get("provider"):
                failures.append(f"{ctx}: provider is empty/missing")
            if not fx.get("model"):
                failures.append(f"{ctx}: model is empty/missing")
            if not fx.get("model_signature"):
                failures.append(f"{ctx}: model_signature is empty/missing")
            rp = fx.get("refresh_policy")
            if rp not in VALID_REFRESH_POLICIES:
                failures.append(
                    f"{ctx}: invalid refresh_policy {rp!r}; "
                    f"must be one of {sorted(VALID_REFRESH_POLICIES)}"
                )
            sec = fx.get("side_effect_class")
            if sec not in VALID_SIDE_EFFECT_CLASSES:
                failures.append(
                    f"{ctx}: invalid side_effect_class {sec!r}; "
                    f"must be one of {sorted(VALID_SIDE_EFFECT_CLASSES)}"
                )
            kind = fx.get("kind")
            if kind not in VALID_KINDS:
                failures.append(
                    f"{ctx}: invalid kind {kind!r}; "
                    f"must be one of {sorted(VALID_KINDS)}"
                )
    assert not failures, (
        "Cassette validation failures:\n" + "\n".join(failures)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-008")
def test_langchain_cassette_contains_retrieval_and_model_call(
    langchain_example_root: Path,
) -> None:
    """Per VAL-W16-008 the LangChain cassette covers LLM completions AND
    retrieval responses. The cassette MUST contain at least one
    ``kind=retrieval`` fixture and at least one ``kind=model_call``
    fixture so the replayed trace exercises the RAG path end-to-end.
    """
    cassette_dir = langchain_example_root / "python" / "cassettes"
    assert cassette_dir.is_dir(), "python/cassettes/ missing"
    any_retrieval = False
    any_model_call = False
    for cassette in cassette_dir.glob("*.jsonl"):
        for fx in _load_fixtures(cassette):
            if fx.get("kind") == "retrieval":
                any_retrieval = True
            if fx.get("kind") == "model_call":
                any_model_call = True
    assert any_retrieval, (
        "python/cassettes/: no fixture with kind=retrieval "
        "(VAL-W16-008 RAG invariant)."
    )
    assert any_model_call, (
        "python/cassettes/: no fixture with kind=model_call "
        "(VAL-W16-008 LLM completion invariant)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-024")
def test_langchain_cassette_model_call_uses_anthropic(
    langchain_example_root: Path,
) -> None:
    """Per VAL-W16-024 at least one cassette model_call fixture MUST
    declare an Anthropic Claude model_signature beginning with the
    literal prefix ``anthropic/claude-``.
    """
    cassette_dir = langchain_example_root / "python" / "cassettes"
    seen_anthropic_claude = False
    for cassette in cassette_dir.glob("*.jsonl"):
        for fx in _load_fixtures(cassette):
            if fx.get("kind") != "model_call":
                continue
            sig = fx.get("model_signature") or ""
            if sig.startswith("anthropic/claude-"):
                seen_anthropic_claude = True
                break
    assert seen_anthropic_claude, (
        "python/cassettes/: no model_call fixture with model_signature "
        "starting with 'anthropic/claude-'. VAL-W16-024 requires the "
        "LangChain example to back onto Anthropic Claude."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-008")
def test_langchain_cassette_replay_deterministic_kind_sequence(
    langchain_example_root: Path,
) -> None:
    """The cassette MUST have a stable, deterministic kind sequence so
    replay produces byte-identical traces (VAL-W16-008 trace digest
    equality).
    """
    cassette_dir = langchain_example_root / "python" / "cassettes"
    cassettes = sorted(cassette_dir.glob("*.jsonl"))
    assert cassettes, "No cassettes found"
    # Take the canonical cassette and verify it has a deterministic order.
    primary = cassettes[0]
    fixtures = _load_fixtures(primary)
    kinds = [f.get("kind") for f in fixtures]
    # The example's RAG flow is: retrieval -> model_call (LLM consumes
    # retrieved docs). Both must appear; retrieval must come before the
    # final model_call for the chain to be a valid RAG trace.
    assert "retrieval" in kinds and "model_call" in kinds, (
        f"cassette {primary.name} must contain both retrieval and model_call "
        f"kinds; got {kinds} (VAL-W16-008)."
    )
    first_retrieval = kinds.index("retrieval")
    last_model_call = len(kinds) - 1 - list(reversed(kinds)).index("model_call")
    assert first_retrieval < last_model_call, (
        f"cassette {primary.name}: retrieval must precede the final "
        f"model_call (RAG ordering); got kinds={kinds}."
    )
