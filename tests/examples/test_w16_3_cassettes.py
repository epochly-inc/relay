"""Cassette / ReplayFixture validation for the Vercel AI tool-agent example.

Covers:
  VAL-W16-012: Vercel AI example replays from cassette (recorded
               cassettes parse + load without errors; the cassette
               carries model_call -> tool_call -> model_call so the
               trace digest is reproducible).
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
def vercel_example_root() -> Path:
    return REPO_ROOT / "examples" / "vercel-ai-tool-agent"


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
    """Yield every .jsonl cassette file under typescript/cassettes/."""
    out: list[Path] = []
    cassette_dir = example_root / "typescript" / "cassettes"
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
@pytest.mark.fulfills("VAL-W16-012")
def test_vercel_cassettes_exist(vercel_example_root: Path) -> None:
    """The TS example ships at least one recorded cassette."""
    cassette_dir = vercel_example_root / "typescript" / "cassettes"
    assert cassette_dir.is_dir(), (
        "cassettes/ directory missing under examples/vercel-ai-tool-agent/typescript/"
    )
    fixtures = list(cassette_dir.glob("*.jsonl"))
    assert fixtures, (
        "typescript/cassettes/ must contain at least one .jsonl cassette "
        "(VAL-W16-012: replay from cassette)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-020")
def test_vercel_cassettes_have_valid_schema_version_and_refresh_policy(
    vercel_example_root: Path,
) -> None:
    """Every cassette entry parses as relay.replay_fixture.v1 with valid
    mode, provider, model, model_signature, refresh_policy, and
    side_effect_class per spec section E.2 / VAL-W16-020.
    """
    cassettes = _iter_cassettes(vercel_example_root)
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
@pytest.mark.fulfills("VAL-W16-012")
def test_vercel_cassette_contains_model_call_and_tool_call(
    vercel_example_root: Path,
) -> None:
    """Per VAL-W16-010 (tool_call span field coverage) + VAL-W16-012
    (cassette replay): the cassette MUST contain at least one
    ``kind=model_call`` fixture and at least one ``kind=tool_call``
    fixture so the replayed trace exercises the tool-agent flow
    end-to-end.
    """
    cassette_dir = vercel_example_root / "typescript" / "cassettes"
    assert cassette_dir.is_dir(), "typescript/cassettes/ missing"
    any_model_call = False
    any_tool_call = False
    for cassette in cassette_dir.glob("*.jsonl"):
        for fx in _load_fixtures(cassette):
            if fx.get("kind") == "model_call":
                any_model_call = True
            if fx.get("kind") == "tool_call":
                any_tool_call = True
    assert any_model_call, (
        "typescript/cassettes/: no fixture with kind=model_call "
        "(VAL-W16-010 tool-agent invariant)."
    )
    assert any_tool_call, (
        "typescript/cassettes/: no fixture with kind=tool_call "
        "(VAL-W16-010 tool-agent invariant)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-012")
def test_vercel_cassette_kind_sequence_is_deterministic(
    vercel_example_root: Path,
) -> None:
    """The cassette MUST have a stable, deterministic kind sequence so
    replay produces byte-identical traces (VAL-W16-012 trace digest
    equality).

    Per the tool-agent flow: the model emits a tool_call, the tool
    returns a result, and the model emits a final answer. The cassette
    sequence is model_call -> tool_call -> model_call.
    """
    cassette_dir = vercel_example_root / "typescript" / "cassettes"
    cassettes = sorted(cassette_dir.glob("*.jsonl"))
    assert cassettes, "No cassettes found"
    primary = cassettes[0]
    fixtures = _load_fixtures(primary)
    kinds = [f.get("kind") for f in fixtures]
    expected = ["model_call", "tool_call", "model_call"]
    assert kinds == expected, (
        f"cassette {primary.name}: kind sequence {kinds} != expected "
        f"{expected} (VAL-W16-012 tool-agent flow)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-011")
def test_vercel_cassette_carries_otel_parent_child_link(
    vercel_example_root: Path,
) -> None:
    """Per VAL-W16-011 (OpenTelemetry trace continuity): the cassette
    fixtures MUST establish a parent/child span graph -- the tool_call
    fixture MUST reference its parent model_call's span_id (via
    parent_span_id), and the second model_call MUST follow the tool_call.

    This is the offline-replay analogue of the spec section B.1
    completeness checker. The cassette records the span graph so replay
    can prove trace continuity without re-invoking the live SDK.
    """
    cassette_dir = vercel_example_root / "typescript" / "cassettes"
    cassettes = sorted(cassette_dir.glob("*.jsonl"))
    assert cassettes, "No cassettes found"
    primary = cassettes[0]
    fixtures = _load_fixtures(primary)
    # Every fixture must declare its source_span_id (per spec E.2 the
    # ReplayFixture envelope binds to the span that produced it).
    for idx, fx in enumerate(fixtures):
        assert fx.get("source_span_id"), (
            f"fixture[{idx}]: source_span_id missing "
            "(VAL-W16-011 span continuity requires per-fixture span_id)."
        )
    # The tool_call fixture MUST carry parent_span_id pointing at the
    # first model_call's source_span_id.
    first_model = next(fx for fx in fixtures if fx.get("kind") == "model_call")
    tool_call = next(fx for fx in fixtures if fx.get("kind") == "tool_call")
    parent_id = tool_call.get("parent_span_id")
    assert parent_id, (
        "tool_call fixture missing parent_span_id (VAL-W16-011 trace continuity)."
    )
    assert parent_id == first_model["source_span_id"], (
        f"tool_call.parent_span_id={parent_id!r} does not equal first "
        f"model_call.source_span_id={first_model['source_span_id']!r} "
        "(VAL-W16-011 trace continuity)."
    )
