"""Cassette / ReplayFixture validation for the OpenAI tool-agent example.

Covers:
  VAL-W16-004: replays from cassette (recorded cassettes parse + load
               without errors; egress assertion deferred to harness).
  VAL-W16-020: ReplayFixtures carry valid schema_version, mode,
               provider, model, model_signature, and refresh_policy
               from the spec section E.2 enumerated set.

Tier-1 plumbing: parses JSONL cassettes on disk, validates each entry
against the codegen-produced Pydantic ReplayFixture model.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Refresh policies per spec E.2 (envelopes.yaml lines 502-510).
VALID_REFRESH_POLICIES: frozenset[str] = frozenset(
    {
        "invalidate_on_signature_change",
        "hold_forever",
        "refresh_weekly",
        "invalidate_on_model_version_change",
    }
)

VALID_MODES: frozenset[str] = frozenset(
    {"cassette", "live", "degraded_live", "mock"}
)

VALID_SIDE_EFFECT_CLASSES: frozenset[str] = frozenset(
    {"read_only", "mutating", "external_irreversible", "approval_required"}
)


def _iter_cassettes(example_root: Path) -> list[Path]:
    """Yield every .jsonl cassette file under either language's cassettes/."""
    out: list[Path] = []
    for lang in ("python", "typescript"):
        cassette_dir = example_root / lang / "cassettes"
        if not cassette_dir.is_dir():
            continue
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
@pytest.mark.fulfills("VAL-W16-004")
def test_openai_cassettes_exist(example_root: Path) -> None:
    """Each language ships at least one recorded cassette under cassettes/."""
    for lang in ("python", "typescript"):
        cassette_dir = example_root / lang / "cassettes"
        assert cassette_dir.is_dir(), (
            f"cassettes/ directory missing under {lang}/"
        )
        fixtures = list(cassette_dir.glob("*.jsonl"))
        assert fixtures, (
            f"{lang}/cassettes/ must contain at least one .jsonl cassette "
            "(VAL-W16-004: replay from cassette)."
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-020")
def test_openai_cassettes_have_valid_schema_version_and_refresh_policy(
    example_root: Path,
) -> None:
    """Every cassette entry parses as relay.replay_fixture.v1 with valid
    mode, provider, model, model_signature, refresh_policy, and
    side_effect_class per spec section E.2 / VAL-W16-020.
    """
    cassettes = _iter_cassettes(example_root)
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
            rp = fx.get("refresh_policy", "invalidate_on_signature_change")
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
    assert not failures, "Cassette validation failures:\n" + "\n".join(failures)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-004")
def test_openai_cassette_contains_model_call_and_tool_call(
    example_root: Path,
) -> None:
    """At least one cassette in each language contains both a model_call
    and a tool_call fixture (VAL-W16-001 reconciliation: example is by
    name a tool-agent and the cassette MUST exercise a tool call).
    """
    for lang in ("python", "typescript"):
        cassette_dir = example_root / lang / "cassettes"
        if not cassette_dir.is_dir():
            continue
        any_model_call = False
        any_tool_call = False
        for cassette in cassette_dir.glob("*.jsonl"):
            for fx in _load_fixtures(cassette):
                if fx.get("kind") == "model_call":
                    any_model_call = True
                if fx.get("kind") == "tool_call":
                    any_tool_call = True
        assert any_model_call, (
            f"{lang}/cassettes/: no fixture with kind=model_call "
            "(VAL-W16-001 tool-agent invariant)"
        )
        assert any_tool_call, (
            f"{lang}/cassettes/: no fixture with kind=tool_call "
            "(VAL-W16-001 tool-agent invariant)"
        )
