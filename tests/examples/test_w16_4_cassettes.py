"""Cassette / ReplayFixture validation for the MCP tool-agent example.

Covers (W16.4 primary):
  VAL-W16-014: MCP example replays from cassette -- both the LLM
               responses and the MCP server responses are captured as
               fixtures of kind ``tool_call`` and ``model_call``. Zero
               network egress, no MCP server process spawned during
               replay. Trace digest matches recorded.

Covers (W16.4 cross-cutting share):
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
def mcp_example_root() -> Path:
    return REPO_ROOT / "examples" / "mcp-tool-agent"


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
@pytest.mark.fulfills("VAL-W16-014")
def test_mcp_cassettes_exist(mcp_example_root: Path) -> None:
    """The Python language ships at least one recorded cassette."""
    cassette_dir = mcp_example_root / "python" / "cassettes"
    assert cassette_dir.is_dir(), (
        "cassettes/ directory missing under examples/mcp-tool-agent/python/"
    )
    fixtures = list(cassette_dir.glob("*.jsonl"))
    assert fixtures, (
        "python/cassettes/ must contain at least one .jsonl cassette "
        "(VAL-W16-014: replay from cassette)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-020")
def test_mcp_cassettes_have_valid_schema_version_and_refresh_policy(
    mcp_example_root: Path,
) -> None:
    """Every cassette entry parses as relay.replay_fixture.v1 with valid
    mode, provider, model, model_signature, refresh_policy, and
    side_effect_class per spec section E.2 / VAL-W16-020.
    """
    cassettes = _iter_cassettes(mcp_example_root)
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
@pytest.mark.fulfills("VAL-W16-014")
def test_mcp_cassette_contains_model_call_and_tool_call(
    mcp_example_root: Path,
) -> None:
    """Per VAL-W16-014 the cassette MUST contain both the LLM responses
    (``kind=model_call``) AND the MCP server responses (``kind=tool_call``)
    so the replayed trace exercises the MCP tool-agent flow end-to-end
    without spawning the MCP server.
    """
    cassette_dir = mcp_example_root / "python" / "cassettes"
    assert cassette_dir.is_dir(), "python/cassettes/ missing"
    any_model_call = False
    any_tool_call = False
    for cassette in cassette_dir.glob("*.jsonl"):
        for fx in _load_fixtures(cassette):
            if fx.get("kind") == "model_call":
                any_model_call = True
            if fx.get("kind") == "tool_call":
                any_tool_call = True
    assert any_model_call, (
        "python/cassettes/: no fixture with kind=model_call "
        "(VAL-W16-014: cassette captures LLM responses)."
    )
    assert any_tool_call, (
        "python/cassettes/: no fixture with kind=tool_call "
        "(VAL-W16-014: cassette captures MCP server responses)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-014")
def test_mcp_cassette_kind_sequence_is_deterministic(
    mcp_example_root: Path,
) -> None:
    """The cassette MUST have a stable, deterministic kind sequence so
    replay produces byte-identical traces (VAL-W16-014 trace digest
    equality).

    Per the MCP tool-agent flow: the model emits an MCP tool_call, the
    MCP server returns a result, and the model emits a final answer.
    The cassette sequence is model_call -> tool_call -> model_call.
    """
    cassette_dir = mcp_example_root / "python" / "cassettes"
    cassettes = sorted(cassette_dir.glob("*.jsonl"))
    assert cassettes, "No cassettes found"
    primary = cassettes[0]
    fixtures = _load_fixtures(primary)
    kinds = [f.get("kind") for f in fixtures]
    expected = ["model_call", "tool_call", "model_call"]
    assert kinds == expected, (
        f"cassette {primary.name}: kind sequence {kinds} != expected "
        f"{expected} (VAL-W16-014 MCP tool-agent flow)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-013")
def test_mcp_cassette_tool_call_carries_mcp_tool_name_form(
    mcp_example_root: Path,
) -> None:
    """Per VAL-W16-013 the tool_call span's ``tool_name`` MUST follow the
    MCP ``server.tool`` form (a fully-qualified name with a ``.``
    separator). The cassette fixture records the tool_name attribute so
    the offline replay proves the MCP-protocol invariant.
    """
    cassette_dir = mcp_example_root / "python" / "cassettes"
    cassettes = sorted(cassette_dir.glob("*.jsonl"))
    assert cassettes, "No cassettes found"
    seen_mcp_tool_name = False
    for cassette in cassettes:
        for fx in _load_fixtures(cassette):
            if fx.get("kind") != "tool_call":
                continue
            tool_name = fx.get("tool_name") or ""
            # MCP names follow ``server.tool`` form (e.g.
            # ``everything.echo``); we assert the canonical dotted
            # namespace separator is present so the cassette records the
            # MCP convention rather than a flat OpenAI-style name.
            if "." in tool_name:
                seen_mcp_tool_name = True
                break
        if seen_mcp_tool_name:
            break
    assert seen_mcp_tool_name, (
        "python/cassettes/: no tool_call fixture has a tool_name in MCP "
        "``server.tool`` form (dotted namespace). VAL-W16-013 requires the "
        "MCP example's tool_call spans to record the MCP tool name "
        "convention."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-013")
def test_mcp_cassette_tool_call_has_args_and_result_hashes(
    mcp_example_root: Path,
) -> None:
    """Per VAL-W16-013 the tool_call span MUST carry args_hash and
    result_hash so the redacted MCP-protocol envelope is bound to the
    span without persisting cleartext.
    """
    cassette_dir = mcp_example_root / "python" / "cassettes"
    cassettes = sorted(cassette_dir.glob("*.jsonl"))
    assert cassettes, "No cassettes found"
    failures: list[str] = []
    seen_tool_call = False
    for cassette in cassettes:
        for idx, fx in enumerate(_load_fixtures(cassette)):
            if fx.get("kind") != "tool_call":
                continue
            seen_tool_call = True
            ctx = f"{cassette.name}[{idx}]"
            if not fx.get("args_hash"):
                failures.append(f"{ctx}: args_hash missing")
            if not fx.get("result_hash"):
                failures.append(f"{ctx}: result_hash missing")
            # The tool_call fixture MUST carry an explicit status and
            # duration field per spec B.1 tool-call flight recorder.
            if "status" not in fx:
                failures.append(f"{ctx}: status missing")
            if "duration_ms" not in fx:
                failures.append(f"{ctx}: duration_ms missing")
            # Side-effect marker per spec B.1 (false for read-only).
            if "side_effect_marker" not in fx:
                failures.append(f"{ctx}: side_effect_marker missing")
    assert seen_tool_call, (
        "No tool_call fixture found in the MCP cassette; VAL-W16-013 "
        "requires at least one MCP-protocol tool_call."
    )
    assert not failures, (
        "tool_call field-coverage failures (VAL-W16-013):\n"
        + "\n".join(failures)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-013")
def test_mcp_cassette_tool_call_provider_is_mcp(
    mcp_example_root: Path,
) -> None:
    """Per VAL-W16-013 the MCP tool_call fixture's provider field MUST
    identify the MCP transport (``mcp`` or ``mcp:<server-id>``) so the
    cassette can be audited as an MCP-protocol capture.
    """
    cassette_dir = mcp_example_root / "python" / "cassettes"
    cassettes = sorted(cassette_dir.glob("*.jsonl"))
    assert cassettes, "No cassettes found"
    seen_mcp_provider = False
    for cassette in cassettes:
        for fx in _load_fixtures(cassette):
            if fx.get("kind") != "tool_call":
                continue
            provider = (fx.get("provider") or "").lower()
            if provider == "mcp" or provider.startswith("mcp:") or provider.startswith("mcp/"):
                seen_mcp_provider = True
                break
        if seen_mcp_provider:
            break
    assert seen_mcp_provider, (
        "python/cassettes/: no tool_call fixture has provider in the MCP "
        "form (``mcp`` or ``mcp:<server>``). VAL-W16-013 requires the "
        "cassette to identify the MCP transport for audit."
    )
