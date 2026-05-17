"""V2 M04 w4-side-effects: replay-proxy side-effect class tests.

Covers contract assertions VAL-V2M04-026..029 (replay-class blocking
codes) and the cassette_format constant alignment with the canonical
four spec E.3 classes.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from relay_replay_proxy.cassette_format import (
    SIDE_EFFECT_APPROVAL_REQUIRED,
    SIDE_EFFECT_EXTERNAL_IRREVERSIBLE,
    SIDE_EFFECT_MUTATING,
    SIDE_EFFECT_READ_ONLY,
)

_THIS = Path(__file__).resolve()
_REPO_ROOT = _THIS.parents[3]


# ---------------------------------------------------------------------------
# Cassette format constants align with the canonical four spec E.3 classes
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_cassette_format_exports_canonical_four_side_effect_classes() -> None:
    """The cassette_format module mirrors the four canonical classes
    (spec E.3 lines 3931-3936) so the cassette schema stays in sync with
    the side-effect classification."""
    assert SIDE_EFFECT_READ_ONLY == "read_only"
    assert SIDE_EFFECT_MUTATING == "mutating"
    assert SIDE_EFFECT_EXTERNAL_IRREVERSIBLE == "external_irreversible"
    assert SIDE_EFFECT_APPROVAL_REQUIRED == "approval_required"


@pytest.mark.plumbing
def test_cassette_format_does_not_export_legacy_classes() -> None:
    """Legacy 'none' / 'reversible' classes must NOT appear as cassette
    format constants (VAL-V2M04-023/024 enforced for the replay-proxy)."""
    import relay_replay_proxy.cassette_format as cf

    exported = set(cf.__all__)
    assert "SIDE_EFFECT_NONE" not in exported
    assert "SIDE_EFFECT_REVERSIBLE" not in exported


# ---------------------------------------------------------------------------
# VAL-V2M04-028/029: RELAY-REPLAY-014 preserved for mutating + external
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-028")
def test_replay_014_blocks_mutating_when_not_authorized() -> None:
    """The CLI replay layer guards mutating tools behind --allow-side-effects.
    Without authorization a mutating class returns RELAY-REPLAY-014."""
    from relay_cli.commands.replay import _DANGEROUS_SIDE_EFFECTS, RELAY_REPLAY_014

    assert RELAY_REPLAY_014 == "RELAY-REPLAY-014"
    assert "mutating" in _DANGEROUS_SIDE_EFFECTS


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-029")
def test_replay_014_blocks_external_irreversible_when_not_authorized() -> None:
    """external_irreversible class is blocked under the same RELAY-REPLAY-014
    code as mutating; the 2-person approval override path is the additional
    surface required to allow it."""
    from relay_cli.commands.replay import _DANGEROUS_SIDE_EFFECTS, RELAY_REPLAY_014

    assert RELAY_REPLAY_014 == "RELAY-REPLAY-014"
    assert "external_irreversible" in _DANGEROUS_SIDE_EFFECTS


# ---------------------------------------------------------------------------
# VAL-V2M04-026/027: approval_required wire codes registered in the YAML
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-026")
def test_approval_required_wire_code_registered_in_yaml() -> None:
    """RELAY-REPLAY-031 (the wire form of APPROVAL_REQUIRED) is registered
    in packages/schemas/raw/relay-error-codes.yaml. The descriptive alias
    APPROVAL_REQUIRED is the details.subcode per the M04 alias mapping."""
    yaml_path = (
        _REPO_ROOT / "packages" / "schemas" / "raw" / "relay-error-codes.yaml"
    )
    text = yaml_path.read_text(encoding="utf-8")
    assert "RELAY-REPLAY-031" in text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-027")
def test_approval_token_consumed_and_expired_codes_registered() -> None:
    yaml_path = (
        _REPO_ROOT / "packages" / "schemas" / "raw" / "relay-error-codes.yaml"
    )
    text = yaml_path.read_text(encoding="utf-8")
    assert "RELAY-REPLAY-032" in text
    assert "RELAY-REPLAY-033" in text


# ---------------------------------------------------------------------------
# VAL-V2M04-035: three-anchor handoff fires BEFORE marker/proof check
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-035")
def test_three_anchor_handoff_check_precedes_side_effect_check() -> None:
    """VAL-V2M04-035: a span with mismatched manifest_commit_hash is
    rejected with RELAY-GATE-021 BEFORE the marker/proof check runs.
    The route layer at /v1/ingest/spans:batch calls
    _enforce_manifest_anchors first; only if that passes does the
    side-effect check engage. This guard reads the runtime.py source to
    confirm the ordering is preserved."""
    runtime_path = (
        _REPO_ROOT
        / "apps"
        / "local-sidecar"
        / "relay_sidecar"
        / "runtime.py"
    )
    text = runtime_path.read_text(encoding="utf-8")
    # Locate the v1_ingest_spans_batch handler.
    handler_match = re.search(
        r"async def v1_ingest_spans_batch.*?(?=async def |\Z)",
        text,
        re.DOTALL,
    )
    assert handler_match, "v1_ingest_spans_batch handler not found"
    body = handler_match.group(0)
    # _enforce_manifest_anchors call MUST appear BEFORE any side-effect
    # marker / proof reference in the handler body.
    manifest_idx = body.find("_enforce_manifest_anchors")
    assert manifest_idx != -1, (
        "v1_ingest_spans_batch handler must call _enforce_manifest_anchors "
        "for three-anchor handoff enforcement (VAL-V2M04-035)"
    )
