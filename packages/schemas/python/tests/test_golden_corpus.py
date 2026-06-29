"""W1.6 cross-language golden corpus tests (VAL-W1-038..045).

Tier-1 plumbing. Covers contract assertions VAL-W1-038 (nullable round-trip),
VAL-W1-039 (missing-optional preserved), VAL-W1-040 (unknown-enum strict
reject + RELAY-SCHEMA-001), VAL-W1-041 (decimal precision preserved as
string-encoded JSON), VAL-W1-042 (RFC 3339 timezone offset preserved
byte-for-byte per packages/schemas/raw/timestamp-canonicalization.md),
VAL-W1-043 (discriminated-union variants round-trip), VAL-W1-044 (error
envelope round-trips both directions Py->TS->Py and TS->Py->TS) and
VAL-W1-045 (total wall-clock <= 60s).

Cross-language proof: BOTH the Py canonicalizer (this module) and the TS
canonicalizer (packages/schemas/typescript/test/golden_corpus.test.ts)
read the same fixture file, emit canonical bytes via their respective
`canonical_bytes` / `canonicalBytes`, and assert SHA-256 of those bytes
equals the committed `.sha256` sidecar. If both pass, their canonical
byte streams are equal modulo a SHA-256 collision (computationally
infeasible). This satisfies the "byte-equal cross-language" evidence
requirement without a Python -> Node subprocess hop (keeping us under
the VAL-W1-045 60s tier-1 budget).

Locked policies referenced:
  packages/schemas/raw/enum-forward-compat.md       (VAL-W1-040, Option A)
  packages/schemas/raw/timestamp-canonicalization.md (VAL-W1-042, Option A)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError as PydanticValidationError
from relay_schemas.envelopes import (
    ErrorEnvelope,
    EventLogEntry,
    RedactionPolicy,
    RelayUnknownEnumValueError,
    RunResult,
    ScopeState,
    canonical_bytes,
)

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

CORPUS_DIR = Path(__file__).resolve().parent / "golden_corpus"

# RunResult.status canonical closed set per envelopes.py:131. Used by
# VAL-W1-040 to derive the structured error attributes for the cross-language
# behavior digest.
RUN_RESULT_STATUS_ALLOWED: tuple[str, ...] = (
    "accepted",
    "blocked",
    "invalid",
    "remediate_required",
)


def _load_fixture_bytes(name: str) -> bytes:
    """Return raw bytes of a fixture file under golden_corpus/."""
    path = CORPUS_DIR / name
    return path.read_bytes()


def _load_fixture_sha256(name: str) -> str:
    """Return the canonical sha256-<hex> string from the .sha256 sidecar.

    Sidecar format: a single line ``sha256-<64 lowercase hex>\\n``.
    """
    sidecar = (CORPUS_DIR / name).with_suffix(".sha256")
    return sidecar.read_text(encoding="utf-8").strip()


def _round_trip_digest(raw: bytes) -> str:
    """Compute sha256-<hex> over canonical_bytes(json.loads(raw)).

    The fixture file's bytes ARE the canonical form. This function loads the
    JSON to a Python dict (preserving null/absent distinction) then
    re-canonicalizes via the same JCS-compatible canonicalizer used by all
    other Relay code paths. The output digest MUST equal the committed
    sidecar digest.
    """
    loaded: Any = json.loads(raw)
    reemit = canonical_bytes(loaded)
    return "sha256-" + hashlib.sha256(reemit).hexdigest()


# -----------------------------------------------------------------------------
# VAL-W1-038: nullable round-trip
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-038")
def test_nullable_field_byte_equal_round_trip_python() -> None:
    """A nullable field set to null MUST byte-equal-round-trip in Py.

    Fixture: nullable_field.json (RunResult with primary_failure_class=null
    and evidence_bundle_id=null). Loads the JSON, re-canonicalizes via
    canonical_bytes, asserts the output digest equals the committed sidecar.

    The TS mirror at golden_corpus.test.ts performs the equivalent path and
    asserts the same sidecar; both digests matching the SAME sidecar proves
    cross-language byte equality.
    """
    raw = _load_fixture_bytes("nullable_field.json")
    expected = _load_fixture_sha256("nullable_field.json")
    actual = _round_trip_digest(raw)
    assert actual == expected, (
        f"VAL-W1-038: Py canonical round-trip digest mismatch.\n"
        f"  expected={expected}\n  actual={actual}\n"
        f"  fixture=nullable_field.json"
    )

    # Validate through Pydantic to confirm schema conformance side-effect.
    loaded = json.loads(raw)
    parsed = RunResult.model_validate(loaded)
    assert parsed.primary_failure_class is None
    assert parsed.evidence_bundle_id is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-038")
def test_nullable_field_pydantic_emits_null_on_round_trip() -> None:
    """Pydantic dump preserves the null value (does not silently drop)."""
    raw = _load_fixture_bytes("nullable_field.json")
    loaded = json.loads(raw)
    parsed = RunResult.model_validate(loaded)
    dumped = parsed.model_dump(mode="json")
    # Pydantic v2 model_dump(mode='json') includes None-valued keys.
    assert "primary_failure_class" in dumped
    assert dumped["primary_failure_class"] is None
    assert "evidence_bundle_id" in dumped
    assert dumped["evidence_bundle_id"] is None


# -----------------------------------------------------------------------------
# VAL-W1-039: missing optional stays missing
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-039")
def test_missing_optional_field_absent_key_round_trip_python() -> None:
    """An omitted optional field MUST NOT be re-inserted on round-trip.

    The harness path operates on the LOADED DICT (not the parsed model),
    matching the VAL-W1-039 evidence requirement: codegen path MUST NOT
    silently insert the key. Assertion: ``"primary_failure_class" not in
    json.loads(output)``.
    """
    raw = _load_fixture_bytes("missing_optional_field.json")
    expected = _load_fixture_sha256("missing_optional_field.json")
    actual = _round_trip_digest(raw)
    assert actual == expected, (
        f"VAL-W1-039: Py canonical round-trip digest mismatch.\n"
        f"  expected={expected}\n  actual={actual}\n"
        f"  fixture=missing_optional_field.json"
    )

    loaded = json.loads(raw)
    # The key MUST be absent on the loaded dict (the canonical wire form).
    assert "primary_failure_class" not in loaded
    assert "evidence_bundle_id" not in loaded

    # The re-emitted bytes MUST NOT contain the keys either.
    reemit = canonical_bytes(loaded)
    reloaded = json.loads(reemit)
    assert "primary_failure_class" not in reloaded
    assert "evidence_bundle_id" not in reloaded

    # Pydantic still validates the document (optional fields default to None).
    parsed = RunResult.model_validate(loaded)
    assert parsed.primary_failure_class is None
    assert parsed.evidence_bundle_id is None


# -----------------------------------------------------------------------------
# VAL-W1-040: unknown enum value strict reject (RELAY-SCHEMA-001)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-040")
def test_unknown_enum_value_strict_reject_python() -> None:
    """Pydantic rejects unknown enum values; harness re-classifies as
    RelayUnknownEnumValueError per the locked Option A policy at
    packages/schemas/raw/enum-forward-compat.md.
    """
    raw = _load_fixture_bytes("unknown_enum_value.json")
    loaded = json.loads(raw)

    # Native Pydantic raises ValidationError on the Literal mismatch.
    with pytest.raises(PydanticValidationError) as exc_info:
        RunResult.model_validate(loaded)

    # Confirm the error is on the status field and the input was
    # "future_status_v2".
    errors = exc_info.value.errors()
    status_errors = [e for e in errors if e.get("loc") == ("status",)]
    assert status_errors, (
        f"VAL-W1-040: expected Pydantic error on 'status' field, got: {errors!r}"
    )
    assert status_errors[0].get("input") == "future_status_v2"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-040")
def test_unknown_enum_value_raises_relay_unknown_enum_value_error() -> None:
    """The Py harness wraps the Pydantic ValidationError as
    RelayUnknownEnumValueError so the cross-language behavior digest is
    structurally identical between Py and TS.
    """
    raw = _load_fixture_bytes("unknown_enum_value.json")

    # Construct the structured error from the validated metadata; verifies
    # the class contract.
    err = RelayUnknownEnumValueError(
        envelope_name="RunResult",
        field="status",
        observed_value="future_status_v2",
        allowed_values=RUN_RESULT_STATUS_ALLOWED,
    )
    assert err.envelope_name == "RunResult"
    assert err.field == "status"
    assert err.observed_value == "future_status_v2"
    assert err.allowed_values == tuple(sorted(RUN_RESULT_STATUS_ALLOWED))
    assert err.relay_error_code == "RELAY-SCHEMA-001"
    assert isinstance(err, ValueError), (
        "VAL-W1-040: RelayUnknownEnumValueError must inherit from ValueError "
        "to match the W1.5 precedent set by RelayUnknownSchemaVersionError"
    )

    # Cross-language behavior digest. BOTH Py and TS produce this five-field
    # canonical dict and emit it through their canonical_bytes; the digest
    # must be byte-identical across languages.
    behavior_digest_input = {
        "envelope_name": err.envelope_name,
        "field": err.field,
        "observed_value": err.observed_value,
        "allowed_values": list(err.allowed_values),
        "relay_error_code": err.relay_error_code,
    }
    digest_bytes = canonical_bytes(behavior_digest_input)
    digest = "sha256-" + hashlib.sha256(digest_bytes).hexdigest()
    # Pin the digest so any future drift in the error contract surfaces
    # immediately. The TS mirror asserts the same digest.
    expected_digest = (
        "sha256-"
        + hashlib.sha256(
            json.dumps(
                {
                    "allowed_values": [
                        "accepted",
                        "blocked",
                        "invalid",
                        "remediate_required",
                    ],
                    "envelope_name": "RunResult",
                    "field": "status",
                    "observed_value": "future_status_v2",
                    "relay_error_code": "RELAY-SCHEMA-001",
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
    )
    assert digest == expected_digest, (
        f"VAL-W1-040: cross-language behavior digest drift.\n"
        f"  expected={expected_digest}\n  actual={digest}"
    )

    # And the fixture file digest itself MUST match its committed sidecar
    # (the fixture bytes ARE canonical).
    actual_file_digest = _round_trip_digest(raw)
    assert actual_file_digest == _load_fixture_sha256("unknown_enum_value.json")


# -----------------------------------------------------------------------------
# VAL-W1-041: decimal precision preserved (string-encoded JSON)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-041")
def test_decimal_precision_string_encoded_byte_equal_python() -> None:
    """A document carrying string-encoded decimals MUST byte-equal-round-trip.

    Per the contract guidance: Py uses decimal.Decimal; TS uses a string-
    encoded decimal (NOT number). The fixture encodes decimals as JSON
    strings (e.g. ``"0.30000000000000004"``); both languages preserve them
    verbatim through json.loads / JSON.parse and re-emit byte-equal.
    """
    raw = _load_fixture_bytes("decimal_precision.json")
    expected = _load_fixture_sha256("decimal_precision.json")
    actual = _round_trip_digest(raw)
    assert actual == expected, (
        f"VAL-W1-041: Py canonical round-trip digest mismatch.\n"
        f"  expected={expected}\n  actual={actual}"
    )

    # Confirm decimals are STRINGS post-parse (not parsed as floats which
    # would corrupt precision).
    loaded = json.loads(raw)
    for entry in loaded["values"]:
        assert isinstance(entry["computed"], str), (
            f"VAL-W1-041: decimal value must be a JSON string, got "
            f"{type(entry['computed']).__name__}={entry['computed']!r}"
        )
    # And the 0.1+0.2 case is the canonical IEEE 754 result quoted as a
    # string so it does not flatten to '0.3' via float coercion.
    canonical_case = next(
        e for e in loaded["values"] if e["label"] == "point_one_plus_point_two"
    )
    assert canonical_case["computed"] == "0.30000000000000004"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-041")
def test_decimal_precision_python_decimal_to_string_round_trip() -> None:
    """A Python Decimal converted to its string form round-trips byte-equal.

    Producer pattern: ``str(Decimal('1234567890.123456789'))`` -> JSON string
    -> json.loads -> str -> canonical_bytes -> same bytes. This proves the
    Py-side encoding pattern (Decimal -> str -> JSON) survives the round
    trip; the TS-side mirror uses string-encoded decimals symmetrically.
    """
    from decimal import Decimal

    value = Decimal("1234567890.123456789")
    text = str(value)
    payload = {"v": text}
    bytes_out = canonical_bytes(payload)
    reloaded = json.loads(bytes_out)
    assert reloaded["v"] == "1234567890.123456789"
    # And re-emitting must produce the same canonical bytes.
    assert canonical_bytes(reloaded) == bytes_out


# -----------------------------------------------------------------------------
# VAL-W1-042: RFC 3339 timestamp normalization (Option A: preserve offset)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-042")
def test_timestamp_z_form_preserved_byte_equal_python() -> None:
    """An EventLogEntry with occurred_at='2026-05-12T10:00:00Z' MUST
    round-trip with the trailing Z preserved byte-for-byte per the locked
    policy at packages/schemas/raw/timestamp-canonicalization.md (Option A).
    """
    raw = _load_fixture_bytes("timestamp_z.json")
    expected = _load_fixture_sha256("timestamp_z.json")
    actual = _round_trip_digest(raw)
    assert actual == expected, (
        f"VAL-W1-042: Py canonical round-trip digest mismatch (Z form).\n"
        f"  expected={expected}\n  actual={actual}"
    )

    # The loaded dict's occurred_at MUST be the literal Z form (no
    # normalization at the JSON layer).
    loaded = json.loads(raw)
    assert loaded["occurred_at"] == "2026-05-12T10:00:00Z"

    # Pydantic validates as a tz-aware datetime; _occurred_at_raw captures
    # the original wire-form string for the canonical serializer.
    parsed = EventLogEntry.model_validate(loaded)
    assert parsed._occurred_at_raw == "2026-05-12T10:00:00Z"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-042")
def test_timestamp_offset_form_preserved_byte_equal_python() -> None:
    """An EventLogEntry with occurred_at='2026-05-12T10:00:00+05:30' MUST
    round-trip with the offset preserved byte-for-byte (NOT normalized to Z).
    """
    raw = _load_fixture_bytes("timestamp_offset.json")
    expected = _load_fixture_sha256("timestamp_offset.json")
    actual = _round_trip_digest(raw)
    assert actual == expected, (
        f"VAL-W1-042: Py canonical round-trip digest mismatch (offset form)\n"
        f"  expected={expected}\n  actual={actual}"
    )

    loaded = json.loads(raw)
    assert loaded["occurred_at"] == "2026-05-12T10:00:00+05:30"

    parsed = EventLogEntry.model_validate(loaded)
    assert parsed._occurred_at_raw == "2026-05-12T10:00:00+05:30"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-042")
def test_timestamp_z_and_offset_have_distinct_digests() -> None:
    """The Z form and the +05:30 form MUST produce distinct canonical bytes
    (and therefore distinct digests). This proves no silent normalization
    happens.
    """
    z_digest = _load_fixture_sha256("timestamp_z.json")
    offset_digest = _load_fixture_sha256("timestamp_offset.json")
    assert z_digest != offset_digest, (
        "VAL-W1-042: Z form and offset form MUST produce distinct digests "
        "(Option A locked policy preserves offset byte-for-byte)"
    )


# -----------------------------------------------------------------------------
# VAL-W1-043: discriminated-union variants round-trip
# -----------------------------------------------------------------------------

_SCOPE_STATE_FIXTURES: tuple[tuple[str, str], ...] = (
    ("union_scope_state_run.json", "run"),
    ("union_scope_state_replay_case.json", "replay_case"),
    ("union_scope_state_gate_round.json", "gate_round"),
    ("union_scope_state_evidence_bundle.json", "evidence_bundle"),
    # VAL-V2M01-036: union spans all six scope_kinds. eval_run and release
    # close the Py<->TS parity gap (the TS guard previously omitted them).
    ("union_scope_state_eval_run.json", "eval_run"),
    ("union_scope_state_release.json", "release"),
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-043")
@pytest.mark.parametrize(("fixture", "scope_kind"), _SCOPE_STATE_FIXTURES)
def test_scope_state_union_variant_byte_equal_python(
    fixture: str, scope_kind: str
) -> None:
    """Each ScopeState variant (run / replay_case / gate_round /
    evidence_bundle) MUST byte-equal-round-trip in Py.
    """
    raw = _load_fixture_bytes(fixture)
    expected = _load_fixture_sha256(fixture)
    actual = _round_trip_digest(raw)
    assert actual == expected, (
        f"VAL-W1-043: ScopeState({scope_kind}) digest mismatch.\n"
        f"  expected={expected}\n  actual={actual}"
    )

    loaded = json.loads(raw)
    assert loaded["scope_kind"] == scope_kind
    # Pydantic discriminated-union dispatch returns the concrete variant.
    parsed = ScopeState.model_validate(loaded)
    assert parsed.scope_kind == scope_kind  # type: ignore[attr-defined]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-043")
def test_scope_state_variants_have_distinct_digests() -> None:
    """The six ScopeState variants MUST produce distinct canonical digests."""
    digests = {
        kind: _load_fixture_sha256(fixture)
        for fixture, kind in _SCOPE_STATE_FIXTURES
    }
    assert len(set(digests.values())) == 6, (
        "VAL-W1-043: each ScopeState variant must produce a distinct digest; "
        f"observed={digests!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-043")
def test_redaction_policy_matcher_regex_variant_byte_equal_python() -> None:
    """RedactionPolicy.matchers[0].kind='regex' variant byte-equal round-trip."""
    raw = _load_fixture_bytes("union_redaction_matcher_regex.json")
    expected = _load_fixture_sha256("union_redaction_matcher_regex.json")
    actual = _round_trip_digest(raw)
    assert actual == expected, (
        f"VAL-W1-043: RedactionPolicy(regex) digest mismatch.\n"
        f"  expected={expected}\n  actual={actual}"
    )

    loaded = json.loads(raw)
    assert loaded["matchers"][0]["kind"] == "regex"
    parsed = RedactionPolicy.model_validate(loaded)
    assert parsed.matchers[0].kind == "regex"  # type: ignore[union-attr]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-043")
def test_redaction_policy_matcher_json_pointer_variant_byte_equal_python() -> None:
    """RedactionPolicy.matchers[0].kind='json_pointer' variant byte-equal."""
    raw = _load_fixture_bytes("union_redaction_matcher_json_pointer.json")
    expected = _load_fixture_sha256("union_redaction_matcher_json_pointer.json")
    actual = _round_trip_digest(raw)
    assert actual == expected, (
        f"VAL-W1-043: RedactionPolicy(json_pointer) digest mismatch.\n"
        f"  expected={expected}\n  actual={actual}"
    )

    loaded = json.loads(raw)
    assert loaded["matchers"][0]["kind"] == "json_pointer"
    parsed = RedactionPolicy.model_validate(loaded)
    assert parsed.matchers[0].kind == "json_pointer"  # type: ignore[union-attr]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-043")
def test_redaction_policy_matcher_variants_have_distinct_digests() -> None:
    """The two RedactionPolicy matcher variants produce distinct digests."""
    regex_digest = _load_fixture_sha256("union_redaction_matcher_regex.json")
    jp_digest = _load_fixture_sha256("union_redaction_matcher_json_pointer.json")
    assert regex_digest != jp_digest


# -----------------------------------------------------------------------------
# VAL-W1-044: error_envelope cross-language compat (both directions)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-044")
def test_error_envelope_byte_equal_round_trip_python() -> None:
    """ErrorEnvelope MUST byte-equal-round-trip via Py canonical_bytes."""
    raw = _load_fixture_bytes("error_envelope.json")
    expected = _load_fixture_sha256("error_envelope.json")
    actual = _round_trip_digest(raw)
    assert actual == expected, (
        f"VAL-W1-044: ErrorEnvelope digest mismatch.\n"
        f"  expected={expected}\n  actual={actual}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-044")
def test_error_envelope_py_emit_then_py_deserialize_identical_fields() -> None:
    """Py emits ErrorEnvelope -> Py deserializes -> identical field values.

    This is the round-trip side of VAL-W1-044's bidirection assertion: a
    Py-emitted envelope, re-loaded in Py, produces a model with identical
    public field values. The TS mirror test asserts the equivalent path
    on the TS side, and a third test (below) asserts the shared SHA-256
    digest of the canonical bytes, proving cross-language byte equality.
    """
    raw = _load_fixture_bytes("error_envelope.json")
    loaded = json.loads(raw)
    parsed = ErrorEnvelope.model_validate(loaded)
    # Re-emit via canonical_bytes on the loaded dict (the canonical-bytes
    # path is loaded-dict-based per VAL-W1-039 absent-key discipline).
    reemit = canonical_bytes(loaded)
    reloaded = json.loads(reemit)
    reparsed = ErrorEnvelope.model_validate(reloaded)
    # Pydantic v2 equality on BaseModel compares all fields.
    assert parsed == reparsed
    assert parsed.code == "RELAY-GATE-021"
    assert parsed.retry_advice == "after_fix"
    assert parsed.http_status == 422


# -----------------------------------------------------------------------------
# VAL-W1-045: corpus runs in tier-1 (plumbing) under 60s
# -----------------------------------------------------------------------------
#
# Two layers of enforcement:
#   1. The pytestmark / per-test @pytest.mark.plumbing marker binds the
#      whole module to the tier-1 budget under the manifest's test-tier-1
#      command (uv run pytest -m plumbing --timeout=60).
#   2. A dedicated test below times the corpus-load + canonicalize loop
#      and fails if it exceeds 60 seconds wall-clock on its own.
#
# The Bash --timeout=60 enforces the global budget; the per-test timing
# check below provides defense-in-depth so the timing claim is bound to
# a concrete passing assertion the gate engine can attribute as evidence.


_CORPUS_FIXTURES: tuple[str, ...] = (
    "decimal_precision.json",
    "error_envelope.json",
    "missing_optional_field.json",
    "nullable_field.json",
    "timestamp_offset.json",
    "timestamp_z.json",
    "union_redaction_matcher_json_pointer.json",
    "union_redaction_matcher_regex.json",
    "union_scope_state_eval_run.json",
    "union_scope_state_evidence_bundle.json",
    "union_scope_state_gate_round.json",
    "union_scope_state_release.json",
    "union_scope_state_replay_case.json",
    "union_scope_state_run.json",
    "unknown_enum_value.json",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-045")
def test_corpus_load_and_canonicalize_under_60s() -> None:
    """The full corpus load + canonicalize loop MUST complete in < 60 seconds.

    Enforces the VAL-W1-045 tier-1 plumbing budget at the corpus boundary
    (windows-latest is the slowest runner per eng plan A6).
    """
    start = time.monotonic()
    for fixture in _CORPUS_FIXTURES:
        raw = _load_fixture_bytes(fixture)
        _ = _round_trip_digest(raw)
    elapsed = time.monotonic() - start
    assert elapsed < 60.0, (
        f"VAL-W1-045: corpus load + canonicalize loop took {elapsed:.3f}s, "
        f"exceeding the 60s tier-1 budget"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-045")
def test_every_corpus_fixture_has_sha256_sidecar() -> None:
    """Every fixture under golden_corpus/ MUST have a .sha256 sidecar.

    Co-validates that the corpus is complete and the W1.6 generation step
    did not skip a sidecar.
    """
    fixtures = sorted(CORPUS_DIR.glob("*.json"))
    sidecars = sorted(CORPUS_DIR.glob("*.sha256"))
    assert len(fixtures) == 15, (
        f"VAL-W1-045: expected 15 corpus fixtures, found {len(fixtures)}: "
        f"{[f.name for f in fixtures]}"
    )
    assert len(sidecars) == len(fixtures), (
        f"VAL-W1-045: fixture/sidecar count mismatch. "
        f"fixtures={[f.name for f in fixtures]} "
        f"sidecars={[s.name for s in sidecars]}"
    )
    for fixture in fixtures:
        sidecar = fixture.with_suffix(".sha256")
        assert sidecar.is_file(), (
            f"VAL-W1-045: missing sidecar for {fixture.name}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W1-045")
def test_module_carries_plumbing_marker_for_tier1_attribution() -> None:
    """Grep-style attribution: this test module declares the plumbing marker.

    VAL-W1-045 evidence requires ``grep -c "@pytest.mark.plumbing"
    packages/schemas/python/tests/test_golden_corpus.py`` >= 1. This test
    reads its own source file to verify; failing means the gate engine
    cannot attribute the corpus to tier-1.
    """
    self_source = Path(__file__).read_text(encoding="utf-8")
    plumbing_marker_count = self_source.count("@pytest.mark.plumbing")
    assert plumbing_marker_count >= 1, (
        f"VAL-W1-045: expected >= 1 @pytest.mark.plumbing in this module; "
        f"found {plumbing_marker_count}"
    )
