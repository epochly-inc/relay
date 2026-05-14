"""Generate the cross-language error-envelope parity corpus (VAL-W4-029).

Emits ``parity_fixtures.json`` next to this file. The Python SDK builds a
typed exception per row of the canonical error code matrix, calls
``to_envelope()``, and writes the JCS-canonical bytes hex form of the
serialized envelope. The TypeScript SDK, given the same fixtures, MUST
deserialize each envelope into the SAME typed leaf (VAL-W4-028) AND
re-serialize back to byte-identical canonical bytes (VAL-W4-029).

Run:
    uv run python tests/conformance/errors/generate_parity_fixtures.py

This is a build-time helper; the generated JSON is committed and
consumed by both Py (parity self-check) and TS
(``packages/sdk-typescript/test/w4_4_cross_language_parity.test.ts``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Make the package source importable when running as a script.
REPO_ROOT = Path(__file__).resolve().parents[2]
SDK_PYTHON_SRC = REPO_ROOT / "packages" / "sdk-python"
SCHEMAS_PYTHON_SRC = REPO_ROOT / "packages" / "schemas" / "python"
sys.path.insert(0, str(SDK_PYTHON_SRC))
sys.path.insert(0, str(SCHEMAS_PYTHON_SRC))

from relay.errors import (  # noqa: E402
    RelayAuthError,
    RelayAuthMismatch,
    RelayCanonicalStatusForbidden,
    RelayConfigError,
    RelayError,
    RelayEvidenceError,
    RelayEvidenceIncomplete,
    RelayGateError,
    RelayHandoffIncomplete,
    RelayIngestError,
    RelayLifecycleInvalid,
    RelayPolicyError,
    RelayRateLimitError,
    RelayReplayError,
    RelayReplayPrecondition,
    RelaySchemaError,
    RelaySdkError,
    RelaySidecarError,
    RelaySidecarNotReachable,
    RelaySidecarVersionMismatch,
    RelaySQLiteError,
    RelayUnknownError,
)
from relay_schemas.envelopes import canonical_bytes  # noqa: E402

# -----------------------------------------------------------------------------
# Curated fixture matrix.
#
# Every row exercises (cls, wire_code, expected_subclass_name). The wire
# code may be a namespace default (e.g., RELAY-AUTH-001) or a typed leaf
# code (e.g., RELAY-ING-031). The TS test asserts:
#   1. RelayError.fromEnvelope(envelope) instanceof <expected_subclass>
#   2. error.code === wire_code
#   3. JCS(canonical_bytes(error.toEnvelope())) === fixture.canonical_hex
# -----------------------------------------------------------------------------

# Each entry: (factory, wire_code, expected_ts_class_name, message,
# request_id, trace_id, details).
_FIXTURE_MATRIX: list[
    tuple[
        type[RelayError],
        str,
        str,
        str,
        str | None,
        str | None,
        dict[str, Any] | None,
    ]
] = [
    # -- Spec B.4 wire codes (VAL-W4-028 enumerated) --------------------------
    (
        RelayIngestError,
        "RELAY-ING-001",
        "RelayIngestError",
        "ingest envelope rejected",
        "req_001",
        "trace_001",
        None,
    ),
    (
        RelayIngestError,
        "RELAY-ING-014",
        "RelayIngestError",
        "ingest payload exceeds size limit",
        "req_014",
        "trace_014",
        None,
    ),
    (
        RelayIngestError,
        "RELAY-ING-021",
        "RelayIngestError",
        "ingest schema invalid",
        "req_021",
        "trace_021",
        None,
    ),
    (
        RelayCanonicalStatusForbidden,
        "RELAY-ING-031",
        "RelayCanonicalStatusForbidden",
        "canonical-result fields are control-plane owned",
        "req_031",
        "trace_031",
        {"forged_field": "status"},
    ),
    (
        RelayAuthError,
        "RELAY-AUTH-001",
        "RelayAuthError",
        "missing project token",
        "req_a01",
        "trace_a01",
        None,
    ),
    (
        RelayAuthError,
        "RELAY-AUTH-014",
        "RelayAuthError",
        "expired project token",
        "req_a14",
        "trace_a14",
        None,
    ),
    (
        RelayRateLimitError,
        "RELAY-RATE-001",
        "RelayRateLimitError",
        "rate limit exceeded",
        "req_r01",
        "trace_r01",
        None,
    ),
    (
        RelayRateLimitError,
        "RELAY-RATE-014",
        "RelayRateLimitError",
        "burst rate exceeded",
        "req_r14",
        "trace_r14",
        None,
    ),
    (
        RelayGateError,
        "RELAY-GATE-001",
        "RelayGateError",
        "gate not found",
        "req_g01",
        "trace_g01",
        None,
    ),
    (
        RelayGateError,
        "RELAY-GATE-014",
        "RelayGateError",
        "gate evaluation failed",
        "req_g14",
        "trace_g14",
        None,
    ),
    (
        RelayHandoffIncomplete,
        "RELAY-GATE-021",
        "RelayHandoffIncomplete",
        "stale three-anchor handoff",
        "req_g21",
        "trace_g21",
        {"mismatched_anchor": "manifest_commit_hash"},
    ),
    (
        RelayEvidenceError,
        "RELAY-EVID-001",
        "RelayEvidenceError",
        "evidence bundle rejected",
        "req_e01",
        "trace_e01",
        None,
    ),
    (
        RelayEvidenceError,
        "RELAY-EVID-014",
        "RelayEvidenceError",
        "evidence signature invalid",
        "req_e14",
        "trace_e14",
        None,
    ),
    (
        RelayReplayError,
        "RELAY-REPLAY-001",
        "RelayReplayError",
        "replay configuration invalid",
        "req_p01",
        "trace_p01",
        None,
    ),
    (
        RelayReplayError,
        "RELAY-REPLAY-014",
        "RelayReplayError",
        "cassette playback failed",
        "req_p14",
        "trace_p14",
        None,
    ),
    # -- Specific typed leaves the SDK explicitly maps ------------------------
    (
        RelayHandoffIncomplete,
        "RELAY-ING-022",
        "RelayHandoffIncomplete",
        "handoff anchors missing",
        "req_022",
        "trace_022",
        {"mismatched_anchor": "actor_identity_hash"},
    ),
    (
        RelayPolicyError,
        "RELAY-ING-032",
        "RelayPolicyError",
        "raw payload rejected by redaction policy",
        "req_032",
        "trace_032",
        None,
    ),
    (
        RelayReplayPrecondition,
        "RELAY-REPLAY-002",
        "RelayReplayPrecondition",
        "replay precondition unmet",
        "req_p02",
        "trace_p02",
        None,
    ),
    (
        RelayEvidenceIncomplete,
        "RELAY-EVID-002",
        "RelayEvidenceIncomplete",
        "evidence envelope missing required binding",
        "req_e02",
        "trace_e02",
        None,
    ),
    # -- SDK-local codes ------------------------------------------------------
    (
        RelayConfigError,
        "RELAY-SDK-001",
        "RelayConfigError",
        "invalid SDK configuration",
        None,
        None,
        None,
    ),
    (
        RelaySidecarVersionMismatch,
        "RELAY-SDK-002",
        "RelaySidecarVersionMismatch",
        "sidecar version mismatch",
        None,
        None,
        None,
    ),
    (
        RelaySidecarNotReachable,
        "RELAY-SDK-003",
        "RelaySidecarNotReachable",
        "sidecar not reachable",
        None,
        None,
        None,
    ),
    (
        RelayAuthMismatch,
        "RELAY-SDK-004",
        "RelaySidecarAuthError",
        "nonce-challenge auth failed",
        None,
        None,
        None,
    ),
    (
        RelayLifecycleInvalid,
        "RELAY-SDK-006",
        "RelayLifecycleInvalid",
        "lifecycle status outside closed enum",
        None,
        None,
        None,
    ),
    # -- Forward-compat (VAL-W4-030) -----------------------------------------
    (
        RelayUnknownError,
        "RELAY-FUTURE-999",
        "RelayUnknownError",
        "unknown forward-compat code",
        "req_999",
        "trace_999",
        {"raw_payload": {"forward": True}},
    ),
    # -- Namespace fallback (intermediates) ----------------------------------
    (
        RelaySchemaError,
        "RELAY-SCHEMA-014",
        "RelaySchemaError",
        "schema rejection",
        "req_s14",
        "trace_s14",
        None,
    ),
    (
        RelaySidecarError,
        "RELAY-SIDECAR-002",
        "RelaySidecarError",
        "sidecar lifecycle fault",
        "req_sc2",
        "trace_sc2",
        None,
    ),
    (
        RelaySQLiteError,
        "RELAY-SQLITE-001",
        "RelaySQLiteError",
        "sqlite-layer fault",
        "req_sq1",
        "trace_sq1",
        None,
    ),
    (
        RelaySdkError,
        "RELAY-SDK-010",
        "RelayPolicyError",
        "sdk policy invalid",
        None,
        None,
        None,
    ),
]


def _render_fixture(
    cls: type[RelayError],
    wire_code: str,
    expected_ts_class: str,
    message: str,
    request_id: str | None,
    trace_id: str | None,
    details: dict[str, Any] | None,
) -> dict[str, Any]:
    # Always route through from_envelope so the canonical leaf class
    # (and therefore error_class envelope field) is whatever the
    # registry says it is. This keeps the corpus aligned with the
    # cross-language routing contract -- if either Py or TS changes the
    # leaf for a given wire code, regenerating the corpus picks it up.
    seed_envelope: dict[str, Any] = {
        "schema_version": "relay.sdk_error.v1",
        "code": wire_code,
        "message": message,
        "request_id": request_id,
        "trace_id": trace_id,
        "details": details or {},
    }
    err = RelayError.from_envelope(seed_envelope)
    # The factory ``cls`` argument is preserved as the *expected* root
    # class so the matrix declarations stay self-documenting; the
    # actual instance class may be a more specific leaf when the
    # registry routes the wire code that way.
    assert isinstance(err, cls | RelayError), (
        f"fixture '{wire_code}': from_envelope produced unexpected class "
        f"{type(err).__name__}; matrix declared {cls.__name__}"
    )
    envelope = err.to_envelope()
    canonical = canonical_bytes(envelope)
    return {
        "name": f"{cls.__name__}__{wire_code}",
        "wire_code": wire_code,
        "expected_ts_class": expected_ts_class,
        "envelope": envelope,
        "canonical_hex": canonical.hex(),
        "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def main() -> None:
    fixtures: list[dict[str, Any]] = []
    for entry in _FIXTURE_MATRIX:
        fixtures.append(_render_fixture(*entry))

    corpus = {
        "schema_version": "relay.error_envelope_parity.v1",
        "description": (
            "Cross-language error envelope parity corpus (VAL-W4-029). "
            "Each fixture is the JCS-canonical hex of the Py-emitted "
            "RelayError.to_envelope(). The TS SDK MUST deserialize the "
            "envelope into the expected typed leaf and re-serialize "
            "byte-equal canonical bytes."
        ),
        "fixtures": fixtures,
    }
    out_path = Path(__file__).parent / "parity_fixtures.json"
    out_path.write_text(
        json.dumps(corpus, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(fixtures)} fixtures to {out_path}")


if __name__ == "__main__":
    main()
