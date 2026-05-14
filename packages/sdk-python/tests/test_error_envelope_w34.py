"""W3.4 -- RelayError hierarchy aligned to the error envelope schema.

Covers VAL-W3-029 .. VAL-W3-035. Every assertion below pins observable
surface (class hierarchy, attribute equality, dict shape, structured
codegen reference) so the worker handoff binds to evidence, not narrative.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest

# The W3.4 surface re-exports the full hierarchy off the package root and
# off relay.errors. Tests import from relay.errors directly so the binding
# is unambiguous.
from relay.errors import (
    RELAY_ING_031_CODE,
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
from relay.run import _LifecycleHTTPClient

# -----------------------------------------------------------------------------
# VAL-W3-030: hierarchy mirrors the error code namespace
# -----------------------------------------------------------------------------
#
# RelayError is the root. One intermediate subclass per RELAY-{AREA} prefix.
# Each "leaf" exception (e.g., RelayHandoffIncomplete for RELAY-ING-022)
# inherits from BOTH RelayError AND the namespace intermediate.

_NAMESPACE_INTERMEDIATES: dict[str, type[RelayError]] = {
    "RELAY-ING-": RelayIngestError,
    "RELAY-AUTH-": RelayAuthError,
    "RELAY-RATE-": RelayRateLimitError,
    "RELAY-GATE-": RelayGateError,
    "RELAY-EVID-": RelayEvidenceError,
    "RELAY-REPLAY-": RelayReplayError,
    "RELAY-SCHEMA-": RelaySchemaError,
    "RELAY-SIDECAR-": RelaySidecarError,
    "RELAY-SDK-": RelaySdkError,
    "RELAY-SQLITE-": RelaySQLiteError,
}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-030")
def test_hierarchy_root_is_relay_error() -> None:
    """Every namespace intermediate inherits from RelayError."""
    for prefix, cls in _NAMESPACE_INTERMEDIATES.items():
        assert issubclass(cls, RelayError), (
            f"VAL-W3-030: {cls.__name__} for prefix {prefix} must inherit "
            f"from RelayError"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-030")
def test_hierarchy_namespace_intermediates_cover_required_prefixes() -> None:
    """The eight required namespace classes from the worker scope exist."""
    required = {
        "RELAY-ING-": RelayIngestError,
        "RELAY-GATE-": RelayGateError,
        "RELAY-REPLAY-": RelayReplayError,
        "RELAY-EVID-": RelayEvidenceError,
        "RELAY-SCHEMA-": RelaySchemaError,
        "RELAY-SIDECAR-": RelaySidecarError,
        "RELAY-SDK-": RelaySdkError,
        "RELAY-SQLITE-": RelaySQLiteError,
    }
    for prefix, cls in required.items():
        assert cls is _NAMESPACE_INTERMEDIATES[prefix]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-030")
@pytest.mark.parametrize(
    "code, expected_namespace",
    [
        ("RELAY-ING-031", RelayIngestError),
        ("RELAY-ING-022", RelayIngestError),
        ("RELAY-ING-032", RelayIngestError),
        ("RELAY-AUTH-001", RelayAuthError),
        ("RELAY-RATE-001", RelayRateLimitError),
        ("RELAY-GATE-021", RelayGateError),
        ("RELAY-EVID-002", RelayEvidenceError),
        ("RELAY-EVID-014", RelayEvidenceError),
        ("RELAY-REPLAY-002", RelayReplayError),
        ("RELAY-REPLAY-014", RelayReplayError),
        ("RELAY-SCHEMA-001", RelaySchemaError),
        ("RELAY-SIDECAR-001", RelaySidecarError),
        ("RELAY-SDK-001", RelaySdkError),
        ("RELAY-SQLITE-001", RelaySQLiteError),
    ],
)
def test_code_maps_to_declared_namespace_subclass(
    code: str, expected_namespace: type[RelayError]
) -> None:
    """from_envelope(code) returns an exception in the right namespace branch."""
    envelope = {
        "schema_version": "relay.sdk_error.v1",
        "code": code,
        "http_status": 422,
        "message": "scoped error",
        "blocked_surface": "POST /v1/ingest/runs",
        "retry_advice": {"mode": "no_retry"},
        "request_id": "req_test",
        "trace_id": "trace_test",
    }
    exc = RelayError.from_envelope(envelope)
    assert isinstance(exc, RelayError)
    assert isinstance(exc, expected_namespace), (
        f"VAL-W3-030: from_envelope({code!r}) returned "
        f"{type(exc).__name__}; expected isinstance of "
        f"{expected_namespace.__name__}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-030")
def test_existing_leaf_exceptions_inherit_from_namespace_class() -> None:
    """Existing typed leaves inherit from BOTH RelayError and their namespace."""
    # RELAY-ING-* leaves
    assert issubclass(RelayCanonicalStatusForbidden, RelayIngestError)
    assert issubclass(RelayHandoffIncomplete, RelayIngestError)
    assert issubclass(RelayPolicyError, RelayIngestError)
    # RELAY-AUTH-* leaves
    assert issubclass(RelayAuthMismatch, RelayAuthError)
    # RELAY-EVID-* leaves
    assert issubclass(RelayEvidenceIncomplete, RelayEvidenceError)
    # RELAY-REPLAY-* leaves
    assert issubclass(RelayReplayPrecondition, RelayReplayError)
    # RELAY-SIDECAR-* leaves
    assert issubclass(RelaySidecarVersionMismatch, RelaySidecarError)
    assert issubclass(RelaySidecarNotReachable, RelaySidecarError)
    # RELAY-SDK-* leaves
    assert issubclass(RelayConfigError, RelaySdkError)
    assert issubclass(RelayLifecycleInvalid, RelaySdkError)


# -----------------------------------------------------------------------------
# VAL-W3-029: every concrete RelayError subclass serializes to a valid envelope
# -----------------------------------------------------------------------------


def _all_concrete_relay_error_subclasses() -> list[type[RelayError]]:
    """Walk RelayError.__subclasses__ recursively, return concrete classes."""
    seen: set[type[RelayError]] = set()
    stack: list[type[RelayError]] = list(RelayError.__subclasses__())
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        stack.extend(cls.__subclasses__())
    return sorted(seen, key=lambda c: c.__name__)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-029")
def test_every_concrete_subclass_serializes_to_envelope() -> None:
    """Each RelayError subclass's to_envelope() returns the canonical shape."""
    discovered = _all_concrete_relay_error_subclasses()
    # Floor of subclass count: ten namespace intermediates + RelayUnknownError
    # + existing leaves (at least RelayCanonicalStatusForbidden,
    # RelayHandoffIncomplete, RelayPolicyError, RelayAuthMismatch,
    # RelayEvidenceIncomplete, RelayReplayPrecondition,
    # RelaySidecarVersionMismatch, RelaySidecarNotReachable,
    # RelayConfigError, RelayLifecycleInvalid).
    assert len(discovered) >= 15, (
        f"VAL-W3-029: expected >= 15 discoverable subclasses; found "
        f"{len(discovered)}: {[c.__name__ for c in discovered]}"
    )
    required_fields = {
        "schema_version",
        "code",
        "http_status",
        "message",
        "blocked_surface",
        "documentation_url",
        "retry_advice",
        "request_id",
        "trace_id",
    }
    for cls in discovered:
        exc = cls("test message")
        env = exc.to_envelope()
        assert isinstance(env, dict), (
            f"VAL-W3-029: {cls.__name__}.to_envelope() returned "
            f"{type(env).__name__}, expected dict"
        )
        missing = required_fields - set(env.keys())
        assert not missing, (
            f"VAL-W3-029: {cls.__name__}.to_envelope() missing required "
            f"fields {missing}"
        )
        assert env["schema_version"] == "relay.sdk_error.v1"
        # code field MUST match the canonical RELAY-* wire pattern.
        assert re.match(r"^RELAY-[A-Z]+-[0-9]{3}$", env["code"]), (
            f"VAL-W3-029: {cls.__name__}.to_envelope()['code'] = "
            f"{env['code']!r} does not match canonical wire pattern"
        )
        assert isinstance(env["http_status"], int)
        assert 400 <= env["http_status"] <= 599
        assert isinstance(env["message"], str)


# -----------------------------------------------------------------------------
# VAL-W3-031: retry_advice is structured (dict), not boolean
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-031")
def test_retry_advice_is_dict_with_mode_field() -> None:
    """to_envelope()['retry_advice'] is a dict with a 'mode' key."""
    discovered = _all_concrete_relay_error_subclasses()
    valid_modes = {"retryable", "no_retry", "after_state_change", "after_retry_after"}
    for cls in discovered:
        exc = cls("test message")
        env = exc.to_envelope()
        ra = env["retry_advice"]
        # Boolean is explicitly forbidden by VAL-W3-031.
        assert not isinstance(ra, bool)
        assert isinstance(ra, dict), (
            f"VAL-W3-031: {cls.__name__}.retry_advice in envelope is "
            f"{type(ra).__name__}, expected dict (NOT a boolean)"
        )
        assert "mode" in ra, (
            f"VAL-W3-031: {cls.__name__}.retry_advice missing 'mode' key"
        )
        assert ra["mode"] in valid_modes, (
            f"VAL-W3-031: {cls.__name__}.retry_advice['mode'] = "
            f"{ra['mode']!r} not in {valid_modes}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-031")
def test_retry_advice_dict_carries_delay_and_max_attempts_when_provided() -> None:
    """Structured retry_advice can carry delay_seconds and max_attempts."""
    err = RelayRateLimitError(
        "rate limited",
        retry_advice={"mode": "after_retry_after", "delay_seconds": 30, "max_attempts": 3},
    )
    env = err.to_envelope()
    ra = env["retry_advice"]
    assert ra["mode"] == "after_retry_after"
    assert ra["delay_seconds"] == 30
    assert ra["max_attempts"] == 3


# -----------------------------------------------------------------------------
# VAL-W3-032: blocked_surface field is populated for every non-2xx error
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-032")
def test_blocked_surface_is_non_empty_string_on_every_envelope() -> None:
    """to_envelope()['blocked_surface'] is a non-empty string on every subclass."""
    discovered = _all_concrete_relay_error_subclasses()
    for cls in discovered:
        exc = cls("test message")
        env = exc.to_envelope()
        bs = env["blocked_surface"]
        assert isinstance(bs, str), (
            f"VAL-W3-032: {cls.__name__}.blocked_surface is "
            f"{type(bs).__name__}, expected str"
        )
        assert bs != "", (
            f"VAL-W3-032: {cls.__name__}.blocked_surface is empty"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-032")
def test_blocked_surface_can_be_overridden_per_instance() -> None:
    """An instance may override blocked_surface at construction time."""
    err = RelayIngestError(
        "test",
        blocked_surface="POST /v1/ingest/runs",
    )
    env = err.to_envelope()
    assert env["blocked_surface"] == "POST /v1/ingest/runs"


# -----------------------------------------------------------------------------
# VAL-W3-033: request_id + trace_id propagated from sidecar response
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-033")
def test_request_id_and_trace_id_attached_from_response_body() -> None:
    """Transport extracts request_id/trace_id from a sidecar error envelope."""
    payload = {
        "schema_version": "relay.error.v1",
        "code": "RELAY-ING-031",
        "http_status": 422,
        "message": "canonical-write field rejected",
        "blocked_surface": "POST /v1/ingest/runs",
        "retry_advice": "do_not_retry",
        "request_id": "req_01HX_TEST_REQ_ID",
        "trace_id": "trace_01HX_TEST_TRACE_ID",
    }
    resp = httpx.Response(
        status_code=422,
        json=payload,
        request=httpx.Request("POST", "http://127.0.0.1:1234/v1/ingest/runs"),
    )
    client = _LifecycleHTTPClient(base_url="http://127.0.0.1:1234")
    try:
        with pytest.raises(RelayCanonicalStatusForbidden) as excinfo:
            client._raise_for_error_envelope(resp)  # noqa: SLF001
        err = excinfo.value
        assert err.request_id == "req_01HX_TEST_REQ_ID"
        assert err.trace_id == "trace_01HX_TEST_TRACE_ID"
        # And those values must round-trip through to_envelope().
        env = err.to_envelope()
        assert env["request_id"] == "req_01HX_TEST_REQ_ID"
        assert env["trace_id"] == "trace_01HX_TEST_TRACE_ID"
    finally:
        client.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-033")
def test_request_id_and_trace_id_fall_back_to_response_headers() -> None:
    """When the body omits the ids, headers X-Request-ID / X-Trace-ID are used."""
    payload = {
        "schema_version": "relay.error.v1",
        "code": "RELAY-ING-031",
        "http_status": 422,
        "message": "canonical-write field rejected",
        "blocked_surface": "POST /v1/ingest/runs",
        "retry_advice": "do_not_retry",
    }
    resp = httpx.Response(
        status_code=422,
        json=payload,
        headers={
            "X-Request-ID": "req_header_id",
            "X-Trace-ID": "trace_header_id",
        },
        request=httpx.Request("POST", "http://127.0.0.1:1234/v1/ingest/runs"),
    )
    client = _LifecycleHTTPClient(base_url="http://127.0.0.1:1234")
    try:
        with pytest.raises(RelayCanonicalStatusForbidden) as excinfo:
            client._raise_for_error_envelope(resp)  # noqa: SLF001
        err = excinfo.value
        assert err.request_id == "req_header_id"
        assert err.trace_id == "trace_header_id"
    finally:
        client.close()


# -----------------------------------------------------------------------------
# VAL-W3-034: codes are codegen'd from a single schema source
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-034")
def test_sdk_error_codes_referenced_via_codegen_constants_not_string_literals() -> None:
    """Every wire literal in errors.py is bound to a Final[str] constant.

    Every wire code referenced by relay/errors.py MUST be sourced from a
    Final[str] constant whose value is the wire token. The grep flags any
    hardcoded code string literal in errors.py that is NOT bound to such
    a constant.
    """
    errors_py = Path(__file__).parent.parent / "relay" / "errors.py"
    text = errors_py.read_text(encoding="utf-8")
    # Find every literal RELAY-XXX-NNN appearance.
    pattern = re.compile(r'"(RELAY-[A-Z]+-[0-9]{3})"')
    literal_codes = set(pattern.findall(text))
    final_decl_pattern = re.compile(
        r'_CODE:\s*Final\[str\]\s*=\s*"(RELAY-[A-Z]+-[0-9]{3})"'
    )
    final_decl_codes = set(final_decl_pattern.findall(text))
    # Every literal in the file must also appear as a Final[str]
    # constant declaration. If a literal appears WITHOUT a Final[str]
    # declaration, that is the banned hardcoded-string pattern.
    orphan = literal_codes - final_decl_codes
    assert not orphan, (
        f"VAL-W3-034: error codes referenced in errors.py without a "
        f"Final[str] codegen-binding constant: {orphan}. Every wire code "
        f"in the SDK MUST be sourced from packages/schemas/raw/"
        f"relay-error-codes.yaml via a Final[str] constant."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-034")
def test_relay_error_code_yaml_is_single_source_of_truth() -> None:
    """All SDK-referenced RELAY-* codes appear in relay-error-codes.yaml."""
    yaml_path = (
        Path(__file__).parent.parent.parent.parent
        / "packages"
        / "schemas"
        / "raw"
        / "relay-error-codes.yaml"
    )
    assert yaml_path.exists(), (
        f"VAL-W3-034: relay-error-codes.yaml missing at {yaml_path}; "
        f"this is the single schema source per CQ4"
    )
    yaml_text = yaml_path.read_text(encoding="utf-8")

    errors_py = Path(__file__).parent.parent / "relay" / "errors.py"
    sdk_text = errors_py.read_text(encoding="utf-8")
    pattern = re.compile(r"(RELAY-[A-Z]+-[0-9]{3})")
    sdk_codes = set(pattern.findall(sdk_text))
    missing = [c for c in sorted(sdk_codes) if c not in yaml_text]
    assert not missing, (
        f"VAL-W3-034: SDK references codes not in "
        f"packages/schemas/raw/relay-error-codes.yaml: {missing}"
    )


# -----------------------------------------------------------------------------
# VAL-W3-035: unknown error code maps to RelayUnknownError, code preserved
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-035")
def test_unknown_code_maps_to_relay_unknown_error_with_code_preserved() -> None:
    """Sidecar returning an unknown code becomes RelayUnknownError(code=...)."""
    envelope = {
        "schema_version": "relay.error.v1",
        "code": "RELAY-FUTURE-001",
        "http_status": 422,
        "message": "future error type",
        "blocked_surface": "POST /v1/ingest/runs",
        "retry_advice": "do_not_retry",
        "request_id": "req_test",
        "trace_id": "trace_test",
    }
    exc = RelayError.from_envelope(envelope)
    assert isinstance(exc, RelayUnknownError), (
        f"VAL-W3-035: unknown code returned {type(exc).__name__}; expected "
        f"RelayUnknownError"
    )
    # Code preserved verbatim -- no info loss.
    assert exc.code == "RELAY-FUTURE-001"
    assert exc.message == "future error type"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-035")
def test_unknown_code_from_transport_preserves_code() -> None:
    """Transport-level unknown-code response surfaces RelayUnknownError."""
    payload = {
        "schema_version": "relay.error.v1",
        "code": "RELAY-ZZZ-099",
        "http_status": 422,
        "message": "unrecognised code",
        "blocked_surface": "POST /v1/ingest/runs",
        "retry_advice": "do_not_retry",
        "request_id": "req_unknown",
        "trace_id": "trace_unknown",
    }
    resp = httpx.Response(
        status_code=422,
        json=payload,
        request=httpx.Request("POST", "http://127.0.0.1:1234/v1/ingest/runs"),
    )
    client = _LifecycleHTTPClient(base_url="http://127.0.0.1:1234")
    try:
        with pytest.raises(RelayUnknownError) as excinfo:
            client._raise_for_error_envelope(resp)  # noqa: SLF001
        err = excinfo.value
        assert err.code == "RELAY-ZZZ-099"
        assert err.request_id == "req_unknown"
        assert err.trace_id == "trace_unknown"
    finally:
        client.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-035")
def test_unknown_error_is_relay_error_subclass() -> None:
    """RelayUnknownError MUST inherit from RelayError for catch-all handlers."""
    assert issubclass(RelayUnknownError, RelayError)


# -----------------------------------------------------------------------------
# Sanity: from_envelope round trip for KNOWN codes maps to typed leaves
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-030")
def test_from_envelope_returns_typed_leaf_for_ing_031() -> None:
    """RELAY-ING-031 from_envelope returns RelayCanonicalStatusForbidden."""
    envelope = {
        "schema_version": "relay.error.v1",
        "code": RELAY_ING_031_CODE,
        "http_status": 422,
        "message": "rejected",
        "blocked_surface": "POST /v1/ingest/runs",
        "retry_advice": "do_not_retry",
        "request_id": "req",
        "trace_id": "trace",
    }
    exc = RelayError.from_envelope(envelope)
    assert isinstance(exc, RelayCanonicalStatusForbidden)
    assert isinstance(exc, RelayIngestError)
    assert isinstance(exc, RelayError)
