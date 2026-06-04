"""RELAY-CEL-009 engine-error + RELAY-CEL-004 extra-UDF-rejection taxonomy.

WS-A foundation for the cel-wasm cutover. The wasm engine emits its OWN
RELAY-CEL-NNN envelope codes (001 compile / 004 exec / 006 request) plus a
RELAY-CEL-PANIC trap marker, whose NUMBERS overlap the host's classified codes
(004 = UDF-impure, 006 = numeric-out-of-bounds) but whose MEANINGS differ. The
wasm-backed adapter MUST translate them into a DISTINCT RELAY-CEL-009 engine
code so a wasm exec/request failure never surfaces downstream as a host
UDF-impurity / numeric-out-of-bounds classification (which would poison the
gate's signed per-condition error_code).

tier-1 plumbing.
"""
from __future__ import annotations

import pytest

from relay_contracts.errors import (
    SUBTYPE_ENGINE_COMPILE,
    SUBTYPE_ENGINE_EXEC,
    SUBTYPE_ENGINE_PANIC,
    SUBTYPE_ENGINE_REQUEST,
    SUBTYPE_NUMERIC_OOB,
    SUBTYPE_UDF_IMPURE,
    SUBTYPE_UDF_UNREGISTERED,
    RelayCelEngineError,
    RelayCelError,
    RelayCelUnsupportedUdfError,
)


@pytest.mark.plumbing
def test_engine_error_code_is_009_not_004_or_006():
    err = RelayCelEngineError("boom", subtype=SUBTYPE_ENGINE_EXEC)
    assert isinstance(err, RelayCelError)
    assert err.code == "RELAY-CEL-009", err.code
    assert err.subtype == SUBTYPE_ENGINE_EXEC
    env = err.envelope
    assert env.code == "RELAY-CEL-009"
    assert env.subtype == "RELAY-CEL-ENGINE-EXEC"


@pytest.mark.plumbing
@pytest.mark.parametrize("wasm_code,expected_subtype", [
    ("RELAY-CEL-001", SUBTYPE_ENGINE_COMPILE),
    ("RELAY-CEL-004", SUBTYPE_ENGINE_EXEC),     # wasm EXEC, NOT host UDF-impure
    ("RELAY-CEL-006", SUBTYPE_ENGINE_REQUEST),  # wasm REQUEST, NOT host numeric-OOB
    ("RELAY-CEL-PANIC", SUBTYPE_ENGINE_PANIC),
    ("RELAY-CEL-999", SUBTYPE_ENGINE_EXEC),     # unknown -> ENGINE-EXEC default
])
def test_from_wasm_envelope_maps_to_009(wasm_code, expected_subtype):
    err = RelayCelEngineError.from_wasm_envelope(wasm_code, "engine said no")
    assert err.code == "RELAY-CEL-009", (wasm_code, err.code)
    assert err.subtype == expected_subtype, (wasm_code, err.subtype)
    # The original wasm code is preserved for diagnosis.
    assert wasm_code in err.message


@pytest.mark.plumbing
def test_collision_guard_wasm_exec_request_never_surface_as_host_004_006():
    # The whole point of 009: a wasm exec (its 004) / request (its 006) failure
    # must NOT carry the host subtypes UDF-IMPURE (004) / NUMERIC-OOB (006).
    exec_err = RelayCelEngineError.from_wasm_envelope("RELAY-CEL-004", "div by zero")
    req_err = RelayCelEngineError.from_wasm_envelope("RELAY-CEL-006", "bad request")
    for err in (exec_err, req_err):
        assert err.code == "RELAY-CEL-009"
        assert err.subtype not in (SUBTYPE_UDF_IMPURE, SUBTYPE_NUMERIC_OOB)


@pytest.mark.plumbing
def test_unsupported_udf_error_is_004_unregistered():
    err = RelayCelUnsupportedUdfError("caller passed my_check; engine has only the 3 Relay UDFs")
    assert isinstance(err, RelayCelError)
    assert err.code == "RELAY-CEL-004", err.code
    assert err.subtype == SUBTYPE_UDF_UNREGISTERED
    # Distinct subtype from the purity error that shares code 004.
    assert err.subtype != SUBTYPE_UDF_IMPURE
