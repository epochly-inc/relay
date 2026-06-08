"""WS-G packaging: reproducible wasm shipped as relay_contracts package data.

Covers VAL-CWC-P3CORPUS-008 / -010 / -012 (M3 P3CORPUS, WS-G):

  - 008: the reproducible ``relay_cel_wasm.wasm`` (the build.sh deterministic
    recipe artifact) is shipped as PACKAGE DATA of ``relay_contracts`` and is
    resolvable at runtime via ``importlib.resources`` (NOT only from the
    gitignored ``crate/target/``); a ``WasmCelEvaluator`` constructs and
    evaluates over the package-data wasm.
  - 010: when the packaged wasm cannot be resolved, constructing/using the wasm
    engine raises a CLEAR STRUCTURED error (a ``RelayCelError``-family error with
    a WS-A engine-error code -- RELAY-CEL-009 ENGINE subtype -- NOT a bare
    ``FileNotFoundError`` / generic exception); the celpy default path is
    UNAFFECTED by a missing wasm artifact.
  - 012: the shipped wasm's sha256 is PINNED in a checked-in constant equal to
    the sha256 of the build.sh deterministic-recipe artifact (repro holds); a
    guard test asserts the packaged wasm's on-disk sha256 == the pinned value
    (a tampered / stale vendored artifact FAILS).

These are tier-1 plumbing tests (offline, deterministic, no network, no build).
The ``-k`` selectors the contract evidence commands use:
    wasm_package_data | importlib_resource   -> 008
    wasm_missing_artifact_structured_error   -> 010
    wasm_pinned_sha                          -> 012

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""
from __future__ import annotations

import hashlib
import importlib.resources

import celpy.celtypes as celtypes
import pytest

pytestmark = pytest.mark.plumbing

# The full sha256 of the reproducible build.sh deterministic-recipe artifact, as
# reported by `bash packages/cel-wasm/conformance/build.sh repro`. The shipped
# package-data wasm MUST hash to this value (012).
_EXPECTED_REPRO_SHA: str = (
    "7d92aca8ca605a2b76c36e944648de72aec56d1130294c0f22923d64c7faa4c0"
)


def _sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- VAL-CWC-P3CORPUS-008: importlib.resources package-data resolution -------


def test_wasm_package_data_resolvable_via_importlib_resource() -> None:
    """The vendored wasm is locatable via importlib.resources on relay_contracts.

    Mirrors a fresh-installed-wheel resolution: the data path is resolved from
    the IMPORTED package root (`importlib.resources.files('relay_contracts')`),
    not from a crate/target/ relative path. The resource must exist as a file.
    """
    from relay_contracts.wasm_artifact import WASM_PACKAGE_DATA_RELPATH

    resource = importlib.resources.files("relay_contracts").joinpath(
        WASM_PACKAGE_DATA_RELPATH
    )
    assert resource.is_file(), (
        f"packaged wasm not resolvable via importlib.resources at "
        f"{WASM_PACKAGE_DATA_RELPATH!r}"
    )


def test_wasm_package_data_resolver_returns_existing_path() -> None:
    """The resolver helper returns a concrete on-disk path to the package wasm."""
    from relay_contracts.wasm_artifact import resolve_packaged_wasm_path

    path = resolve_packaged_wasm_path()
    assert path is not None
    data = path.read_bytes()
    assert len(data) > 0


def test_wasm_package_data_constructs_engine_from_importlib_resource() -> None:
    """A WasmCelEvaluator constructs from the package-data wasm and evaluates.

    The evaluator resolves its wasm via the package-data resolver (no
    CEL_WASM env, no crate/target/ dependency at the call site) and produces a
    correct result through the wasm engine.
    """
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    ev = WasmCelEvaluator(timeout_ms=250)
    result = ev.evaluate("1 + 2")
    assert isinstance(result, celtypes.IntType)
    assert int(result) == 3


# --- VAL-CWC-P3CORPUS-010: missing-artifact structured error -----------------


def test_wasm_missing_artifact_structured_error() -> None:
    """An absent wasm artifact raises a structured RelayCel*Error, not ENOENT.

    Pointing the wasm resolver at an absent path must surface a
    ``RelayCelError``-family error carrying a stable RELAY-CEL- code (the WS-A
    engine-error code), NOT a bare ``FileNotFoundError`` / generic exception.
    """
    from relay_contracts.errors import RelayCelError
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    ev = WasmCelEvaluator(timeout_ms=250)
    missing = "/nonexistent/relay_cel_wasm__absent__.wasm"
    with pytest.raises(RelayCelError) as excinfo:
        ev.evaluate_with_wasm_path("1 + 2", wasm_path=missing)
    err = excinfo.value
    assert not isinstance(err, FileNotFoundError)
    assert isinstance(err.code, str) and err.code.startswith("RELAY-CEL-"), (
        f"missing-artifact error must carry a RELAY-CEL- code; got {err.code!r}"
    )


def test_wasm_missing_artifact_structured_error_celpy_default_unaffected() -> None:
    """The celpy default path still constructs + evaluates with the wasm absent.

    A missing wasm artifact must NOT break the default (celpy) engine: the
    factory with RELAY_CEL_ENGINE unset returns a working RelayCelEvaluator.
    """
    from relay_contracts.engine import make_cel_evaluator

    ev = make_cel_evaluator(udfs=())
    assert type(ev).__name__ == "RelayCelEvaluator"
    result = ev.evaluate("1 + 2")
    assert int(result) == 3


# --- VAL-CWC-P3CORPUS-012: pinned sha == packaged sha == repro sha -----------


def test_wasm_pinned_sha_constant_equals_repro_sha() -> None:
    """The checked-in pinned sha constant equals the build.sh repro sha."""
    from relay_contracts.wasm_artifact import WASM_PINNED_SHA256

    assert WASM_PINNED_SHA256 == _EXPECTED_REPRO_SHA


def test_wasm_pinned_sha_matches_packaged_artifact_on_disk() -> None:
    """The packaged wasm's on-disk sha256 equals the pinned constant.

    A tampered or stale vendored artifact (whose bytes hash to anything other
    than the pinned value) makes this guard FAIL.
    """
    from relay_contracts.wasm_artifact import (
        WASM_PACKAGE_DATA_RELPATH,
        WASM_PINNED_SHA256,
    )

    resource = importlib.resources.files("relay_contracts").joinpath(
        WASM_PACKAGE_DATA_RELPATH
    )
    data = resource.read_bytes()
    assert _sha256_of(data) == WASM_PINNED_SHA256, (
        "packaged wasm on-disk sha256 != pinned WASM_PINNED_SHA256 -- the "
        "vendored artifact is tampered or stale"
    )
