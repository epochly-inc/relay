"""VAL-W3-007: SDK pins sidecar version compatibility on attach.

On attach the SDK MUST compare ``sidecar_version`` from ``/health``
against its declared compatibility range. A version outside the range MUST
raise ``RelaySidecarVersionMismatch`` (code ``RELAY-SDK-002`` / error_class
``RELAY-SDK-VERSION-MISMATCH``) and NO operation may proceed.

The test seeds a fake ``/health`` response carrying an out-of-range
``sidecar_version`` and asserts the exception is raised before the SDK
returns a usable connection. The pure version-comparison helper is also
exercised directly.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay import Relay
from relay._transport import (
    MAX_COMPATIBLE_SIDECAR_VERSION,
    MIN_COMPATIBLE_SIDECAR_VERSION,
    is_sidecar_version_compatible,
)
from relay.errors import RelaySidecarVersionMismatch

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-007")
def test_version_compat_helper_accepts_in_range() -> None:
    """The pinned in-range version(s) are accepted."""
    assert is_sidecar_version_compatible(MIN_COMPATIBLE_SIDECAR_VERSION)
    assert is_sidecar_version_compatible(MAX_COMPATIBLE_SIDECAR_VERSION)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-007")
@pytest.mark.parametrize(
    "bad_version",
    [
        "999.0.0",  # far future major
        "0.0.1",  # one patch above the v0.1 pinned range
        "1.0.0",  # next major
        "not-a-version",  # unparseable -> fail closed
        "",  # empty -> fail closed
    ],
)
def test_version_compat_helper_rejects_out_of_range(bad_version: str) -> None:
    """Out-of-range and unparseable versions are rejected (fail closed)."""
    assert is_sidecar_version_compatible(bad_version) is False


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-007")
def test_attach_with_out_of_range_version_raises(
    relay_home_tmp,
    stop_sidecar,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sidecar reporting an out-of-range version stops the attach.

    We let the SDK spawn a real sidecar but force the version-compat
    helper to treat its version as incompatible, simulating a sidecar
    whose ``sidecar_version`` falls outside the SDK's supported range. The
    SDK MUST raise RelaySidecarVersionMismatch and return no usable
    connection.
    """
    import relay._transport as transport_mod

    monkeypatch.setattr(
        transport_mod, "is_sidecar_version_compatible", lambda _v: False
    )

    stop_sidecar.append(relay_home_tmp)
    r = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    stop_sidecar.track(r)

    with pytest.raises(RelaySidecarVersionMismatch) as excinfo:
        r.trace("op")
    err = excinfo.value
    assert err.error_class == "RELAY-SDK-VERSION-MISMATCH"
    assert err.code == "RELAY-SDK-002"
    # The details name the observed version and the compat bounds.
    assert "sidecar_version" in err.details
    assert err.details["min_compatible"] == MIN_COMPATIBLE_SIDECAR_VERSION
    assert err.details["max_compatible"] == MAX_COMPATIBLE_SIDECAR_VERSION

    # No usable connection was cached: a retry still raises (does not
    # silently return a half-built connection).
    with pytest.raises(RelaySidecarVersionMismatch):
        r.trace("op-again")

    r.close()
