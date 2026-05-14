"""VAL-W3-005: ``Relay(...)`` rejects invalid ``project_key`` deterministically.

``Relay(project_key=None)``, ``Relay(project_key="")``, and
``Relay(project_key="not-a-ulid-or-token")`` MUST raise ``RelayConfigError``
(a subclass of ``RelayError``) with error_class ``RELAY-SDK-CONFIG-001`` AND
a W1-compliant numeric wire ``code`` at construction, BEFORE any network or
sidecar interaction. The exception is raised synchronously: no spawn, no
lockfile touch, no HTTP request.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re

import pytest
from relay import Relay, RelayConfigError, RelayError

# W1-compliant wire code pattern (VAL-W1-029).
_WIRE_CODE_RE = re.compile(r"^RELAY-[A-Z]+-[0-9]{3}$")


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "bad_key",
    [
        None,
        "",
        "   ",
        "not-a-ulid-or-token",
        12345,
        b"01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ],
)
def test_invalid_project_key_raises_relay_config_error(bad_key: object) -> None:
    """An invalid project_key raises RelayConfigError synchronously."""
    with pytest.raises(RelayConfigError) as excinfo:
        Relay(project_key=bad_key)  # type: ignore[arg-type]
    err = excinfo.value
    # Subclass relationship (contract: "subclass of RelayError").
    assert isinstance(err, RelayError)
    # error_class is the contract.md prose token.
    assert err.error_class == "RELAY-SDK-CONFIG-001"
    # code is the W1-compliant numeric wire token.
    assert _WIRE_CODE_RE.match(err.code), err.code
    assert err.code == "RELAY-SDK-001"
    # No retry: a config error is not transient.
    assert err.retry_advice == "no_retry"


@pytest.mark.plumbing
def test_invalid_project_key_no_spawn_no_lockfile_no_http(
    relay_home_tmp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Construction failure happens BEFORE any spawn / lockfile / HTTP.

    We hard-fail if the construction path reaches httpx, subprocess, or
    acquire_or_attach: each is monkeypatched to raise.
    """
    import subprocess

    import httpx
    import relay._transport as transport_mod

    def _boom_acquire(*_a: object, **_k: object) -> object:
        raise AssertionError("acquire_or_attach must not be called on bad config")

    def _boom_popen(*_a: object, **_k: object) -> object:
        raise AssertionError("subprocess.Popen must not be called on bad config")

    def _boom_client(*_a: object, **_k: object) -> object:
        raise AssertionError("httpx.Client must not be constructed on bad config")

    monkeypatch.setattr(transport_mod, "acquire_or_attach", _boom_acquire)
    monkeypatch.setattr(subprocess, "Popen", _boom_popen)
    monkeypatch.setattr(httpx, "Client", _boom_client)

    with pytest.raises(RelayConfigError):
        Relay(project_key="")

    # No lockfile was created under RELAY_HOME.
    assert not (relay_home_tmp / "sidecar.lock").exists()


@pytest.mark.plumbing
def test_valid_project_key_constructs_without_error(relay_home_tmp) -> None:
    """A syntactically valid ULID or relay_pk_ token constructs cleanly."""
    ulid_client = Relay(project_key="01ARZ3NDEKTSV4RRFFQ69G5FAV")
    assert ulid_client.project_key == "01ARZ3NDEKTSV4RRFFQ69G5FAV"

    token_client = Relay(project_key="relay_pk_" + "A" * 20)
    assert token_client.project_key.startswith("relay_pk_")

    # Still no lockfile: construction does not spawn (VAL-W3-003 overlap).
    assert not (relay_home_tmp / "sidecar.lock").exists()
