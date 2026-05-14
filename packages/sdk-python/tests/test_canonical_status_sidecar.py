"""VAL-W3-010 (sidecar-side) -- sidecar HTTP 422 + RELAY-ING-031 maps to
``RelayCanonicalStatusForbidden`` in the SDK.

The SDK-side guard (in ``lifecycle.build_ingest_run_envelope``) prevents
canonical-write fields from ever crossing the wire. As defense in
depth, the sidecar ALSO rejects any forged envelope with HTTP 422 +
``RELAY-ING-031``. The SDK MUST surface the rejection as the typed
exception ``RelayCanonicalStatusForbidden`` so the caller has a single
typed surface regardless of which side caught the violation.

This test forces the wire-format path via a private/escape API (a
raw httpx POST through the SDK's lifecycle client) and asserts the
typed exception with the correct ``code`` / ``error_class``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay import RelayCanonicalStatusForbidden
from relay.run import _LifecycleHTTPClient
from test_loopback_server import LoopbackServer


@pytest.fixture
def server():
    s = LoopbackServer()
    s.start()
    try:
        yield s
    finally:
        s.stop()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-010")
@pytest.mark.parametrize(
    "forged_field",
    [
        "status",
        "primary_failure_class",
        "written_by",
        "accepted_at",
        "finalized_at",
    ],
)
def test_sidecar_returns_422_and_sdk_raises_canonical_status_forbidden(
    server, forged_field: str
) -> None:
    """For each of the five canonical-write fields the sidecar returns
    HTTP 422 + RELAY-ING-031 and the SDK surfaces
    RelayCanonicalStatusForbidden.
    """
    server.add_route(
        "POST", "/v1/ingest/runs",
        lambda req: (
            422,
            {
                "schema_version": "relay.error.v1",
                "code": "RELAY-ING-031",
                "error_class": "CANONICAL-WRITE-FIELD-REJECTED",
                "message": f"client tried to set canonical field {forged_field!r}",
                "retry_advice": {"mode": "no_retry"},
                "details": {"forbidden_field": forged_field},
            },
            {},
        ),
    )

    # Drive the wire-format path directly with the SDK's lifecycle
    # HTTP client. The SDK's envelope builder would normally block
    # this construction at the boundary; here we simulate a forged
    # raw-HTTP submission to verify the defense-in-depth path.
    client = _LifecycleHTTPClient(base_url=server.base_url)
    try:
        # The forged envelope deliberately carries the canonical-write
        # field; the SDK's HTTP client posts it (the SDK-boundary guard
        # is bypassed because we use the raw _LifecycleHTTPClient).
        forged_envelope = {
            "schema_version": "relay.ingest.run.v1",
            forged_field: "tampered-value",
        }
        with pytest.raises(RelayCanonicalStatusForbidden) as excinfo:
            client.post_ingest_run(forged_envelope)
        err = excinfo.value
        assert err.error_class == "RELAY-SDK-CANONICAL-STATUS-FORBIDDEN"
        assert err.code == "RELAY-SDK-005"
        assert err.details.get("http_status") == 422
        assert err.details.get("code") == "RELAY-ING-031"
    finally:
        client.close()
