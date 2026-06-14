"""SSRF guard: a destination IPv4 literal decorated with a trailing FQDN dot or
surrounding whitespace must still be denied (bug hunt finding).

The resolver / HTTP client dials ``169.254.169.254.`` and ``10.0.0.1 `` as the
bare address, but ``ipaddress.ip_address`` rejects the decorated form, so without
normalizing first the literal misses the cloud-metadata / RFC1918 / loopback
checks and falls through the hostname denylist as a NON-match -> ALLOWED, a
default-deny egress bypass. ``_classify`` normalizes (strip whitespace + trailing
dots) before any IP classification.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.plumbing


@pytest.mark.parametrize(
    "host,reason",
    [
        ("169.254.169.254.", "cloud_metadata"),  # trailing FQDN-root dot
        ("169.254.169.254..", "cloud_metadata"),  # multiple trailing dots
        ("169.254.169.254 ", "cloud_metadata"),  # trailing space
        (" 169.254.169.254", "cloud_metadata"),  # leading space
        ("\t169.254.169.254\n", "cloud_metadata"),  # tab + newline wrap
        ("10.0.0.1.", "rfc1918"),
        ("10.0.0.1 ", "rfc1918"),
        ("192.168.0.1\t", "rfc1918"),
        ("10.0.0.1\n", "rfc1918"),
        ("127.0.0.1.", "loopback"),
        ("https://169.254.169.254./latest/meta-data/", "cloud_metadata"),
        ("http://10.0.0.1.:8080/", "rfc1918"),
    ],
)
def test_decorated_internal_ipv4_is_denied(host: str, reason: str) -> None:
    from relay.network_policy import EgressDenied, validate_egress_entries

    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries([host])
    assert exc.value.envelope["denied_reason"] == reason, (host, exc.value.envelope)


@pytest.mark.parametrize(
    "host",
    [
        "8.8.8.8.",  # public IP with trailing dot -- still allowed
        "8.8.8.8 ",  # public IP with whitespace -- still allowed
        "api.openai.com.",  # public FQDN with root dot -- still allowed
    ],
)
def test_decorated_public_host_stays_allowed(host: str) -> None:
    # Normalization must NOT over-block: a public address/host decorated the same
    # way is still allowed (validate_egress_entries returns without raising).
    from relay.network_policy import validate_egress_entries

    validate_egress_entries([host])
