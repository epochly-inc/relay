"""VAL-ISO-018: SSRF egress guard MUST reject IPv4-mapped IPv6 forms.

Bug (base commit): ``_classify`` matches cloud-metadata endpoints only by
literal string against ``CLOUD_METADATA_IPS`` and classifies IPv6
addresses purely via the stdlib ``is_link_local`` / ``is_private`` /
``is_multicast`` / ``is_unspecified`` / ``is_reserved`` flags. It never
unwraps an IPv4-mapped IPv6 address (``::ffff:a.b.c.d``). For such an
address all the stdlib ``is_*`` flags are ``False`` and the literal-string
metadata match never fires, so e.g. ``::ffff:169.254.169.254`` (AWS/GCP
metadata), ``::ffff:127.0.0.1`` (loopback), ``::ffff:10.0.0.5`` (RFC1918),
and ``::ffff:100.100.100.200`` (Alibaba metadata) all BYPASS the guard --
a default-deny egress bypass (keystone #7 / SSRF).

PASS when: before the IPv6 branch, ``_classify`` detects a mapped/embedded
IPv4 (``ip.ipv4_mapped``) and re-classifies on the unwrapped form,
re-checking ``CLOUD_METADATA_IPS`` membership too. A mapped denied address
is rejected; a mapped PUBLIC address stays per its real class (no
over-block).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-018")
@pytest.mark.parametrize(
    ("host", "expected_reason"),
    [
        # IPv4-mapped cloud-metadata endpoints.
        ("[::ffff:169.254.169.254]", "cloud_metadata"),
        ("[::ffff:100.100.100.200]", "cloud_metadata"),
        # IPv4-mapped loopback.
        ("[::ffff:127.0.0.1]", "loopback"),
        # IPv4-mapped RFC1918 private.
        ("[::ffff:10.0.0.5]", "rfc1918"),
        ("[::ffff:192.168.1.1]", "rfc1918"),
        # IPv4-mapped link-local.
        ("[::ffff:169.254.1.1]", "link_local"),
    ],
)
def test_ipv4_mapped_ipv6_internal_addresses_are_blocked(
    host: str, expected_reason: str
) -> None:
    """Every IPv4-mapped IPv6 form of an internal/metadata IPv4 address is
    denied with the SAME reason its bare IPv4 form would yield.

    At base commit this is RED: ``validate_egress_entries`` returns
    silently because the embedded IPv4 is never unwrapped.
    """
    from relay.network_policy import EgressDenied, validate_egress_entries

    full_url = f"http://{host}/latest/meta-data/"
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries([full_url])
    assert exc.value.envelope["denied_reason"] == expected_reason, (
        f"{host}: expected denied_reason={expected_reason!r}, "
        f"got {exc.value.envelope['denied_reason']!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-018")
def test_ipv4_mapped_public_address_is_not_over_blocked() -> None:
    """SECURITY regression guard: a mapped PUBLIC IPv4 (8.8.8.8) must NOT
    be blocked just because it arrived in IPv4-mapped form. No over-block.
    """
    from relay.network_policy import validate_egress_entries

    # Should pass the guard silently (public, not internal).
    validate_egress_entries(["http://[::ffff:8.8.8.8]/resolve"])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-018")
def test_bare_ipv6_internal_still_blocked_no_regression() -> None:
    """No regression for native (non-mapped) IPv6 classification."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    # ULA fc00::/7 -> rfc1918; loopback ::1 -> rfc1918 (per existing code).
    for host in ("[fc00::1]", "[::1]", "[fe80::1]"):
        with pytest.raises(EgressDenied):
            validate_egress_entries([f"http://{host}/"])
