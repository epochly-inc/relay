"""SSRF egress guard MUST reject numeric-IPv4 and IPv6 transition forms.

Two P2 SSRF under-blocks found by /structural-review (default-deny egress,
keystone #7):

  * BUG 1 -- non-dotted-decimal IPv4 literals. ``_classify`` relied on
    ``ipaddress.ip_address(host)``, which REJECTS integer-form
    ('2130706433' == 127.0.0.1), hex-form ('0x7f000001'), and
    short/octal forms ('127.1', '0177.0.0.1'). These raised ValueError,
    fell through to the hostname denylist (no match), and returned None
    -> ALLOWED. But the OS resolver / libcurl / requests-via-socket WILL
    interpret these as the internal IP. The fix canonicalizes numeric
    IPv4 the same way the libc resolver does (``socket.inet_aton`` ->
    ``socket.inet_ntoa``) and re-classifies on the dotted-decimal form.
    A numeric form normalizing to a PUBLIC IP stays ALLOWED.

  * BUG 2 -- IPv4-in-IPv6 transition forms. ``_classify`` only unwrapped
    ``ip.ipv4_mapped`` (::ffff:0:0/96). It did NOT unwrap 6to4
    (2002::/16, ``ip.sixtofour``), NAT64 (64:ff9b::/96), or
    IPv4-compatible (::/96). So ``[2002:a9fe:a9fe::]`` (embeds
    169.254.169.254) returned None -> ALLOWED. The fix unwraps each
    transition form and re-classifies on the embedded IPv4; only an
    embedded IPv4 in a blocked class is rejected (no over-block of
    transition forms wrapping a public IPv4).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# BUG 1 -- numeric-IPv4 encodings
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.parametrize(
    ("host", "expected_reason"),
    [
        # integer-form 127.0.0.1
        ("2130706433", "loopback"),
        # hex-form 127.0.0.1
        ("0x7f000001", "loopback"),
        # short-form 127.1 -> 127.0.0.1
        ("127.1", "loopback"),
        # octal-form 0177.0.0.1 -> 127.0.0.1
        ("0177.0.0.1", "loopback"),
        # integer-form 169.254.169.254 (AWS/GCP metadata)
        ("2852039166", "cloud_metadata"),
    ],
)
def test_numeric_ipv4_internal_forms_are_blocked(
    host: str, expected_reason: str
) -> None:
    """Numeric-IPv4 encodings of internal/metadata addresses are denied with
    the SAME reason their dotted-decimal form would yield.

    At base commit this is RED: ``ipaddress.ip_address`` raises ValueError
    on these forms, they fall to the hostname denylist (no match), and
    ``validate_egress_entries`` returns silently -- a default-deny bypass.
    """
    from relay.network_policy import EgressDenied, validate_egress_entries

    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries([host])
    assert exc.value.envelope["denied_reason"] == expected_reason, (
        f"{host!r}: expected denied_reason={expected_reason!r}, "
        f"got {exc.value.envelope['denied_reason']!r}"
    )


@pytest.mark.plumbing
def test_numeric_ipv4_internal_via_url_form_is_blocked() -> None:
    """BUG 1 via URL: ``http://2130706433/latest/meta-data/`` is caught after
    host extraction (the canonical SSRF attack string)."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    for entry in (
        "http://2130706433/latest/meta-data/",
        "http://0x7f000001/admin",
        "https://2852039166/latest/meta-data/",
    ):
        with pytest.raises(EgressDenied):
            validate_egress_entries([entry])


@pytest.mark.plumbing
def test_numeric_ipv4_public_form_is_not_over_blocked() -> None:
    """SECURITY no-false-positive guard: a numeric form normalizing to a
    PUBLIC IP (134744072 == 8.8.8.8) must STAY ALLOWED, identical to the
    dotted-decimal path. Do not block all-numeric strings wholesale."""
    from relay.network_policy import validate_egress_entries

    # 134744072 == 8.8.8.8 (public). No raise.
    validate_egress_entries(["134744072"])
    validate_egress_entries(["http://134744072/resolve"])


@pytest.mark.plumbing
def test_hostname_still_classified_as_hostname_not_numeric() -> None:
    """No regression: alpha hostnames must NOT be coerced through the numeric
    path (inet_aton raises on them) -- public hostnames still pass, denylist
    hostnames still trip 'reserved_hostname'."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    # Public hostnames continue to pass.
    validate_egress_entries(["api.openai.com", "example.com"])

    # Denylist hostname still trips reserved_hostname (not numeric).
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["localhost"])
    assert exc.value.envelope["denied_reason"] == "reserved_hostname"


# ---------------------------------------------------------------------------
# BUG 2 -- IPv6 transition forms (6to4 / NAT64 / IPv4-compatible)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.parametrize(
    ("host", "expected_reason"),
    [
        # 6to4 2002::/16 wrapping 169.254.169.254 (a9fe:a9fe) metadata.
        ("[2002:a9fe:a9fe::]", "cloud_metadata"),
        # NAT64 64:ff9b::/96 wrapping 169.254.169.254 metadata.
        ("[64:ff9b::a9fe:a9fe]", "cloud_metadata"),
        # IPv4-compatible ::/96 wrapping 169.254.169.254 metadata.
        ("[::a9fe:a9fe]", "cloud_metadata"),
        # 6to4 wrapping a loopback 127.0.0.1 (7f00:0001).
        ("[2002:7f00:1::]", "loopback"),
        # NAT64 wrapping RFC1918 10.0.0.5 (0a00:0005).
        ("[64:ff9b::a00:5]", "rfc1918"),
    ],
)
def test_ipv6_transition_forms_wrapping_internal_are_blocked(
    host: str, expected_reason: str
) -> None:
    """6to4 / NAT64 / IPv4-compatible transition forms that embed an
    internal/metadata IPv4 are denied with the SAME reason the bare IPv4
    form would yield.

    At base commit this is RED: ``_classify`` only unwraps ``ipv4_mapped``,
    so the embedded IPv4 in these transition forms is never inspected and
    ``validate_egress_entries`` returns silently.
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
def test_ipv6_transition_forms_wrapping_public_are_not_over_blocked() -> None:
    """SECURITY no-false-positive guard: a 6to4 / NAT64 / IPv4-compatible
    form wrapping a PUBLIC IPv4 (8.8.8.8 == 0808:0808) must STAY ALLOWED.
    Do not over-block transition forms wholesale."""
    from relay.network_policy import validate_egress_entries

    # 6to4 wrapping 8.8.8.8 -- previously would be over-blocked by the
    # native IPv6 ``is_private`` flag if not unwrapped first.
    validate_egress_entries(["http://[2002:808:808::]/resolve"])
    # NAT64 wrapping 8.8.8.8.
    validate_egress_entries(["http://[64:ff9b::808:808]/resolve"])
    # IPv4-compatible wrapping 8.8.8.8.
    validate_egress_entries(["http://[::808:808]/resolve"])


# ---------------------------------------------------------------------------
# Regression -- pre-existing classification paths unchanged
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_existing_paths_unchanged_regression() -> None:
    """ipv4_mapped + dotted-decimal + native IPv6 + public-host cases all
    still behave exactly as before."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    # ipv4_mapped internal still blocked.
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["http://[::ffff:169.254.169.254]/"])
    assert exc.value.envelope["denied_reason"] == "cloud_metadata"

    # ipv4_mapped public still allowed.
    validate_egress_entries(["http://[::ffff:8.8.8.8]/resolve"])

    # dotted-decimal loopback still blocked.
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["127.0.0.1"])
    assert exc.value.envelope["denied_reason"] == "loopback"

    # dotted-decimal metadata still blocked.
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["169.254.169.254"])
    assert exc.value.envelope["denied_reason"] == "cloud_metadata"

    # native IPv6 loopback / ULA / link-local still blocked.
    for host in ("[::1]", "[fc00::1]", "[fe80::1]"):
        with pytest.raises(EgressDenied):
            validate_egress_entries([f"http://{host}/"])

    # public dotted-decimal + hostnames still allowed.
    validate_egress_entries(
        ["8.8.8.8", "1.1.1.1", "api.openai.com", "https://api.anthropic.com/v1"]
    )
