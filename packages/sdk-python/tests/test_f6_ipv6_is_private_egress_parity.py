"""F6 (keystone #16 + #7): native-IPv6 ``is_private`` egress-guard oracle.

The Python SDK egress SSRF guard (``relay.network_policy._classify``) classifies
a native IPv6 host through CPython ``ipaddress.IPv6Address.is_private``. The
TypeScript SDK (``packages/sdk-typescript/src/run.ts`` ``_classifyIpv6`` ->
``_ipv6IsPrivate``) hand-rolls a faithful REPLICA of that CPython table so the
two SDKs reach the SAME allow/deny verdict for a replay ``egress_allowlist``
entry (keystone #16). A divergence is a Py<->TS SSRF verdict split.

This module is the STRUCTURAL TRIPWIRE for that hand-rolled TS copy. It pins:

  1. the verdict the Python reference produces for each address (the contract the
     TS mirror must match -- the same address list as
     ``packages/sdk-typescript/test/replay_egress_ipv6_is_private_parity.test.ts``);
  2. the LIVE CPython ``is_private`` flag for each address. ``is_private`` tracks
     a MOVING IANA special-registry definition (the 2001::/23 and 3fff::/20
     blocks and their global carve-out exceptions were added / revised across
     CPython point releases). If a future CPython mutates the table, assertion
     (2) breaks HERE first -- the loud signal that the TS hand-rolled
     ``_ipv6IsPrivate`` table must be re-synced to match.

Bug context: before F6, the TS subset omitted 2001::/23, 3fff::/20, and the
NAT64 local-use 64:ff9b:1::/48, so 2001::1 / 2001:2::1 / 2001:10::1 / 3fff::1 /
64:ff9b:1::1 were ALLOWED by the TS replay allowlist while CPython DENIES them --
an SSRF default-deny bypass.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ipaddress

import pytest

# CPython is_private == True -> network_policy._classify denies as
# ("rfc1918", "fc00::/7"). These are the SAME addresses the TS parity suite
# asserts DENY for. The first five are the finding's regressed set.
_PRIVATE_DENY: tuple[str, ...] = (
    "2001::1",
    "2001:2::1",
    "2001:10::1",
    "3fff::1",
    "64:ff9b:1::1",
    "::1",
    "fc00::1",
    "fdff::1",
    "2001:db8::1",
    "100::1",
)

# CPython is_private == False -> _classify == None (ALLOWED). The 2001:* entries
# are the _private_networks_exceptions (global carve-outs inside 2001::/23); the
# rest are public global-unicast / above-block boundaries. TS must NOT over-block
# these.
_GLOBAL_ALLOW: tuple[str, ...] = (
    "2001:1::1",
    "2001:1::2",
    "2001:3::1",
    "2001:4:112::1",
    "2001:20::1",
    "2001:2f:ffff::1",
    "2001:30::1",
    "2606:4700:4700::1111",
    "2620:fe::fe",
    "3fff:ffff::1",  # just ABOVE 3fff::/20 (only 3fff:0000-3fff:0fff is private)
)


@pytest.mark.plumbing
@pytest.mark.parametrize("host", _PRIVATE_DENY)
def test_private_ipv6_denied_as_rfc1918(host: str) -> None:
    """The Python egress guard denies each private IPv6 host as rfc1918/fc00::/7
    -- the reference verdict the TS _ipv6IsPrivate mirror must match."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries([host])
    env = exc.value.envelope
    assert env["denied_reason"] == "rfc1918", (host, env["denied_reason"])
    assert env["denied_cidr"] == "fc00::/7", (host, env["denied_cidr"])


@pytest.mark.plumbing
@pytest.mark.parametrize("host", _GLOBAL_ALLOW)
def test_global_ipv6_allowed_no_over_block(host: str) -> None:
    """The Python egress guard ALLOWS each global/exception IPv6 host (no
    over-block) -- the reference verdict the TS mirror must match."""
    from relay.network_policy import validate_egress_entries

    # No raise == allowed (the guard returns silently for a non-denied entry).
    validate_egress_entries([host])


@pytest.mark.plumbing
def test_cpython_is_private_oracle_unchanged() -> None:
    """LIVE oracle tripwire: pin CPython ``is_private`` for every address.

    If a future CPython revises the IANA special-registry ``is_private`` table,
    THIS assertion fails first -- the signal that the TS hand-rolled
    ``_ipv6IsPrivate`` / ``_PRIVATE_IPV6_NETWORKS`` table in run.ts must be
    re-synced (and its parity corpus regenerated)."""
    for host in _PRIVATE_DENY:
        assert ipaddress.ip_address(host).is_private is True, (
            f"{host}: CPython is_private changed to False -- re-sync the TS "
            f"_ipv6IsPrivate table in packages/sdk-typescript/src/run.ts"
        )
    for host in _GLOBAL_ALLOW:
        assert ipaddress.ip_address(host).is_private is False, (
            f"{host}: CPython is_private changed to True -- re-sync the TS "
            f"_ipv6IsPrivate table in packages/sdk-typescript/src/run.ts"
        )
