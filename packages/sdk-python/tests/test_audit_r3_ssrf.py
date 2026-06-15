"""Audit-r3 tier-1 plumbing tests: SSRF guard hardening (BUG-B1..B3).

Encodes the audit-r3 P0 SSRF bypass fixes as plumbing-tier tests:

  * BUG-B1: IPv4 127.0.0.0/8 loopback was bypassing the hand-rolled
    RFC1918-only subset. The fix routes IPv4 (and IPv6) through the
    stdlib's full classification (``is_loopback``, ``is_private``,
    ``is_link_local``, ``is_multicast``, ``is_reserved``).
  * BUG-B2: Hostname-based SSRF bypassed the guard entirely because
    the ValueError on ``ipaddress.ip_address(host)`` returned None
    unconditionally. The fix adds an exact + suffix hostname denylist
    (localhost / metadata / kubernetes / *.internal / *.local / *.svc
    / *.localhost).
  * BUG-B3: ``validate_egress_entries`` was previously uninvoked. The
    fix wires it into the SDK-side ReplayCase envelope builder
    (``lifecycle.build_replay_case_envelope``) which the
    ``Run.replay_create`` path now uses.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest


@pytest.mark.plumbing
def test_ipv4_loopback_127_x_x_x_is_now_rejected() -> None:
    """BUG-B1: every address in 127.0.0.0/8 is rejected with reason 'loopback'.

    Prior to audit-r3 the hand-rolled RFC1918-only subset let
    ``127.0.0.1`` / ``127.0.0.2`` / ``127.255.255.254`` silently pass.
    """
    from relay.network_policy import EgressDenied, validate_egress_entries

    for host in ("127.0.0.1", "127.0.0.2", "127.1.2.3", "127.255.255.254"):
        with pytest.raises(EgressDenied) as exc:
            validate_egress_entries([host])
        env = exc.value.envelope
        assert env["denied_reason"] == "loopback", (
            f"expected loopback for {host!r}; got {env!r}"
        )
        assert env["denied_entry"] == host


@pytest.mark.plumbing
def test_ipv4_loopback_via_url_form_is_rejected() -> None:
    """BUG-B1: URL-wrapped 127.0.0.1 is also caught after extraction."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    for entry in (
        "http://127.0.0.1/admin",
        "https://127.0.0.1:8443/metrics",
        "http://127.0.0.1:9999",
    ):
        with pytest.raises(EgressDenied) as exc:
            validate_egress_entries([entry])
        assert exc.value.envelope["denied_reason"] == "loopback"


@pytest.mark.plumbing
def test_ipv4_multicast_unspecified_and_documentation_rejected() -> None:
    """BUG-B1: the stdlib classifications add multicast / unspecified /
    documentation-range (is_private) coverage that the hand-rolled
    subset missed."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    # 0.0.0.0 -> is_unspecified
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["0.0.0.0"])
    assert exc.value.envelope["denied_reason"] in {"reserved", "rfc1918"}

    # 224.0.0.1 -> multicast
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["224.0.0.1"])
    assert exc.value.envelope["denied_reason"] == "multicast"

    # 240.0.0.1 -> is_reserved (240/4 reserved)
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["240.0.0.1"])
    assert exc.value.envelope["denied_reason"] in {"reserved", "rfc1918"}

    # 192.0.2.1 (RFC 5737 documentation TEST-NET-1) -> is_private True
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["192.0.2.1"])
    assert exc.value.envelope["denied_reason"] == "rfc1918"


@pytest.mark.plumbing
def test_cidr_block_allowlist_entries_classified_by_network_address() -> None:
    """A CIDR block whose network/address is internal must be DENIED -- the
    replay sandbox accepts CIDR allowlist entries, so allowlisting a private
    range (e.g. 10.0.0.0/8, fc00::/7) would otherwise authorize the whole block
    (SSRF default-deny bypass). A public-network CIDR stays ALLOWED."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    for cidr in ("10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7"):
        with pytest.raises(EgressDenied):
            validate_egress_entries([cidr])
    # BROAD supernets with a public-looking network address that nevertheless
    # CONTAIN internal ranges must also be denied (overlap, not just the network
    # address): 8.0.0.0/6 contains 10/8; 64.0.0.0/2 contains 127/8; /0 / /1 span
    # everything.
    for broad in ("0.0.0.0/0", "8.8.8.8/0", "8.8.8.0/1", "8.0.0.0/6", "64.0.0.0/2"):
        with pytest.raises(EgressDenied):
            validate_egress_entries([broad])
    # A CIDR fully within public space is allowed (no exception).
    validate_egress_entries(["8.8.8.0/24"])
    validate_egress_entries(["8.0.0.0/8"])  # 8/8 is entirely public


@pytest.mark.plumbing
def test_ipv4_in_ipv6_transition_cidr_blocks_are_denied() -> None:
    """A BROAD CIDR over an IPv4-in-IPv6 transition prefix (IPv4-mapped
    ::ffff:0:0/96, 6to4 2002::/16, NAT64 64:ff9b::/96) must be DENIED.

    A single transition address unwraps + classifies on its embedded IPv4
    (so ``::ffff:10.0.0.1`` is already caught and ``::ffff:8.8.8.8`` stays
    allowed), but a broad CIDR over the transition space has a public-looking
    IPv6 network address while spanning denied embedded IPv4 ranges. Without
    the transition supernets in ``_DENIED_SUPERNETS`` the overlap check would
    pass it (SSRF default-deny bypass). The transition supernets themselves and
    any sub-block must be refused.
    """
    from relay.network_policy import EgressDenied, validate_egress_entries

    for cidr in (
        "::ffff:0:0/96",  # entire IPv4-mapped space
        "::ffff:800:0/102",  # ::ffff:8.0.0.0/X sub-block (public-looking network)
        "2002::/16",  # entire 6to4 space
        "2002:800::/22",  # 6to4 sub-block
        "64:ff9b::/96",  # entire NAT64 space
        "64:ff9b::800:0/102",  # NAT64 sub-block
    ):
        with pytest.raises(EgressDenied):
            validate_egress_entries([cidr])


@pytest.mark.plumbing
def test_single_transition_addresses_classify_on_embedded_ipv4() -> None:
    """A single IPv4-in-IPv6 transition address is denied iff its embedded
    IPv4 is internal -- a public embedded IPv4 stays ALLOWED (no over-block)."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    # Internal embedded IPv4 -> denied.
    for host in (
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:10.0.0.1",  # IPv4-mapped RFC1918
        "2002:a00:1::",  # 6to4 wrapping 10.0.0.1
        "64:ff9b::a00:1",  # NAT64 wrapping 10.0.0.1
    ):
        with pytest.raises(EgressDenied):
            validate_egress_entries([host])

    # Public embedded IPv4 -> allowed (single address, no broad CIDR).
    validate_egress_entries(["::ffff:8.8.8.8"])


@pytest.mark.plumbing
def test_hostname_localhost_bypass_now_blocked() -> None:
    """BUG-B2: literal 'localhost' is rejected with reason 'reserved_hostname'.

    Prior to audit-r3 the ValueError from ``ipaddress.ip_address('localhost')``
    fell through to ``return None`` and silently bypassed the guard.
    """
    from relay.network_policy import EgressDenied, validate_egress_entries

    for host in ("localhost", "LOCALHOST", "LocalHost", "localhost."):
        with pytest.raises(EgressDenied) as exc:
            validate_egress_entries([host])
        env = exc.value.envelope
        assert env["denied_reason"] == "reserved_hostname", (
            f"expected reserved_hostname for {host!r}; got {env!r}"
        )


@pytest.mark.plumbing
def test_hostname_cloud_metadata_names_blocked() -> None:
    """BUG-B2: well-known cloud-metadata hostnames are rejected."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    for host in (
        "metadata.google.internal",
        "metadata",
        "instance-data.ec2.internal",
        "kubernetes.default.svc",
        "kubernetes",
    ):
        with pytest.raises(EgressDenied) as exc:
            validate_egress_entries([host])
        env = exc.value.envelope
        assert env["denied_reason"] == "reserved_hostname", (
            f"expected reserved_hostname for {host!r}; got {env!r}"
        )


@pytest.mark.plumbing
def test_hostname_suffix_denylist() -> None:
    """BUG-B2: hostnames ending in .local / .internal / .svc / .localhost
    / .svc.cluster.local are rejected."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    for host in (
        "myhost.local",
        "etcd.internal",
        "redis.svc",
        "db.svc.cluster.local",
        "anything.localhost",
        "http://myhost.local/path",
        "https://etcd.internal:2379",
    ):
        with pytest.raises(EgressDenied) as exc:
            validate_egress_entries([host])
        env = exc.value.envelope
        assert env["denied_reason"] == "reserved_hostname", (
            f"expected reserved_hostname for {host!r}; got {env!r}"
        )


@pytest.mark.plumbing
def test_public_hostname_still_accepted() -> None:
    """BUG-B2 backstop: public hostnames that are not in the denylist
    continue to pass (general hostname-based SSRF requires DNS-pinning
    policy, out of scope for this guard).
    """
    from relay.network_policy import validate_egress_entries

    # No raise.
    validate_egress_entries(
        [
            "api.openai.com",
            "api.anthropic.com",
            "example.com",
            "https://api.openai.com/v1",
        ]
    )


@pytest.mark.plumbing
def test_validate_egress_entries_wired_to_replay_case_builder() -> None:
    """BUG-B3: the SSRF guard is now invoked by
    ``lifecycle.build_replay_case_envelope``. A poisoned allowlist
    raises EgressDenied at the SDK boundary BEFORE any HTTP I/O."""
    from relay.lifecycle import build_replay_case_envelope
    from relay.network_policy import EgressDenied

    actor = "sha256-" + ("a" * 64)
    manifest = "sha256-" + ("b" * 64)

    # 127.0.0.1 in the allowlist must be rejected.
    with pytest.raises(EgressDenied) as exc:
        build_replay_case_envelope(
            run_id="01JG2YCOMPLETED1234567890123",
            manifest_commit_hash=manifest,
            actor_identity_hash=actor,
            egress_allowlist=["127.0.0.1"],
        )
    assert exc.value.envelope["denied_reason"] == "loopback"

    # localhost in the allowlist must be rejected.
    with pytest.raises(EgressDenied) as exc:
        build_replay_case_envelope(
            run_id="01JG2YCOMPLETED1234567890123",
            manifest_commit_hash=manifest,
            actor_identity_hash=actor,
            egress_allowlist=["http://localhost:8080"],
        )
    assert exc.value.envelope["denied_reason"] == "reserved_hostname"

    # metadata.google.internal in the allowlist must be rejected.
    with pytest.raises(EgressDenied) as exc:
        build_replay_case_envelope(
            run_id="01JG2YCOMPLETED1234567890123",
            manifest_commit_hash=manifest,
            actor_identity_hash=actor,
            egress_allowlist=["metadata.google.internal"],
        )
    assert exc.value.envelope["denied_reason"] == "reserved_hostname"


@pytest.mark.plumbing
def test_build_replay_case_envelope_accepts_clean_allowlist() -> None:
    """BUG-B3: a clean allowlist passes through and lands in the envelope."""
    from relay.lifecycle import (
        REPLAY_CASE_CREATE_SCHEMA_VERSION,
        build_replay_case_envelope,
    )

    actor = "sha256-" + ("a" * 64)
    manifest = "sha256-" + ("b" * 64)
    envelope = build_replay_case_envelope(
        run_id="01JG2YCOMPLETED1234567890123",
        manifest_commit_hash=manifest,
        actor_identity_hash=actor,
        egress_allowlist=["api.openai.com", "api.anthropic.com"],
    )
    assert envelope["schema_version"] == REPLAY_CASE_CREATE_SCHEMA_VERSION
    assert envelope["egress_allowlist"] == [
        "api.openai.com",
        "api.anthropic.com",
    ]
    assert envelope["run_id"] == "01JG2YCOMPLETED1234567890123"
    assert envelope["manifest_commit_hash"] == manifest
    assert envelope["actor_identity_hash"] == actor


@pytest.mark.plumbing
def test_build_replay_case_envelope_no_allowlist_is_no_op() -> None:
    """BUG-B3: the builder is backward compatible when no allowlist is supplied."""
    from relay.lifecycle import build_replay_case_envelope

    actor = "sha256-" + ("a" * 64)
    manifest = "sha256-" + ("b" * 64)
    envelope = build_replay_case_envelope(
        run_id="01JG2YCOMPLETED1234567890123",
        manifest_commit_hash=manifest,
        actor_identity_hash=actor,
    )
    assert envelope["egress_allowlist"] == []
