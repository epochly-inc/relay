"""SSRF egress allowlist validation (VAL-V2M08-011..014).

Spec anchor: AI line 5664.

The replay-case submit path validates each entry in a caller-supplied
``egress_allowlist`` and rejects any host that falls inside an RFC 1918
private range, the link-local block (169.254.0.0/16), or one of the
well-known cloud-metadata endpoints (AWS / GCP / Azure / Alibaba).

Rejected entries surface as :class:`EgressDenied` carrying a structured
envelope dict whose keys are stable wire-format names:

* ``code`` -- ``"RELAY-REPLAY-SSRF"`` (a word-form code per the
  precedent set by ``RELAY-EVID-SIGCOUNT-EXCEEDED``; the numeric-suffix
  registry guard VAL-W1-057 explicitly tolerates word-form codes that
  are defined in source rather than in the YAML).
* ``http_status`` -- ``400``.
* ``denied_entry`` -- the caller-supplied entry string (verbatim, no
  URL canonicalization) so the caller can correlate.
* ``denied_reason`` -- one of ``rfc1918``, ``link_local``, or
  ``cloud_metadata``.
* ``denied_cidr`` -- the matching CIDR / well-known endpoint, when
  the rejection is range-based.

The denylist is closed (default-deny is enforced by treating any
RFC 1918, link-local, or cloud-metadata match as a rejection); the
allowlist is the caller's responsibility, but each entry MUST first
clear this set of guards before it is honored.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ipaddress
import socket
import unicodedata
from collections.abc import Iterable
from typing import Any, Final
from urllib.parse import urlparse

# Word-form code per VAL-V2M08-011 contract. Not in the numeric-suffix
# YAML registry; follows the RELAY-EVID-SIGCOUNT-EXCEEDED precedent.
RELAY_REPLAY_SSRF: Final[str] = "RELAY-REPLAY-SSRF"
_HTTP_STATUS: Final[int] = 400

# Well-known cloud-metadata endpoints (spec AI line 5664). The check
# matches the literal IP / hostname; the link-local block 169.254/16
# catches IPv4 cloud metadata as a separate `link_local` reason. The
# explicit set below upgrades the most-targeted endpoints to
# `cloud_metadata` so detection bots can route the alarm differently.
CLOUD_METADATA_IPS: Final[frozenset[str]] = frozenset(
    {
        "169.254.169.254",  # AWS EC2, GCP, Azure, OpenStack
        "100.100.100.200",  # Alibaba Cloud
        "fd00:ec2::254",  # AWS IPv6 metadata
    }
)

# RFC 1918 private IPv4 ranges.
_RFC1918_NETWORKS: Final[tuple[ipaddress.IPv4Network, ...]] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

# Special-purpose / non-global ranges a CIDR allowlist entry must not OVERLAP.
# A broad CIDR supernet (e.g. 8.0.0.0/6, 0.0.0.0/0) can contain these even when
# its network address looks public, so the CIDR branch of _classify denies any
# entry overlapping one of them. Mirrored byte-for-byte in the TS SDK
# (run.ts _DENIED_SUPERNETS) for Py<->TS verdict parity.
_DENIED_SUPERNETS: Final[
    tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
] = tuple(
    ipaddress.ip_network(c)
    for c in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::1/128",
        "::/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
        "2001:db8::/32",
        # IETF special-registry PRIVATE blocks (no global carve-out exceptions)
        # that the single-host IPv6 path denies via ip.is_private: 3fff::/20 (RFC
        # 9637 documentation) and 64:ff9b:1::/48 (NAT64 local-use). Without these
        # the OVERLAP check admitted a BROAD CIDR whose network address is public
        # but whose range CONTAINS the private block -- e.g. 3fff:ffff::1/16 (the
        # /16 spans 3fff::/20) -- an SSRF gap and an inconsistency with the
        # single-host deny. 2001::/23 is handled SEPARATELY (it HAS global
        # carve-out exceptions; see _classify) so an all-global exception CIDR is
        # not over-blocked. Mirrored byte-for-byte in run.ts.
        "3fff::/20",
        "64:ff9b:1::/48",
        # IPv4-in-IPv6 TRANSITION prefixes: a broad CIDR over the IPv4-mapped
        # (::ffff:0:0/96), 6to4 (2002::/16), NAT64 (64:ff9b::/96), or the
        # deprecated IPv4-compatible (::/96) space can embed denied IPv4 ranges
        # with a public-looking IPv6 network address -- e.g. ::800:0/102 has the
        # public-looking network ::8.0.0.0 yet spans ::a00:0 == 10.0.0.0. A
        # single transition address still unwraps + classifies via the
        # direct-classify step (incl. _classify's IPv4-compatible ::/96 unwrap);
        # these entries deny the BROAD transition-form CIDRs the overlap check
        # covers. ::/96 subsumes the ::1/128 and ::/128 specials above.
        "::ffff:0:0/96",
        "2002::/16",
        "64:ff9b::/96",
        "::/96",
    )
)

# The 2001::/23 IETF protocol-assignments PRIVATE block and its global carve-out
# EXCEPTIONS (CPython _private_networks_exceptions: the sub-blocks that are
# is_private == False / is_global == True even though they sit inside 2001::/23).
# A CIDR allowlist entry is denied for OVERLAPPING the PRIVATE portion of
# 2001::/23, but an entry FULLY CONTAINED in the GLOBAL portion (any one
# exception OR a CIDR spanning ADJACENT exceptions, e.g. 2001:20::/27 == the
# union of 2001:20::/28 + 2001:30::/28) is NOT over-blocked -- it is global
# address space the single-host path also allows. To get that exactly right we
# precompute the PRIVATE REMAINDER of 2001::/23 (the supernet minus the union of
# all exceptions) as a sorted list of [first, last] integer intervals and deny a
# CIDR only when it overlaps one of those private intervals. Mirrored byte-for-
# byte in run.ts (_IPV6_2001_23 / _PRIVATE_IPV6_EXCEPTIONS /
# _IPV6_2001_23_PRIVATE_REMAINDER -- same interval-subtraction algorithm).
_IPV6_2001_23_NETWORK: Final[ipaddress.IPv6Network] = ipaddress.IPv6Network(
    "2001::/23"
)
_IPV6_2001_23_EXCEPTIONS: Final[tuple[ipaddress.IPv6Network, ...]] = tuple(
    ipaddress.IPv6Network(c)
    for c in (
        "2001:1::1/128",
        "2001:1::2/128",
        "2001:3::/32",
        "2001:4:112::/48",
        "2001:20::/28",
        "2001:30::/28",
    )
)


def _private_remainder(
    supernet: ipaddress.IPv6Network,
    exceptions: tuple[ipaddress.IPv6Network, ...],
) -> tuple[tuple[int, int], ...]:
    """The half-open-free [first, last] integer intervals of ``supernet`` that are
    NOT covered by any exception (the PRIVATE remainder).

    Sweeps the exceptions in address order, accumulating gaps; ADJACENT or
    overlapping exceptions merge via ``max(cursor, e_last + 1)`` so a CIDR
    spanning two touching exception blocks leaves no spurious private sliver.
    Deterministic and side-effect free -- the TS mirror runs the identical
    algorithm so both SDKs deny exactly the same CIDRs."""
    first = int(supernet.network_address)
    last = int(supernet.broadcast_address)
    excs = sorted(
        (int(e.network_address), int(e.broadcast_address)) for e in exceptions
    )
    remainder: list[tuple[int, int]] = []
    cursor = first
    for e_first, e_last in excs:
        if e_first > cursor:
            remainder.append((cursor, e_first - 1))
        cursor = max(cursor, e_last + 1)
    if cursor <= last:
        remainder.append((cursor, last))
    return tuple(remainder)


_IPV6_2001_23_PRIVATE_REMAINDER: Final[tuple[tuple[int, int], ...]] = (
    _private_remainder(_IPV6_2001_23_NETWORK, _IPV6_2001_23_EXCEPTIONS)
)

# Link-local IPv4 range.
_LINK_LOCAL_V4: Final[ipaddress.IPv4Network] = ipaddress.IPv4Network(
    "169.254.0.0/16"
)

# IPv4-in-IPv6 transition ranges whose embedded IPv4 lives in the low 32
# bits (structural-review BUG 2). 6to4 (2002::/16) is unwrapped via the
# stdlib ``IPv6Address.sixtofour`` accessor instead of a low-32-bit mask
# because its IPv4 is embedded in bits 16-48, not the low 32.
_NAT64_NETWORK: Final[ipaddress.IPv6Network] = ipaddress.IPv6Network(
    "64:ff9b::/96"
)
_IPV4_COMPAT_NETWORK: Final[ipaddress.IPv6Network] = ipaddress.IPv6Network(
    "::/96"
)

# Hostname denylist (BUG-B2 / audit-r3). The stdlib ``ipaddress.ip_address``
# raises ValueError on a literal hostname; without an explicit denylist,
# names that resolve to internal infrastructure (``localhost``,
# ``metadata.google.internal``, ``kubernetes.default.svc``, and the
# ``.local`` / ``.internal`` / ``.svc`` / ``.localhost`` suffix families)
# would silently bypass the SSRF guard. Hostname-based SSRF in the
# general case requires DNS-pinning policy (resolve once, pin the
# returned IP, validate the IP against the same guard before the
# connection is made). The denylist below catches the well-known
# infrastructure names that resolve to interior addresses on the major
# clouds and Kubernetes; the DNS-pinning policy is a separate concern
# tracked under the replay-sandbox network-policy primitive.
_HOSTNAME_DENYLIST_EXACT: Final[frozenset[str]] = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.google.internal",
        "instance-data.ec2.internal",
        "kubernetes",
        "kubernetes.default.svc",
    }
)
_HOSTNAME_DENYLIST_SUFFIXES: Final[tuple[str, ...]] = (
    ".local",
    ".internal",
    ".svc",
    ".svc.cluster.local",
    ".localhost",
)


class EgressDenied(Exception):
    """Raised when an egress allowlist entry is denied by policy.

    The structured rejection envelope is on :attr:`envelope`; the human
    message echoes ``denied_entry`` so the exception's repr is
    self-explanatory in logs.
    """

    def __init__(self, envelope: dict[str, Any]) -> None:
        self.envelope = envelope
        denied_entry = envelope.get("denied_entry", "")
        denied_reason = envelope.get("denied_reason", "")
        super().__init__(
            f"egress entry {denied_entry!r} denied by SSRF guard "
            f"(reason={denied_reason})"
        )


def _lenient_url_hostname(entry: str) -> str:
    """Lenient URL host extraction that never raises -- byte-identical to the
    TS SDK's ``_urlparseHostname`` (packages/sdk-typescript/src/run.ts).

    Used only as the fallback when CPython's strict ``urlparse`` raises
    ``ValueError`` on a bracketed-IPv4 / empty-bracket / malformed-bracket
    authority. Mirrors urlparse's algorithm MINUS the bracket-content
    validation: strip ASCII tab/CR/LF (CPython urlsplit hardening), take the
    netloc as the authority after ``scheme://`` up to the first ``/``/``?``/
    ``#``, take the host as the part after the LAST ``@`` (userinfo split),
    strip a bracketed form (inner only) or a trailing ``:port``, and lowercase.
    Strips brackets without validating their contents, exactly like the TS
    port, so both SDKs classify the same inner string.
    """
    cleaned = entry.replace("\t", "").replace("\r", "").replace("\n", "")
    scheme_idx = cleaned.find("://")
    rest = cleaned[scheme_idx + 3:]
    end = len(rest)
    for sep in ("/", "?", "#"):
        i = rest.find(sep)
        if i >= 0 and i < end:
            end = i
    netloc = rest[:end]
    at = netloc.rfind("@")
    hostinfo = netloc[at + 1:] if at >= 0 else netloc
    open_br = hostinfo.find("[")
    if open_br >= 0:
        bracketed = hostinfo[open_br + 1:]
        close_br = bracketed.find("]")
        hostname = bracketed[:close_br] if close_br >= 0 else bracketed
    else:
        colon = hostinfo.find(":")
        hostname = hostinfo[:colon] if colon >= 0 else hostinfo
    return hostname.lower()


def _extract_host(entry: str) -> str:
    """Return the host portion of ``entry`` (URL or bare host).

    Supported entry forms:

      * URL with scheme: ``https://host[:port]/path`` or
        ``https://[ipv6][:port]/path`` -- delegated to ``urlparse``,
        whose ``hostname`` attribute strips brackets per RFC 3986.
      * Bare IPv4 / hostname, optionally with port: ``10.0.0.1`` or
        ``10.0.0.1:8080``. The single trailing ``:port`` is stripped.
      * Bare bracketed IPv6, optionally with port (RFC 3986
        authority form): ``[::1]``, ``[::1]:8080``,
        ``[fe80::1]:8080``. The brackets are stripped and any
        trailing ``:port`` after the closing bracket is discarded.
      * Bare unbracketed IPv6 literal: ``::1``, ``fe80::1``. Returned
        as-is (no port-stripping; the unbracketed form cannot carry
        a port unambiguously and the caller's input is treated as a
        pure host literal).
    """
    if "://" in entry:
        try:
            parsed = urlparse(entry)
            host = parsed.hostname or ""
            return host
        except ValueError:
            # CPython 3.12+ urlparse (._check_bracketed_host) RAISES on a
            # bracketed-IPv4 (``https://[10.0.0.1]/``), an empty/non-IP bracket
            # (``https://[]/``), or a malformed/stray bracket
            # (``http://foo[bar/``). The TS SDK's hand-rolled _urlparseHostname
            # never validates bracket contents -- it strips the brackets and
            # classifies the inner string -- so an unguarded urlparse here both
            # CRASHES the SSRF screen (the contract is silent-allow or
            # EgressDenied, never a raw ValueError) AND diverges from the TS
            # verdict. Fall back to the SAME lenient, never-throwing bracket
            # extraction the TS port uses so both SDKs agree byte-for-byte.
            return _lenient_url_hostname(entry)
    # Bare host -- may carry an optional port and IPv6 bracket form.
    host = entry
    # RFC 3986 bracketed IPv6 authority form: ``[ipv6]`` or
    # ``[ipv6]:port``. Strip brackets and discard any trailing port.
    if host.startswith("["):
        end = host.find("]")
        if end > 0:
            return host[1:end]
        return host
    if ":" in host and host.count(":") == 1:
        # Likely host:port (not IPv6 since IPv6 has multiple colons).
        host = host.split(":", 1)[0]
    return host


def _canonical_numeric_ipv4(host: str) -> str | None:
    """Return the dotted-decimal IPv4 a libc resolver would derive from a
    numeric-IPv4 literal, or ``None`` if ``host`` is not such a literal.

    Structural-review SSRF under-block (BUG 1): ``ipaddress.ip_address``
    REJECTS the non-dotted-decimal IPv4 encodings that ``inet_aton`` /
    ``gethostbyname`` (and therefore libcurl, requests-via-socket, and the
    OS resolver) silently accept: integer-form (``2130706433`` ==
    127.0.0.1), hex-form (``0x7f000001``), octal-form (``0177.0.0.1``),
    and short 1-to-4-part forms (``127.1`` -> 127.0.0.1). Left unhandled
    these raised ValueError in ``_classify``, fell through the hostname
    denylist (no match), and were ALLOWED -- a default-deny egress bypass
    because the HTTP client still reaches the internal IP.

    We canonicalize the SAME WAY the libc resolver does (``inet_aton`` ->
    ``inet_ntoa``) so the dotted-decimal result can be re-run through the
    existing classification. CRITICAL: this only NORMALIZES; the caller
    must still classify the result, so a numeric form normalizing to a
    PUBLIC IP stays ALLOWED exactly like its dotted-decimal twin. We do
    NOT block all-numeric strings wholesale.

    Alpha-guard: ``inet_aton`` accepts only digits, dots, and a leading
    ``0x``/``0X`` hex prefix per part; a real DNS name (``api.openai.com``,
    ``localhost``) raises OSError and returns ``None`` here so it stays on
    the hostname path. We additionally reject any host carrying an alpha
    char outside a ``0x`` hex prefix, so an accidental ``inet_aton`` accept
    of a name-like token never coerces a hostname into the numeric path.
    """
    # Reject anything that is not an IPv4 literal: only ASCII digits, dots,
    # and 'x'/'X' (the hex-prefix marker) are permitted. Hex letters a-f
    # appear only after a '0x' marker, so a part like '0xff' is fine while a
    # bare 'face' (a hostname label) is rejected. We enforce that every 'x'
    # is immediately preceded by a '0' (i.e. a valid '0x' prefix) and that
    # no other alpha appears except hex digits inside a hex part.
    if not host:
        return None
    for part in host.split("."):
        if not part:
            # Empty part (e.g. leading/trailing/double dot) -- not a clean
            # numeric literal; let inet_aton decide but most will OSError.
            continue
        lowered = part.lower()
        if lowered.startswith("0x"):
            body = lowered[2:]
            if not body or any(c not in "0123456789abcdef" for c in body):
                return None
        else:
            # Non-hex part must be pure (decimal/octal) digits.
            if any(not c.isdigit() for c in lowered):
                return None
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    return socket.inet_ntoa(packed)


def _classify(host: str) -> tuple[str, str] | None:
    """Return ``(denied_reason, denied_cidr_or_endpoint)`` or ``None``
    if ``host`` is not denied by the SSRF guard.

    Audit-r3 BUG-B1 + BUG-B2 hardening: this function rejects
    (a) every IPv4/IPv6 address the stdlib classifies as loopback,
    private, link-local, multicast, or reserved (the previous
    hand-rolled RFC1918-only subset let 127.0.0.0/8 silently pass);
    (b) a denylist of well-known infrastructure hostnames (the previous
    behavior returned ``None`` on any ValueError, letting
    ``localhost`` / ``metadata.google.internal`` /
    ``kubernetes.default.svc`` / ``*.internal`` / ``*.local`` etc.
    bypass the guard). General hostname-based SSRF in addition to this
    denylist requires DNS-pinning policy (resolve, pin the IP, validate
    the pinned IP against this same guard) -- that is a separate
    primitive owned by the replay-sandbox network policy.
    """
    if not host:
        return None
    # Normalize BEFORE any IP/metadata classification: a destination wrapped in
    # whitespace ("10.0.0.1 ", "\t169.254.169.254\n") or carrying a trailing
    # FQDN-root dot ("169.254.169.254." / "169.254.169.254..") is dialed by the
    # resolver as the bare address, but ipaddress.ip_address / inet_aton reject
    # the decorated form -- so without this the literal would MISS the metadata /
    # RFC1918 / loopback checks and fall through the hostname denylist as a
    # NON-match (ALLOWED): an SSRF default-deny bypass. Strip surrounding
    # whitespace and trailing dots up front (no resolvable host has either, so
    # this never over-blocks a public destination). This also normalizes the
    # URL-derived host from _extract_host through the same chokepoint.
    host = host.strip().rstrip(".")
    if not host:
        return None
    # Cloud-metadata literal match takes precedence over link-local so
    # 169.254.169.254 attributes correctly.
    if host in CLOUD_METADATA_IPS:
        return ("cloud_metadata", host)
    # CIDR-block entry (e.g. "10.0.0.0/8", "fc00::/7"): the replay sandbox
    # accepts CIDR allowlist entries, so a private/reserved RANGE must be denied
    # like a single internal address -- otherwise allowlisting "10.0.0.0/8"
    # authorizes the whole private block (SSRF default-deny bypass).
    if "/" in host:
        # (1) Classify the network/address portion directly: a specific subnet
        # whose network address is internal (10.0.0.0/8, fc00::/7) is denied,
        # and this is the common case.
        direct = _classify(host.split("/", 1)[0])
        if direct is not None:
            return direct
        # (2) A BROAD CIDR can be a SUPERNET that CONTAINS internal ranges even
        # with a public-looking network address (8.0.0.0/6 contains 10.0.0.0/8;
        # 64.0.0.0/2 contains 127.0.0.0/8; 0.0.0.0/0 contains everything).
        # is_global does NOT catch these (it checks subnet-OF, not contains), so
        # deny any CIDR that OVERLAPS a special-purpose range. The supernet list
        # is mirrored byte-for-byte in the TS SDK for Py<->TS verdict parity.
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError:
            return None
        for denied in _DENIED_SUPERNETS:
            if isinstance(net, type(denied)) and net.overlaps(denied):
                return ("rfc1918", str(denied))
        # 2001::/23 with EXCEPTION-awareness (it has global carve-outs, unlike
        # the flat supernets above): deny a CIDR ONLY when it overlaps the PRIVATE
        # remainder of 2001::/23 (the supernet minus the union of all global
        # exceptions). A CIDR fully inside the global portion -- one exception
        # (2001:20::/28) OR a span of adjacent exceptions (2001:20::/27) -- hits
        # no private interval and is ALLOWED; a CIDR straddling private +
        # exception space (2001:3::1/31) hits a private interval and is denied.
        if isinstance(net, ipaddress.IPv6Network):
            n_first = int(net.network_address)
            n_last = int(net.broadcast_address)
            for r_first, r_last in _IPV6_2001_23_PRIVATE_REMAINDER:
                if n_first <= r_last and r_first <= n_last:
                    return ("rfc1918", "2001::/23")
        return None
    # IPv4 / IPv6 range checks.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Structural-review BUG 1: ``ipaddress.ip_address`` rejects the
        # non-dotted-decimal IPv4 encodings (integer / hex / octal /
        # short-form) that the libc resolver -- and therefore the HTTP
        # client that will actually dial this host -- silently accepts.
        # Canonicalize them the SAME WAY ``inet_aton`` does and re-run the
        # full classification so e.g. ``2130706433`` is rejected as
        # 127.0.0.1 while ``134744072`` stays ALLOWED as the public
        # 8.8.8.8 (no over-block of numeric forms that resolve public).
        canonical = _canonical_numeric_ipv4(host)
        if canonical is not None and canonical != host:
            return _classify(canonical)
        # Not a literal IP -- run the hostname denylist (BUG-B2).
        # Normalize: lowercase + strip a single trailing dot (FQDN root).
        normalized = host.lower()
        if normalized.endswith("."):
            normalized = normalized[:-1]
        if normalized in _HOSTNAME_DENYLIST_EXACT:
            return ("reserved_hostname", normalized)
        for suffix in _HOSTNAME_DENYLIST_SUFFIXES:
            if normalized.endswith(suffix):
                return ("reserved_hostname", suffix)
        # Hostname not in the denylist. General hostname-based SSRF is
        # out of scope for this guard; the caller is expected to
        # resolve hostnames through a separate DNS-pinning policy.
        return None
    # IPv4: cloud-metadata already matched; RFC 1918 and the IPv4
    # link-local /16 keep their specific ``rfc1918`` / ``link_local``
    # reason codes so downstream alerting routes correctly.
    if isinstance(ip, ipaddress.IPv4Address):
        for net in _RFC1918_NETWORKS:
            if ip in net:
                return ("rfc1918", str(net))
        if ip in _LINK_LOCAL_V4:
            return ("link_local", str(_LINK_LOCAL_V4))
        # BUG-B1: the previous implementation stopped here, letting
        # 127.0.0.0/8 loopback through. Use the stdlib's full
        # classification for every other reserved/internal range so the
        # guard is comprehensive rather than a hand-rolled subset.
        if ip.is_loopback:
            return ("loopback", "127.0.0.0/8")
        if ip.is_multicast:
            return ("multicast", "224.0.0.0/4")
        if ip.is_unspecified:
            return ("reserved", "0.0.0.0/8")
        if ip.is_private:
            # Catches any remaining RFC1918-equivalent block the
            # explicit table above did not enumerate (e.g., the
            # CGNAT 100.64.0.0/10 block which Python tags as private).
            return ("rfc1918", "private")
        if ip.is_reserved:
            return ("reserved", "ipv4_reserved")
        return None
    # IPv6: check link-local fe80::/10 and the well-known metadata
    # literals (handled above by string match for fd00:ec2::254).
    if isinstance(ip, ipaddress.IPv6Address):
        # VAL-ISO-018: an IPv4-mapped IPv6 address (``::ffff:a.b.c.d``)
        # tunnels an IPv4 destination through an IPv6 literal. The stdlib
        # ``is_*`` flags on the wrapper do not reliably reflect the
        # embedded IPv4's class (e.g. ``::ffff:100.100.100.200`` -- the
        # Alibaba metadata endpoint -- has EVERY ``is_*`` flag False), and
        # the literal cloud-metadata match above never fires for the
        # wrapped form. Unwrap and re-classify on the embedded IPv4 BEFORE
        # the generic IPv6 flag checks so the denied_reason matches the
        # bare-IPv4 form and no internal/metadata address bypasses the
        # guard. ``ipv4_mapped`` is None for non-mapped IPv6 addresses, so
        # native IPv6 falls through to the existing flag checks unchanged.
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return _classify(str(mapped))
        # Structural-review BUG 2: IPv4-in-IPv6 TRANSITION forms also tunnel
        # an IPv4 destination through an IPv6 literal, and like ipv4_mapped
        # their wrapper ``is_*`` flags do not reflect the embedded IPv4's
        # class. Unwrap each and re-classify on the embedded IPv4 so the
        # denied_reason matches the bare-IPv4 form. Unwrap BEFORE the native
        # flag checks below because some transition wrappers carry a
        # misleading native flag (e.g. a 6to4 address wrapping the PUBLIC
        # 8.8.8.8 reports ``is_private == True`` -- classifying it on the
        # wrapper would OVER-BLOCK a legitimate public destination). Only
        # the embedded IPv4's real class decides.
        #
        # 6to4 (2002::/16): the stdlib exposes the embedded IPv4 directly.
        sixto = ip.sixtofour
        if sixto is not None:
            return _classify(str(sixto))
        # NAT64 (64:ff9b::/96) and the deprecated IPv4-compatible (::/96)
        # forms both carry the IPv4 in the low 32 bits. The native flag
        # checks for loopback (``::1``) and unspecified (``::``) run first
        # below so those specials keep their own reasons; remaining ::/96
        # and all NAT64 addresses unwrap to their embedded IPv4 here.
        if ip in _NAT64_NETWORK:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            return _classify(str(embedded))
        if ip.is_link_local:
            return ("link_local", "fe80::/10")
        # IPv6 private (ULA + loopback ::1) maps to rfc4193. Tag under
        # rfc1918 for parity with IPv4 internal addresses; this keeps
        # the denied_reason set small and tractable. Note: ``::1`` is
        # ``is_private == True`` per the stdlib so loopback is covered
        # by this branch (the IPv6 loopback was already enforced; the
        # IPv4 loopback gap above was the BUG-B1 regression).
        if ip.is_private:
            return ("rfc1918", "fc00::/7")
        if ip.is_multicast:
            return ("multicast", "ff00::/8")
        if ip.is_unspecified:
            return ("reserved", "::/128")
        # Structural-review BUG 2 (cont.): the deprecated IPv4-compatible
        # form (``::/96``, e.g. ``::a9fe:a9fe`` for 169.254.169.254) carries
        # the IPv4 in the low 32 bits. The loopback ``::1`` and unspecified
        # ``::`` specials are already handled above (``is_private`` and
        # ``is_unspecified`` respectively), so by here a ``::/96`` address
        # is a genuine IPv4-compatible wrapper -- unwrap to its embedded
        # IPv4 and re-classify (public embedded IPv4 stays ALLOWED). This
        # runs before ``is_reserved`` because ``::/96`` addresses report
        # ``is_reserved == True`` on the wrapper, which would otherwise
        # over-block a public-wrapping compat form.
        if ip in _IPV4_COMPAT_NETWORK:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            return _classify(str(embedded))
        if ip.is_reserved:
            return ("reserved", "ipv6_reserved")
    return None


def validate_egress_entries(
    entries: Iterable[str],
) -> None:
    """Validate every entry in ``entries`` against the SSRF guard.

    Raises :class:`EgressDenied` on the first rejected entry. Returns
    silently if every entry passes. Callers receive an exception with
    a structured ``envelope`` they can serialize directly into the
    HTTP rejection body.
    """
    for entry in entries:
        if not isinstance(entry, str) or not entry:
            continue
        host = _extract_host(entry)
        classification = _classify(host)
        if classification is None:
            continue
        denied_reason, denied_cidr = classification
        raise EgressDenied(
            {
                "code": RELAY_REPLAY_SSRF,
                "http_status": _HTTP_STATUS,
                "denied_entry": entry,
                "denied_reason": denied_reason,
                "denied_cidr": denied_cidr,
            }
        )


# -----------------------------------------------------------------------------
# UTS-39 confusables guard on manifest URLs (VAL-V3M5-010)
# -----------------------------------------------------------------------------
#
# When the SDK fetches a manifest URL whose host is a Unicode homograph
# of an expected canonical ASCII host, the verifier-side guard would
# never get a chance to catch the substitution because the SDK has
# already loaded the wrong manifest. We add the same UTS-39 fold +
# skeleton comparison the verifier uses (jwks_loader.check_host_confusable)
# scoped to the SDK's manifest-URL surface.
#
# Spec anchor: AI line 5659 (UTS-39 confusables). The SDK helper is
# intentionally a small hand-rolled subset (Cyrillic / Greek / Armenian /
# fullwidth / mathematical / mixed-script) sufficient for the documented
# variants. Operators wanting full UTS-39 coverage should layer the
# optional ``confusable_homoglyphs`` PyPI dependency on top.
#
# Keys are built via ``chr(codepoint)`` so this source file remains pure
# ASCII per CLAUDE.md "ASCII-Safe Source".

RELAY_SDK_HOMOGRAPH: Final[str] = "RELAY-SDK-HOMOGRAPH"
"""Wire code for a manifest URL whose host fails the UTS-39 confusables
guard. Word-form code per the precedent set by ``RELAY-REPLAY-SSRF``."""

_MANIFEST_HOMOGRAPH_HTTP_STATUS: Final[int] = 400


_MANIFEST_CONFUSABLES_MAP: Final[dict[str, str]] = {
    # Cyrillic small letters most-targeted in phishing kits.
    chr(0x0430): "a",  # CYRILLIC SMALL LETTER A
    chr(0x0435): "e",  # CYRILLIC SMALL LETTER IE
    chr(0x043E): "o",  # CYRILLIC SMALL LETTER O
    chr(0x0440): "p",  # CYRILLIC SMALL LETTER ER
    chr(0x0441): "c",  # CYRILLIC SMALL LETTER ES
    chr(0x0445): "x",  # CYRILLIC SMALL LETTER HA
    chr(0x0443): "y",  # CYRILLIC SMALL LETTER U
    chr(0x0456): "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    chr(0x0458): "j",  # CYRILLIC SMALL LETTER JE
    chr(0x04BB): "h",  # CYRILLIC SMALL LETTER SHHA
    # Greek small letters.
    chr(0x03BF): "o",  # GREEK SMALL LETTER OMICRON
    chr(0x03C1): "p",  # GREEK SMALL LETTER RHO
    chr(0x03BA): "k",  # GREEK SMALL LETTER KAPPA
    chr(0x03BD): "v",  # GREEK SMALL LETTER NU
    chr(0x03B1): "a",  # GREEK SMALL LETTER ALPHA
    chr(0x03B9): "i",  # GREEK SMALL LETTER IOTA
    # Armenian small letters.
    chr(0x0585): "o",  # ARMENIAN SMALL LETTER OH
    chr(0x0578): "n",  # ARMENIAN SMALL LETTER VO
    chr(0x0570): "h",  # ARMENIAN SMALL LETTER HO
    chr(0x0566): "q",  # ARMENIAN SMALL LETTER ZA
}


def _manifest_script_of(ch: str) -> str:
    """Coarse script bucket for mixed-script detection."""
    cp = ord(ch)
    if cp < 0x80:
        if ch.isalnum() or ch == "-":
            return "ascii"
        return "common"
    if 0x0400 <= cp <= 0x04FF:
        return "cyrillic"
    if 0x0370 <= cp <= 0x03FF:
        return "greek"
    if 0x0530 <= cp <= 0x058F:
        return "armenian"
    if 0xFF00 <= cp <= 0xFFEF:
        return "fullwidth"
    if 0x1D400 <= cp <= 0x1D7FF:
        return "math"
    return "other"


def _manifest_ascii_skeleton(host: str) -> str:
    """Return the NFKC + curated-map ASCII skeleton of ``host``."""
    nfkc = unicodedata.normalize("NFKC", host)
    return "".join(_MANIFEST_CONFUSABLES_MAP.get(ch, ch) for ch in nfkc)


def _manifest_is_pure_ascii(s: str) -> bool:
    return all(ord(c) < 0x80 for c in s)


class ManifestUrlHomographDenied(Exception):
    """Raised when a manifest URL's host fails the UTS-39 guard.

    The structured rejection envelope is on :attr:`envelope`; the
    exception message echoes the offending URL so logs are
    self-explanatory.
    """

    def __init__(self, envelope: dict[str, Any]) -> None:
        self.envelope = envelope
        super().__init__(
            f"manifest URL {envelope.get('denied_url', '')!r} denied by "
            f"UTS-39 homograph guard "
            f"(reason={envelope.get('denied_reason', '')})"
        )


def check_manifest_url_confusable(url: str, *, canonical_host: str) -> None:
    """Reject ``url`` when its host is a UTS-39 confusable of ``canonical_host``.

    Pure ASCII candidates pass unconditionally so an SDK caller may
    point at any ASCII host on purpose. Non-ASCII candidates are folded
    via NFKC + the curated confusables map; a skeleton that equals the
    canonical host trips a ``confusable`` rejection. Mixed-script
    labels trip ``mixed_script``. Residual non-ASCII codepoints after
    folding trip ``non_ascii``.

    Args:
        url: candidate manifest URL (scheme://host[:port]/path).
        canonical_host: the expected ASCII host.

    Raises:
        ManifestUrlHomographDenied: with a structured envelope ready to
            serialize directly into an HTTP rejection body.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    canonical_lower = canonical_host.lower()
    if not host:
        # Malformed URL; the caller is responsible for surfacing the
        # structural error. The homograph guard is a no-op here.
        return None
    if _manifest_is_pure_ascii(host):
        return None

    # Per-label mixed-script detection. A label that mixes ASCII letters
    # with foreign-script letters is the canonical UTS-39 attack
    # signature; reject before skeleton folding so the reason code
    # attributes correctly even against UNRELATED canonical hosts.
    for label in host.split("."):
        scripts: set[str] = set()
        for ch in label:
            s = _manifest_script_of(ch)
            if s in {"ascii", "common"}:
                continue
            scripts.add(s)
        if len(scripts) >= 1 and any(
            _manifest_script_of(ch) == "ascii" for ch in label
        ):
            skeleton_label = _manifest_ascii_skeleton(label)
            if _manifest_is_pure_ascii(skeleton_label):
                # Folds cleanly to ASCII; the broader skeleton check
                # below will pick up a confusables match if one exists.
                continue
            raise ManifestUrlHomographDenied(
                {
                    "code": RELAY_SDK_HOMOGRAPH,
                    "http_status": _MANIFEST_HOMOGRAPH_HTTP_STATUS,
                    "denied_url": url,
                    "denied_host": host,
                    "canonical_host": canonical_host,
                    "denied_reason": "mixed_script",
                    "label": label,
                    "scripts": sorted(scripts),
                }
            )

    skeleton = _manifest_ascii_skeleton(host).lower()
    if skeleton == canonical_lower:
        raise ManifestUrlHomographDenied(
            {
                "code": RELAY_SDK_HOMOGRAPH,
                "http_status": _MANIFEST_HOMOGRAPH_HTTP_STATUS,
                "denied_url": url,
                "denied_host": host,
                "canonical_host": canonical_host,
                "denied_reason": "confusable",
                "skeleton": skeleton,
            }
        )

    if not _manifest_is_pure_ascii(skeleton):
        raise ManifestUrlHomographDenied(
            {
                "code": RELAY_SDK_HOMOGRAPH,
                "http_status": _MANIFEST_HOMOGRAPH_HTTP_STATUS,
                "denied_url": url,
                "denied_host": host,
                "canonical_host": canonical_host,
                "denied_reason": "non_ascii",
                "skeleton": skeleton,
            }
        )
    return None


__all__ = [
    "CLOUD_METADATA_IPS",
    "EgressDenied",
    "ManifestUrlHomographDenied",
    "RELAY_REPLAY_SSRF",
    "RELAY_SDK_HOMOGRAPH",
    "check_manifest_url_confusable",
    "validate_egress_entries",
]
