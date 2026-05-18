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

# Link-local IPv4 range.
_LINK_LOCAL_V4: Final[ipaddress.IPv4Network] = ipaddress.IPv4Network(
    "169.254.0.0/16"
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
        parsed = urlparse(entry)
        host = parsed.hostname or ""
        return host
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


def _classify(host: str) -> tuple[str, str] | None:
    """Return ``(denied_reason, denied_cidr_or_endpoint)`` or ``None``
    if ``host`` is not denied by the SSRF guard."""
    if not host:
        return None
    # Cloud-metadata literal match takes precedence over link-local so
    # 169.254.169.254 attributes correctly.
    if host in CLOUD_METADATA_IPS:
        return ("cloud_metadata", host)
    # IPv4 range checks.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not a literal IP -- skip. Hostname-based SSRF is out of scope
        # for this guard; the caller is expected to resolve hostnames
        # through a separate DNS-pinning policy.
        return None
    if isinstance(ip, ipaddress.IPv4Address):
        for net in _RFC1918_NETWORKS:
            if ip in net:
                return ("rfc1918", str(net))
        if ip in _LINK_LOCAL_V4:
            return ("link_local", str(_LINK_LOCAL_V4))
        return None
    # IPv6: check link-local fe80::/10 and the well-known metadata
    # literals (handled above by string match for fd00:ec2::254).
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.is_link_local:
            return ("link_local", "fe80::/10")
        # IPv6 private (ULA) maps to rfc4193 (similar to RFC 1918). Tag
        # under rfc1918 for parity with IPv4 internal addresses; this
        # keeps the denied_reason set small and tractable.
        if ip.is_private:
            return ("rfc1918", "fc00::/7")
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


__all__ = [
    "CLOUD_METADATA_IPS",
    "EgressDenied",
    "RELAY_REPLAY_SSRF",
    "validate_egress_entries",
]
