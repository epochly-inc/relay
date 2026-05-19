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

# Link-local IPv4 range.
_LINK_LOCAL_V4: Final[ipaddress.IPv4Network] = ipaddress.IPv4Network(
    "169.254.0.0/16"
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
    # Cloud-metadata literal match takes precedence over link-local so
    # 169.254.169.254 attributes correctly.
    if host in CLOUD_METADATA_IPS:
        return ("cloud_metadata", host)
    # IPv4 / IPv6 range checks.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
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
