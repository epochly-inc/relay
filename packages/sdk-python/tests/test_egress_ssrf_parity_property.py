"""Generative Py<->TS parity for the egress SSRF classifier (keystone #9 + #16).

Keystone invariant #16 (and #9, cassette-first replay's default-deny sandbox)
require the Python SDK egress guard
(``relay.network_policy.validate_egress_entries``) and the TypeScript SDK guard
(``packages/sdk-typescript/src/run.ts`` ``validateEgressEntries``) to reach the
SAME allow/deny verdict -- AND the same ``(denied_reason, denied_cidr)``
envelope bytes -- for every ``replay_case.egress_allowlist`` entry. A divergence
is a Py<->TS SSRF verdict split: one SDK admits a destination the other denies,
which is a default-deny egress bypass (P0).

The example-based suites (``test_f6_ipv6_is_private_egress_parity.py``,
``test_ssrf_numeric_and_transition_forms.py``, the TS ``replay_egress_*``
suites) pin specific addresses. THIS module is the universally-quantified
counterpart: Hypothesis GENERATES random host strings across the full taxonomy
the guard must classify --

  * IPv4 dotted-decimal (public + every internal/reserved block);
  * IPv4 non-dotted numeric forms (integer / 0x-hex / 0-octal / short 1-3 part)
    that ``inet_aton`` accepts but ``ipaddress`` rejects (the BUG-1 bypass class);
  * IPv6 native specials (loopback/ULA/link-local/multicast/documentation/2001::
    /3fff::/NAT64-local), random global-unicast, IPv4-mapped, and the 6to4 /
    NAT64 / IPv4-compatible TRANSITION forms that tunnel an IPv4 destination;
  * bracketed IPv6 authority forms (``[::1]``, ``[fe80::1]:8080``) and zone ids;
  * bare and FQDN-root-dotted hostnames incl. the reserved-hostname denylist;
  * full URL forms (``scheme://host[:port]/path``) wrapping any of the above;
  * IPv4 / IPv6 CIDR entries incl. BROAD supernets that contain internal ranges
    behind a public-looking network address --

and asserts, for each generated entry:

  PROPERTY A (verdict parity): the Python verdict tuple
  ``(allow, denied_reason, denied_cidr)`` is BYTE-IDENTICAL to the TypeScript
  verdict tuple. The TS guard is driven through a Node subprocess over the
  compiled ``dist`` build (mirrors the ``test_redaction_parity.py`` and
  ``replay_egress_*`` subprocess pattern).

  PROPERTY B (security direction): every address drawn from a KNOWN-internal
  generator (RFC1918 / loopback / IPv4 link-local / cloud-metadata / IPv6 ULA /
  IPv6 link-local) is DENIED (``allow is False``) on BOTH runtimes. This is the
  default-deny half of keystone #16 expressed as a one-directional invariant:
  the generators cannot, by construction, produce a public address, so an
  ``allow`` is necessarily a guard miss.

When Node or the TS ``dist`` build are unavailable (offline tier-1 / pre-build)
the cross-language half is SKIPPED rather than failed; the gate environment
rebuilds the dist first, where these tests are authoritative.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st
from relay.network_policy import EgressDenied, validate_egress_entries

# ---------------------------------------------------------------------------
# Verdict computation (Python reference) + TS oracle via Node subprocess.
# ---------------------------------------------------------------------------

#: A verdict is a hashable tuple ``(allow, denied_reason, denied_cidr)`` where
#: ``denied_reason``/``denied_cidr`` are ``None`` when ``allow`` is True.
Verdict = tuple[bool, str | None, str | None]


def _py_verdict(entry: str) -> Verdict:
    """Python reference verdict for a single egress entry."""
    try:
        validate_egress_entries([entry])
    except EgressDenied as exc:
        env = exc.envelope
        return (False, env["denied_reason"], env["denied_cidr"])
    return (True, None, None)


def _find_node() -> str | None:
    return shutil.which("node")


def _ts_dist_path() -> Path:
    repo_root = Path(__file__).resolve().parents[3]
    return repo_root / "packages" / "sdk-typescript" / "dist" / "src" / "run.js"


# Node ESM script: read a JSON array of host strings from stdin, classify each
# through the SAME public entrypoint the SDK uses (``validateEgressEntries``),
# and emit a JSON array of verdict objects. One subprocess validates a whole
# batch of generated entries so Node startup is amortised across the example.
_TS_SCRIPT = """
import {{ validateEgressEntries, EgressDenied }} from {dist_json};

const stdin = await new Promise((resolve) => {{
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => {{ buf += c; }});
  process.stdin.on('end', () => resolve(buf));
}});
const entries = JSON.parse(stdin);
const out = entries.map((entry) => {{
  try {{
    validateEgressEntries([entry]);
    return {{ allow: true }};
  }} catch (err) {{
    if (err instanceof EgressDenied) {{
      return {{
        allow: false,
        reason: err.envelope.denied_reason,
        cidr: err.envelope.denied_cidr,
      }};
    }}
    return {{ unexpected: err && err.message ? err.message : String(err) }};
  }}
}});
process.stdout.write(JSON.stringify(out));
"""


def _ts_verdicts(entries: list[str]) -> list[Verdict] | None:
    """Return the TS verdict for every entry, or ``None`` when Node / the TS
    dist build are unavailable (caller should skip).

    Raises ``RuntimeError`` on a subprocess crash or an unexpected (non
    ``EgressDenied``) TS throw -- a real defect must surface loudly, never be
    masked into a skip.
    """
    node = _find_node()
    if node is None:
        return None
    dist = _ts_dist_path()
    if not dist.exists():
        return None
    script = _TS_SCRIPT.format(dist_json=json.dumps(str(dist)))
    proc = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(entries),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"node TS egress subprocess failed: rc={proc.returncode} "
            f"stderr={proc.stderr!r}"
        )
    raw: list[dict[str, Any]] = json.loads(proc.stdout.strip())
    verdicts: list[Verdict] = []
    for entry, item in zip(entries, raw, strict=True):
        if "unexpected" in item:
            raise RuntimeError(
                f"TS validateEgressEntries threw a non-EgressDenied error on "
                f"{entry!r}: {item['unexpected']!r}"
            )
        if item["allow"]:
            verdicts.append((True, None, None))
        else:
            verdicts.append((False, item["reason"], item["cidr"]))
    return verdicts


# ---------------------------------------------------------------------------
# Generators -- the egress-entry taxonomy.
# ---------------------------------------------------------------------------

_octet = st.integers(min_value=0, max_value=255)


def _dotted(a: int, b: int, c: int, d: int) -> str:
    return f"{a}.{b}.{c}.{d}"


# Public-ish random dotted IPv4 (may land internal; both engines must agree).
_ipv4_random = st.builds(_dotted, _octet, _octet, _octet, _octet)

# Internal / reserved IPv4 -- biased to exercise the deny path and the
# security-direction invariant. RFC1918, loopback /8, IPv4 link-local /16,
# CGNAT /10, and the explicit cloud-metadata literals.
_ipv4_internal = st.one_of(
    st.builds(lambda b, c, d: _dotted(10, b, c, d), _octet, _octet, _octet),
    st.builds(lambda b, c, d: _dotted(127, b, c, d), _octet, _octet, _octet),
    st.builds(
        lambda b, c, d: _dotted(172, b, c, d),
        st.integers(min_value=16, max_value=31),
        _octet,
        _octet,
    ),
    st.builds(lambda c, d: _dotted(192, 168, c, d), _octet, _octet),
    st.builds(lambda c, d: _dotted(169, 254, c, d), _octet, _octet),
    st.sampled_from(["169.254.169.254", "100.100.100.200"]),
)


@st.composite
def _ipv4_numeric(draw: st.DrawFn) -> str:
    """A non-dotted-decimal IPv4 encoding (integer / hex / octal / short form)
    that ``inet_aton`` accepts -- the BUG-1 bypass class both guards must
    canonicalise identically."""
    a = draw(_octet)
    b = draw(_octet)
    c = draw(_octet)
    d = draw(_octet)
    value = (a << 24) | (b << 16) | (c << 8) | d
    form = draw(st.sampled_from(["int", "hex", "octal_parts", "short3", "short2"]))
    if form == "int":
        return str(value)
    if form == "hex":
        return f"0x{value:x}"
    if form == "octal_parts":
        # Per-part octal (inet_aton reads a leading-zero part as octal).
        return f"0{a:o}.0{b:o}.0{c:o}.0{d:o}"
    if form == "short3":
        # a.b.(c<<8|d) -- inet_aton's 3-part form.
        return f"{a}.{b}.{(c << 8) | d}"
    # short2: a.(b<<16|c<<8|d)
    return f"{a}.{(b << 16) | (c << 8) | d}"


# Curated IPv6 special-block literals + a random-suffix factory so the deny
# path (and the moving 2001::/3fff:: registry) is exercised broadly.
_ipv6_special = st.sampled_from(
    [
        "::1",  # loopback (is_private)
        "::",  # unspecified
        "fc00::1",  # ULA
        "fd12:3456::1",  # ULA
        "fdff::1",
        "fe80::1",  # link-local
        "fe80::abcd:1234",
        "2001:db8::1",  # documentation (is_private)
        "2001::1",  # 2001::/23 private remainder
        "2001:2::1",
        "2001:10::1",
        "3fff::1",  # RFC 9637 documentation (is_private)
        "64:ff9b:1::1",  # NAT64 local-use (is_private)
        "ff02::1",  # multicast
        "100::1",  # discard-only (is_private)
        # Global-unicast / 2001::/23 carve-out exceptions -- must stay ALLOWED.
        "2001:20::1",
        "2001:30::1",
        "2001:3::1",
        "2606:4700:4700::1111",
        "2620:fe::fe",
        "3fff:ffff::1",
    ]
)


@st.composite
def _ipv6_random(draw: st.DrawFn) -> str:
    """A random full 8-group IPv6 literal."""
    groups = [draw(st.integers(min_value=0, max_value=0xFFFF)) for _ in range(8)]
    return ":".join(f"{g:x}" for g in groups)


@st.composite
def _ipv6_transition(draw: st.DrawFn) -> str:
    """An IPv4-in-IPv6 transition / mapped form embedding a generated IPv4."""
    a = draw(_octet)
    b = draw(_octet)
    c = draw(_octet)
    d = draw(_octet)
    kind = draw(st.sampled_from(["mapped", "sixtofour", "nat64", "compat"]))
    if kind == "mapped":
        return f"::ffff:{a}.{b}.{c}.{d}"
    if kind == "sixtofour":
        return f"2002:{a:02x}{b:02x}:{c:02x}{d:02x}::1"
    if kind == "nat64":
        return f"64:ff9b::{a}.{b}.{c}.{d}"
    # Deprecated IPv4-compatible ::/96 form.
    return f"::{a}.{b}.{c}.{d}"


@st.composite
def _ipv6_bracketed(draw: st.DrawFn) -> str:
    """RFC 3986 bracketed IPv6 authority, optionally with :port and zone id."""
    inner = draw(st.one_of(_ipv6_special, _ipv6_random()))
    if draw(st.booleans()):
        inner = inner + "%eth0"
    bracketed = f"[{inner}]"
    if draw(st.booleans()):
        bracketed = bracketed + ":" + str(draw(st.integers(min_value=1, max_value=65535)))
    return bracketed


_dns_label = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
    min_size=1,
    max_size=12,
).filter(lambda s: not s.startswith("-") and not s.endswith("-"))


@st.composite
def _hostname(draw: st.DrawFn) -> str:
    """A bare hostname: random global names, the reserved denylist, and the
    reserved suffix families (``*.internal`` / ``*.local`` / ``*.svc`` ...)."""
    kind = draw(st.sampled_from(["random", "denylist", "suffix", "fqdn_root"]))
    if kind == "denylist":
        return draw(
            st.sampled_from(
                [
                    "localhost",
                    "metadata",
                    "metadata.google.internal",
                    "instance-data.ec2.internal",
                    "kubernetes",
                    "kubernetes.default.svc",
                ]
            )
        )
    if kind == "suffix":
        label = draw(_dns_label)
        suffix = draw(
            st.sampled_from([".internal", ".local", ".svc", ".localhost"])
        )
        return label + suffix
    labels = draw(st.lists(_dns_label, min_size=1, max_size=3))
    tld = draw(st.sampled_from(["com", "org", "net", "io", "ai"]))
    host = ".".join([*labels, tld])
    if kind == "fqdn_root":
        host = host + "."  # trailing FQDN-root dot
    return host


# A "host token" usable as the authority of a URL (IPv6 must be bracketed).
_url_host = st.one_of(
    _ipv4_random,
    _ipv4_internal,
    _ipv4_numeric(),
    _hostname(),
    _ipv6_bracketed(),
)


@st.composite
def _url(draw: st.DrawFn) -> str:
    """A full URL form ``scheme://host[:port]/path`` wrapping a host token."""
    scheme = draw(st.sampled_from(["http", "https"]))
    host = draw(_url_host)
    authority = host
    # Append a :port only when the host token is not already bracketed/ported.
    if not host.startswith("[") and draw(st.booleans()):
        authority = host + ":" + str(draw(st.integers(min_value=1, max_value=65535)))
    path = draw(st.sampled_from(["", "/", "/path", "/a/b?q=1", "/#frag"]))
    return f"{scheme}://{authority}{path}"


# Broad supernet CIDRs whose NETWORK address looks public but whose range
# CONTAINS an internal block -- the overlap-check class. Plus random CIDRs.
_cidr_broad = st.sampled_from(
    [
        "0.0.0.0/0",
        "8.0.0.0/6",
        "64.0.0.0/2",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "100.64.0.0/10",
        "::/0",
        "fc00::/7",
        "fe80::/10",
        "2001::/23",
        "2001:db8::/32",
        "3fff::/20",
        "3fff:ffff::1/16",
        "2001:20::/28",
        "2001:20::/27",
        "2606:4700::/32",
    ]
)


@st.composite
def _cidr_random(draw: st.DrawFn) -> str:
    if draw(st.booleans()):
        base = draw(st.one_of(_ipv4_random, _ipv4_internal))
        prefix = draw(st.integers(min_value=0, max_value=32))
    else:
        base = draw(st.one_of(_ipv6_special, _ipv6_random()))
        prefix = draw(st.integers(min_value=0, max_value=128))
    return f"{base}/{prefix}"


# The full egress-entry domain.
_entry = st.one_of(
    _ipv4_random,
    _ipv4_internal,
    _ipv4_numeric(),
    _ipv6_special,
    _ipv6_random(),
    _ipv6_transition(),
    _ipv6_bracketed(),
    _hostname(),
    _url(),
    _cidr_broad,
    _cidr_random(),
)

# Known-internal domain for the security-direction invariant (cannot produce a
# public address by construction).
_internal_entry = st.one_of(
    _ipv4_internal,
    st.sampled_from(
        [
            "::1",
            "fc00::1",
            "fd00::1",
            "fe80::1",
            "169.254.169.254",
            "100.100.100.200",
            "[::1]",
            "[fe80::1]:9000",
            "https://10.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
        ]
    ),
)


# ---------------------------------------------------------------------------
# PROPERTY A: Py<->TS verdict parity over the full generated domain.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@settings(max_examples=60, deadline=None)
@given(entries=st.lists(_entry, min_size=1, max_size=20))
# Deterministic anchors that guarantee the deny path (and the teeth break) are
# always exercised, independent of Hypothesis's random draw.
@example(entries=["10.0.0.1"])
@example(entries=["127.0.0.1"])
@example(entries=["169.254.169.254"])
@example(entries=["::1"])
@example(entries=["8.0.0.0/6"])
@example(entries=["2130706433"])
@example(entries=["::ffff:10.0.0.1"])
def test_egress_verdict_parity_py_ts(entries: list[str]) -> None:
    """For every generated egress entry, the Python and TypeScript guards MUST
    return the SAME ``(allow, denied_reason, denied_cidr)`` verdict.

    A mismatch is a Py<->TS SSRF verdict split (keystone #16): one SDK admits a
    destination the other denies, or they disagree on the rejection reason/CIDR
    bytes that flow into the wire rejection envelope.

    Skipped when Node or the TS dist are unavailable; authoritative otherwise.
    """
    ts = _ts_verdicts(entries)
    if ts is None:
        pytest.skip(
            "node binary or TS dist (packages/sdk-typescript/dist) not "
            "available; cross-language verdict parity cannot be checked"
        )
    py = [_py_verdict(e) for e in entries]
    for entry, pv, tv in zip(entries, py, ts, strict=True):
        assert pv == tv, (
            f"Py<->TS egress verdict split on {entry!r}: "
            f"py={pv!r} ts={tv!r}"
        )


# ---------------------------------------------------------------------------
# PROPERTY B: security direction -- internal addresses are DENIED on BOTH.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@settings(max_examples=60, deadline=None)
@given(entries=st.lists(_internal_entry, min_size=1, max_size=20))
@example(entries=["10.0.0.1"])
@example(entries=["169.254.169.254"])
@example(entries=["fc00::1"])
def test_internal_addresses_denied_on_both(entries: list[str]) -> None:
    """Every entry drawn from the KNOWN-internal generator is DENIED
    (``allow is False``) by the Python guard, and -- when Node + the dist are
    present -- by the TypeScript guard too.

    The generator cannot produce a public address, so an ``allow`` here is a
    default-deny egress bypass (keystone #16 security direction).
    """
    # Python reference: the security invariant holds unconditionally (no Node
    # dependency), so it is checked even in the offline tier.
    for entry in entries:
        allow, _reason, _cidr = _py_verdict(entry)
        assert allow is False, (
            f"Python egress guard ALLOWED a known-internal destination "
            f"{entry!r} (default-deny bypass)"
        )
    ts = _ts_verdicts(entries)
    if ts is None:
        pytest.skip(
            "node binary or TS dist not available; TS half of the "
            "security-direction invariant cannot be checked"
        )
    for entry, (allow, _r, _c) in zip(entries, ts, strict=True):
        assert allow is False, (
            f"TypeScript egress guard ALLOWED a known-internal destination "
            f"{entry!r} (default-deny bypass)"
        )


# ---------------------------------------------------------------------------
# Sanity: a clearly-public destination is ALLOWED on both runtimes (guards the
# property suites against a degenerate all-deny classifier that would make the
# parity assertions vacuously true).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_public_destination_allowed_on_both() -> None:
    """A public destination MUST be ALLOWED on both runtimes -- proves the
    classifier is not degenerately denying everything (which would make Property
    A trivially satisfiable)."""
    public = ["8.8.8.8", "api.openai.com", "https://example.com/v1", "2606:4700::1"]
    for entry in public:
        assert _py_verdict(entry) == (True, None, None), entry
    ts = _ts_verdicts(public)
    if ts is None:
        pytest.skip("node / TS dist unavailable")
    assert ts == [(True, None, None)] * len(public)
