/**
 * ``Relay.run`` lifecycle surface (W4.2).
 *
 * Parity with the Python ``relay.run`` module
 * (``packages/sdk-python/relay/run.py``). This module owns the SDK-side
 * lifecycle surface a caller uses inside a trace context: capture
 * lifecycle events, submit gate-evaluate drafts, create replay cases
 * (cassette mode by default), submit evidence bundles, and flush.
 *
 * Per CLAUDE.md keystone invariant #1 the SDK NEVER writes canonical
 * results; it submits lifecycle metadata + drafts and reads canonical
 * decisions the control plane writes.
 *
 * The :class:`Run` is the user-facing handle returned by ``relay.trace``.
 * Caller code drives lifecycle events via :meth:`Run.capture` /
 * :meth:`Run.modelCall` / :meth:`Run.toolCall` / :meth:`Run.gateEvaluate`
 * / :meth:`Run.replayCreate` / :meth:`Run.submitEvidence`. On
 * :meth:`Run.close` the SDK flushes pending lifecycle events according to
 * the configured :class:`FlushPolicy`.
 *
 * Streaming model_call (VAL-W4-012):
 *   :meth:`Run.modelCall` accepts a streaming response and emits ONE
 *   ``model_call`` span with summarised token deltas (``promptTokens``,
 *   ``completionTokens``, ``chunkCount``, ``firstTokenLatencyMs``,
 *   ``modelSignature``). Per-chunk events do NOT become separate spans.
 *
 * Side-effect tool calls (VAL-W4-013):
 *   :meth:`Run.toolCall` with ``sideEffect: true`` requires both
 *   ``idempotencyKey`` AND ``replayPolicy``. Missing either raises
 *   :class:`RelaySideEffectMissingFieldsError` BEFORE the span opens.
 *
 * Replay (VAL-W4-017):
 *   :meth:`Run.replayCreate` defaults to cassette mode. Live mode
 *   requires the caller to explicitly opt in via
 *   ``{mode: 'live', acknowledgeDegradedApproximation: true}``.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";
import { isIP } from "node:net";

import { FlushPolicy } from "./flush.js";
import { AsyncFlushDispatcher } from "./flush.js";
import {
  RelayCanonicalStatusForbidden,
  RelayConfigError,
  RelayError,
  RelayEvidenceIncomplete,
  RelayHandoffIncomplete,
  RelayReplayLiveModeUnacknowledgedError,
  RelayReplayPrecondition,
  RelaySideEffectMissingFieldsError,
  RelayUnknownError,
  RELAY_EVID_002_CODE,
  RELAY_GATE_021_CODE,
  RELAY_ING_022_CODE,
  RELAY_ING_031_CODE,
  RELAY_REPLAY_002_CODE,
  RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CODE,
  RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CODE,
  resolveClassForCode,
  type ErrorEnvelopeWire,
} from "./errors.js";
import {
  buildEvidenceEnvelope,
  buildGateDraftEnvelope,
  buildIngestRunEnvelope,
  type EvidenceEnvelope,
  type GateDraftEnvelope,
  type IngestRunEnvelope,
  type LifecycleStatus,
} from "./lifecycle.js";
import { _canonicalJsonStringify } from "./redaction.js";
import { newUlid } from "./ulid.js";

/** SDK version string the SDK includes in every envelope.
 *
 * Resolved at module load time from the package's own package.json so
 * the canonical version (the one baked into the published tarball) is
 * what every envelope reports. The published tarball includes
 * package.json at the package root and the compiled module at
 * dist/src/run.js, so `../../package.json` resolves correctly in both
 * the published artifact and a local `npm pack` build.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function resolveSdkVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkgPath = join(here, "..", "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string };
    if (typeof pkg.version === "string" && pkg.version.length > 0) {
      return `relay-typescript@${pkg.version}`;
    }
  } catch {
    // fallthrough to fallback
  }
  return "relay-typescript@0.0.0+local";
}

export const SDK_VERSION = resolveSdkVersion();

/** UTC timestamp with millisecond precision (mirrors Python ``_utcnow_iso8601``). */
export function utcNowIso8601(): string {
  const now = new Date();
  // ISO string already in UTC with millisecond precision; replace 'Z' as-is.
  return now.toISOString();
}

/**
 * Replay-policy enum for side-effecting tool calls (VAL-W4-013, spec X).
 *
 *   * ``replay_in_sandbox``      -- tool re-executes in the sandbox.
 *   * ``block_in_replay``        -- tool is BLOCKED in any replay; cassette
 *                                   used if available.
 *   * ``external_irreversible``  -- tool MUST NEVER replay; only cassette
 *                                   playback is permitted.
 */
export const REPLAY_POLICIES: ReadonlySet<string> = new Set([
  "replay_in_sandbox",
  "block_in_replay",
  "external_irreversible",
]);

export type ReplayPolicy = "replay_in_sandbox" | "block_in_replay" | "external_irreversible";

// ---------------------------------------------------------------------------
// SDK-boundary SSRF egress-allowlist guard (parity with the Python SDK
// packages/sdk-python/relay/network_policy.py::validate_egress_entries,
// exercised by Run.replayCreate's egressAllowlist option).
//
// The replay-case submit path validates every caller-supplied
// egress-allowlist entry and rejects any host that falls inside an RFC 1918
// private range, the IPv4 link-local block (169.254.0.0/16), the IPv4
// loopback block (127.0.0.0/8), the multicast / unspecified / reserved
// ranges, an IPv6 internal range, one of the well-known cloud-metadata
// endpoints, or the reserved-hostname denylist. Rejected entries surface as
// EgressDenied carrying a structured envelope whose keys are stable
// wire-format names (code / http_status / denied_entry / denied_reason /
// denied_cidr) -- byte-identical to the Python EgressDenied.envelope.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
// ---------------------------------------------------------------------------

/** Wire code for an egress-allowlist entry denied by the SSRF guard.
 *
 * Word-form code per the precedent set by ``RELAY-EVID-SIGCOUNT-EXCEEDED``;
 * mirrors the Python ``relay.network_policy.RELAY_REPLAY_SSRF`` constant so
 * an operator running the same agent on Node or Python sees the same code. */
export const RELAY_REPLAY_SSRF_CODE = "RELAY-REPLAY-SSRF";

const _EGRESS_DENIED_HTTP_STATUS = 400;

/** Well-known cloud-metadata endpoints (spec AI line 5664). The link-local
 * /16 catches IPv4 cloud metadata as a separate ``link_local`` reason; this
 * set upgrades the most-targeted endpoints to ``cloud_metadata`` so an
 * operator's detection routing can distinguish them. Mirrors the Python
 * ``CLOUD_METADATA_IPS`` frozenset. */
const _CLOUD_METADATA_IPS: ReadonlySet<string> = new Set([
  "169.254.169.254", // AWS EC2, GCP, Azure, OpenStack
  "100.100.100.200", // Alibaba Cloud
  "fd00:ec2::254", // AWS IPv6 metadata
]);

/** Exact reserved-hostname denylist (mirrors ``_HOSTNAME_DENYLIST_EXACT``). */
const _HOSTNAME_DENYLIST_EXACT: ReadonlySet<string> = new Set([
  "localhost",
  "metadata",
  "metadata.google.internal",
  "instance-data.ec2.internal",
  "kubernetes",
  "kubernetes.default.svc",
]);

/** Reserved-hostname suffix denylist (mirrors ``_HOSTNAME_DENYLIST_SUFFIXES``). */
const _HOSTNAME_DENYLIST_SUFFIXES: readonly string[] = [
  ".local",
  ".internal",
  ".svc",
  ".svc.cluster.local",
  ".localhost",
];

/** Structured rejection envelope carried by {@link EgressDenied}. The key
 * set is byte-identical to the Python ``EgressDenied.envelope`` so the wire
 * shape an operator serialises is the same across SDKs. */
export interface EgressDeniedEnvelope {
  readonly code: string;
  readonly http_status: number;
  readonly denied_entry: string;
  readonly denied_reason: string;
  readonly denied_cidr: string;
}

/**
 * Raised when an egress-allowlist entry is denied by the SDK-boundary SSRF
 * guard (parity with ``relay.network_policy.EgressDenied``).
 *
 * The structured rejection envelope is on {@link envelope}; the human
 * message echoes ``denied_entry`` so the error is self-explanatory in logs.
 */
export class EgressDenied extends Error {
  readonly envelope: EgressDeniedEnvelope;
  constructor(envelope: EgressDeniedEnvelope) {
    super(
      `egress entry ${JSON.stringify(envelope.denied_entry)} denied by SSRF guard ` +
        `(reason=${envelope.denied_reason})`,
    );
    this.name = "EgressDenied";
    this.envelope = envelope;
    Object.setPrototypeOf(this, EgressDenied.prototype);
  }
}

/** Faithful port of Python ``urllib.parse.urlparse(entry).hostname`` for the
 * URL-form egress-allowlist entries.
 *
 * The TS SDK previously used the WHATWG ``new URL()`` parser, but WHATWG and
 * ``urlparse`` resolve the authority DIFFERENTLY for backslash-in-userinfo and
 * embedded-space URLs, so ``validateEgressEntries`` (TS) and
 * ``validate_egress_entries`` (Python) returned OPPOSITE verdicts for the same
 * caller-supplied entry -- a Py<->TS parity break AND a default-deny SSRF
 * under-block on the TS side (round-5 re-hunt HIGH). E.g.
 * ``http://evil.com\@10.0.0.1/``: WHATWG treats ``\`` as a path delimiter so
 * ``hostname`` is ``evil.com`` (ALLOW), while urlparse keeps ``10.0.0.1`` as the
 * host (DENY -- and the IP a urlparse-style HTTP client actually dials); and
 * ``http://10.0.0.1 /``: ``new URL`` THROWS so the old extractor returned ""
 * (ALLOW) while urlparse yields ``10.0.0.1 `` (DENY after _classify strips it).
 *
 * ``urlparse`` does NOT treat ``\`` as a delimiter and does NOT strip
 * whitespace: netloc = the authority after ``scheme://`` up to the first ``/``,
 * ``?``, or ``#``; the host is the part after the LAST ``@`` (userinfo split),
 * with a bracketed IPv6 form or a trailing ``:port`` removed, then lowercased
 * (the empty case maps to ""). Verified byte-identical to ``urlparse().hostname``
 * across the divergent + canonical forms. */
function _urlparseHostname(entry: string): string {
  // CPython's urlsplit/urlparse REMOVES every ASCII tab (\t) and newline
  // (\r, \n) from the URL before splitting (the bpo-43882 / CVE-2022-0391
  // hardening: _UNSAFE_URL_BYTES_TO_REMOVE). Without this, an entry like
  // http://169.254.\t169.254/ keeps the embedded tab on the TS side so
  // _classify no longer recognizes the host as an IP and ALLOWS the metadata
  // target, while Python strips the tab and DENIES 169.254.169.254 -- a
  // Py<->TS parity break + SSRF under-block. Strip the same three bytes first.
  entry = entry.replace(/[\t\r\n]/g, "");
  const schemeIdx = entry.indexOf("://");
  const rest = entry.slice(schemeIdx + 3);
  let end = rest.length;
  for (const sep of ["/", "?", "#"]) {
    const i = rest.indexOf(sep);
    if (i >= 0 && i < end) end = i;
  }
  const netloc = rest.slice(0, end);
  const at = netloc.lastIndexOf("@");
  const hostinfo = at >= 0 ? netloc.slice(at + 1) : netloc;
  const openBr = hostinfo.indexOf("[");
  let hostname: string;
  if (openBr >= 0) {
    const bracketed = hostinfo.slice(openBr + 1);
    const closeBr = bracketed.indexOf("]");
    hostname = closeBr >= 0 ? bracketed.slice(0, closeBr) : bracketed;
  } else {
    const colon = hostinfo.indexOf(":");
    hostname = colon >= 0 ? hostinfo.slice(0, colon) : hostinfo;
  }
  return hostname.toLowerCase();
}

/** Return the host portion of ``entry`` (URL or bare host). Mirrors the Python
 * ``_extract_host``: URL forms go through ``_urlparseHostname`` (a faithful
 * urlparse port, NOT WHATWG ``new URL()`` -- see that function); bare forms
 * strip a single trailing ``:port`` and the RFC 3986 bracketed-IPv6 form. */
function _extractHost(entry: string): string {
  if (entry.includes("://")) {
    return _urlparseHostname(entry);
  }
  let host = entry;
  // RFC 3986 bracketed IPv6 authority form: ``[ipv6]`` or ``[ipv6]:port``.
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    if (end > 0) {
      return host.slice(1, end);
    }
    return host;
  }
  // ``host:port`` -- a single colon means it is not an IPv6 literal (which
  // carries multiple colons), so strip the trailing port.
  if (host.includes(":") && (host.match(/:/g) ?? []).length === 1) {
    host = host.split(":", 1)[0] as string;
  }
  return host;
}

/** Canonicalise a numeric-IPv4 literal (integer / hex / octal / short-form)
 * the SAME WAY the libc resolver (``inet_aton``) does, or ``null`` if
 * ``host`` is not such a literal. Mirrors the Python
 * ``_canonical_numeric_ipv4``: these encodings are dialled by the OS
 * resolver / HTTP client but rejected by a strict dotted-decimal parser, so
 * left unhandled they would bypass the default-deny screen. This only
 * NORMALISES; the caller must still classify the result so a numeric form
 * resolving to a PUBLIC IP stays allowed exactly like its dotted twin. */
function _canonicalNumericIpv4(host: string): string | null {
  if (!host) return null;
  const parts = host.split(".");
  // Alpha-guard: only ASCII digits, dots, and a leading ``0x``/``0X`` hex
  // prefix per part are permitted, so a real DNS name never coerces onto the
  // numeric path. inet_aton accepts at most 4 parts.
  if (parts.length > 4) return null;
  const values: bigint[] = [];
  for (const part of parts) {
    if (part === "") {
      // Empty part (leading/trailing/double dot) -- not a clean numeric
      // literal. inet_aton rejects these, so bail out.
      return null;
    }
    const lowered = part.toLowerCase();
    let value: bigint;
    if (lowered.startsWith("0x")) {
      const body = lowered.slice(2);
      if (body === "" || /[^0-9a-f]/.test(body)) return null;
      value = BigInt(`0x${body}`);
    } else if (lowered.startsWith("0") && lowered.length > 1) {
      // Octal (leading zero), per inet_aton.
      if (/[^0-7]/.test(lowered)) return null;
      value = BigInt(`0o${lowered}`);
    } else {
      if (/[^0-9]/.test(lowered)) return null;
      value = BigInt(lowered);
    }
    values.push(value);
  }
  // inet_aton part semantics: the final part fills the remaining low octets;
  // each leading part is exactly one octet (must be <= 255). The integer
  // 1-part form fills all four octets.
  let packed: bigint;
  const n = values.length;
  if (n === 1) {
    // inet_aton / getaddrinfo MASK a 1-part value to its low 32 bits rather
    // than reject the overflow (verified: 7147006462 -> 169.254.169.254,
    // 0x17f000001 -> 127.0.0.1, 4294967296 -> 0.0.0.0). Returning null here
    // made _classify treat the entry as a non-IP and ALLOW it, while the OS
    // resolver the replay HTTP client uses reaches the masked internal /
    // metadata IP -- a Py<->TS verdict split (Python delegates to inet_aton,
    // which masks + denies) and an SSRF default-deny under-block. Mask to
    // match the resolver, then re-classify on the true resolved IP (an
    // overflow form masking to a public IP stays allowed).
    packed = (values[0] as bigint) & 0xffffffffn;
  } else {
    packed = 0n;
    for (let i = 0; i < n - 1; i += 1) {
      const octet = values[i] as bigint;
      if (octet > 0xffn) return null;
      packed |= octet << BigInt(8 * (3 - i));
    }
    const last = values[n - 1] as bigint;
    // inet_aton: the (n-1) leading parts are one octet each (top bits), and
    // the LAST part fills the remaining low 32-8*(n-1) bits = 8*(5-n).
    // (The earlier 8*(4-n) was off by one octet: for n===4 it yielded 0 bits,
    // rejecting any last octet >=1 so 0177.0.0.1 / 0x7f.0.0.1 escaped the
    // numeric canonicalization and bypassed the SSRF screen -- round-2 #11.)
    const remainingBits = 8 * (5 - n);
    if (last >= 1n << BigInt(remainingBits)) return null;
    packed |= last;
  }
  const a = Number((packed >> 24n) & 0xffn);
  const b = Number((packed >> 16n) & 0xffn);
  const c = Number((packed >> 8n) & 0xffn);
  const d = Number(packed & 0xffn);
  return `${a}.${b}.${c}.${d}`;
}

/** Parse a dotted-decimal IPv4 literal to its 32-bit integer, or ``null``. */
function _ipv4ToInt(host: string): number | null {
  if (isIP(host) !== 4) return null;
  const parts = host.split(".");
  let value = 0;
  for (const part of parts) {
    value = value * 256 + Number(part);
  }
  return value >>> 0;
}

/** Classify a dotted-decimal IPv4 host. Mirrors the IPv4 arm of the Python
 * ``_classify`` EXACTLY, including its branch ORDER, so the TS allow/deny
 * verdict AND the (denied_reason, denied_cidr) envelope bytes are identical
 * to ``ipaddress.ip_address(host)``-driven classification on CPython
 * 3.12 / 3.13 / 3.14:
 *
 *   1. RFC 1918 explicit (10/8, 172.16/12, 192.168/16)  -> rfc1918 / <cidr>
 *   2. link-local 169.254.0.0/16                         -> link_local / ...
 *   3. is_loopback   127.0.0.0/8                         -> loopback / ...
 *   4. is_multicast  224.0.0.0/4                         -> multicast / ...
 *   5. is_unspecified (0.0.0.0 ONLY, not the whole /8)   -> reserved / 0.0.0.0/8
 *   6. is_private (the full ipaddress private set)       -> rfc1918 / private
 *   7. is_reserved (240.0.0.0/4 -- unreachable: caught by 6) -> reserved / ...
 *
 * Round-2 follow-on (roborev MED): the previous tail (a) DENIED CGNAT
 * 100.64.0.0/10 as rfc1918, but Python's ``is_private`` and ``is_reserved``
 * are BOTH False for 100.64.0.0/10 on 3.12/3.13/3.14, so Python ALLOWS it --
 * the TS deny was a parity break (over-block); and (b) labelled the
 * documentation / benchmarking / 240.0.0.0/4 / 192.0.0.0/24 /
 * 255.255.255.255 blocks ``reserved`` / ``ipv4_reserved``, but Python tags
 * every one of them ``is_private`` (the private check precedes the reserved
 * check), so the parity-correct reason/cidr is ``rfc1918`` / ``private``.
 * A public IPv4 returns ``null`` (allowed). */
function _classifyIpv4(host: string): readonly [string, string] | null {
  const v = _ipv4ToInt(host);
  if (v === null) return null;
  const inNet = (net: number, prefix: number): boolean => {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return ((v & mask) >>> 0) === ((net & mask) >>> 0);
  };
  // (1) RFC 1918 explicit -- keep the specific matched CIDR.
  if (inNet(0x0a000000, 8)) return ["rfc1918", "10.0.0.0/8"];
  if (inNet(0xac100000, 12)) return ["rfc1918", "172.16.0.0/12"];
  if (inNet(0xc0a80000, 16)) return ["rfc1918", "192.168.0.0/16"];
  // (2) link-local.
  if (inNet(0xa9fe0000, 16)) return ["link_local", "169.254.0.0/16"];
  // (3) loopback.
  if (inNet(0x7f000000, 8)) return ["loopback", "127.0.0.0/8"];
  // (4) multicast.
  if (inNet(0xe0000000, 4)) return ["multicast", "224.0.0.0/4"];
  // (5) unspecified -- ONLY 0.0.0.0 (Python ``is_unspecified``). Interior
  // 0.0.0.0/8 addresses (e.g. 0.0.0.5) are ``is_private``, handled at (6).
  if (v === 0) return ["reserved", "0.0.0.0/8"];
  // (6) The remaining IANA private blocks Python tags via ``is_private``
  // (``ipaddress``'s _private_networks): the 0.0.0.0/8 remainder, the IETF
  // protocol-assignment 192.0.0.0/24, the documentation TEST-NET-1/2/3
  // (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), the benchmarking
  // 198.18.0.0/15, and the future-use 240.0.0.0/4 (which also covers the
  // 255.255.255.255 limited broadcast). All tag ``rfc1918`` / ``private`` --
  // ``is_private`` runs BEFORE ``is_reserved`` in CPython, so the future-use
  // /4 never reaches the reserved label.
  if (inNet(0x00000000, 8)) return ["rfc1918", "private"]; // 0.0.0.0/8 remainder
  if (inNet(0xc0000000, 24)) return ["rfc1918", "private"]; // 192.0.0.0/24
  if (inNet(0xc0000200, 24)) return ["rfc1918", "private"]; // 192.0.2.0/24 TEST-NET-1
  if (inNet(0xc6336400, 24)) return ["rfc1918", "private"]; // 198.51.100.0/24 TEST-NET-2
  if (inNet(0xcb007100, 24)) return ["rfc1918", "private"]; // 203.0.113.0/24 TEST-NET-3
  if (inNet(0xc6120000, 15)) return ["rfc1918", "private"]; // 198.18.0.0/15 benchmarking
  if (inNet(0xf0000000, 4)) return ["rfc1918", "private"]; // 240.0.0.0/4 future use
  // CGNAT 100.64.0.0/10 is is_private == False AND is_reserved == False on
  // CPython 3.12/3.13/3.14, so it is NOT denied here (parity: Python allows
  // it). A public IPv4 falls through to null.
  return null;
}

/** Expand an IPv6 literal to its 8 16-bit hextets as bigint, or ``null``. */
function _ipv6Hextets(host: string): bigint[] | null {
  if (isIP(host) !== 6) return null;
  let h = host;
  // An IPv4-mapped / transition trailer (e.g. ``::ffff:1.2.3.4``) is handled
  // by the caller via dedicated unwrap helpers; for the generic hextet
  // expansion convert a trailing dotted-IPv4 group into two hextets.
  const lastColon = h.lastIndexOf(":");
  const trailer = h.slice(lastColon + 1);
  if (trailer.includes(".")) {
    const v = _ipv4ToInt(trailer);
    if (v === null) return null;
    const hi = (v >>> 16) & 0xffff;
    const lo = v & 0xffff;
    h = `${h.slice(0, lastColon + 1)}${hi.toString(16)}:${lo.toString(16)}`;
  }
  const doubleColon = h.indexOf("::");
  let groups: string[];
  if (doubleColon >= 0) {
    const [left, right] = h.split("::");
    const leftParts = left ? left.split(":") : [];
    const rightParts = right ? right.split(":") : [];
    const fill = 8 - leftParts.length - rightParts.length;
    if (fill < 0) return null;
    groups = [...leftParts, ...Array(fill).fill("0"), ...rightParts];
  } else {
    groups = h.split(":");
  }
  if (groups.length !== 8) return null;
  return groups.map((g) => BigInt(parseInt(g === "" ? "0" : g, 16)));
}

/** Assemble an IPv6 literal's 128-bit integer from its hextets. */
function _ipv6ToInt(hextets: bigint[]): bigint {
  let value = 0n;
  for (const hx of hextets) {
    value = (value << 16n) | hx;
  }
  return value;
}

/** Classify an IPv6 host. Mirrors the IPv6 arm of the Python ``_classify``,
 * including unwrap-and-reclassify for IPv4-mapped (``::ffff:a.b.c.d``),
 * 6to4 (2002::/16), NAT64 (64:ff9b::/96), and the deprecated
 * IPv4-compatible (``::/96``) transition forms so an embedded internal /
 * metadata IPv4 cannot tunnel past the guard, while an embedded PUBLIC IPv4
 * stays allowed. */
function _classifyIpv6(host: string): readonly [string, string] | null {
  const hextets = _ipv6Hextets(host);
  if (hextets === null) return null;
  const value = _ipv6ToInt(hextets);
  const low32 = Number(value & 0xffffffffn) >>> 0;
  const embeddedIpv4 = (v: number): string =>
    `${(v >>> 24) & 0xff}.${(v >>> 16) & 0xff}.${(v >>> 8) & 0xff}.${v & 0xff}`;
  // IPv4-mapped ``::ffff:a.b.c.d`` -- bits 32..47 == 0xffff, high bits 0.
  const high96 = value >> 32n;
  if (high96 === 0xffffn) {
    return _classify(embeddedIpv4(low32));
  }
  // 6to4 2002::/16 -- embedded IPv4 in bits 16..47.
  if ((value >> 112n) === 0x2002n) {
    const v = Number((value >> 80n) & 0xffffffffn) >>> 0;
    return _classify(embeddedIpv4(v));
  }
  // NAT64 64:ff9b::/96 -- embedded IPv4 in the low 32 bits. high96 is the
  // TOP 96 bits (value >> 32n), so the /96 prefix is 0x64ff9b shifted into the
  // high 32 bits of that window (0x64ff9b << 64), NOT the bare 0x64ff9b (which
  // never matched, so 64:ff9b::7f00:1 wrapping 127.0.0.1 was ALLOWED -- round-2
  // #11). Mirrors Python `ip in _NAT64_NETWORK` (membership in 64:ff9b::/96).
  if (high96 === 0x64ff9bn << 64n) {
    return _classify(embeddedIpv4(low32));
  }
  // Native specials in the SAME branch order as Python's IPv6 ``_classify``
  // arm: link-local, then ``is_private`` (which subsumes the documentation,
  // loopback, and unspecified blocks below), then multicast, then the
  // IPv4-compatible ::/96 unwrap, so the allow/deny verdict AND the
  // (denied_reason, denied_cidr) bytes match CPython 3.12/3.13/3.14.
  //
  // Link-local fe80::/10.
  if ((value >> 118n) === (0xfe80n >> 6n)) {
    return ["link_local", "fe80::/10"];
  }
  // ``is_private`` blocks Python tags ``rfc1918`` / ``fc00::/7``: ULA
  // fc00::/7, loopback ``::1``, the IPv6 documentation 2001:db8::/32, and --
  // critically -- the unspecified ``::`` (``is_private`` runs BEFORE
  // ``is_unspecified`` in CPython, so ``::`` is fc00::/7, NOT reserved/::/128:
  // the previous ``["reserved", "::/128"]`` was a byte-parity break in this
  // same finding's class). Only these stable, uniformly-private prefixes are
  // matched here; the irregular per-sub-block private carve-outs inside
  // 2001::/23, 100::/64, and 3fff::/20 (where adjacent sub-blocks flip
  // global<->private across CPython's IANA special-registry) are intentionally
  // NOT hand-rolled to avoid introducing fresh divergences for their global
  // sub-blocks.
  if (value === 0n) return ["rfc1918", "fc00::/7"]; // ``::`` unspecified
  if (value === 1n) return ["rfc1918", "fc00::/7"]; // ``::1`` loopback
  if ((value >> 96n) === 0x20010db8n) return ["rfc1918", "fc00::/7"]; // 2001:db8::/32
  if ((value >> 121n) === (0xfc00n >> 9n)) return ["rfc1918", "fc00::/7"]; // fc00::/7
  // Multicast ff00::/8.
  if ((value >> 120n) === 0xffn) return ["multicast", "ff00::/8"];
  // Deprecated IPv4-compatible ::/96 (high 96 bits zero, not the specials
  // above) -- unwrap the embedded IPv4. ``::`` and ``::1`` are already handled
  // above as private, so only genuine IPv4-compatible wrappers reach here.
  if (high96 === 0n) {
    return _classify(embeddedIpv4(low32));
  }
  return null;
}

/** Parse a CIDR ("a.b.c.d/p" or "ipv6/p") into its inclusive integer range. */
function _cidrToRange(
  cidr: string,
): { v: 4 | 6; first: bigint; last: bigint } | null {
  const slash = cidr.indexOf("/");
  if (slash < 0) return null;
  const addr = cidr.slice(0, slash);
  const prefixStr = cidr.slice(slash + 1);
  if (!/^\d+$/.test(prefixStr)) return null;
  const prefix = Number(prefixStr);
  const kind = isIP(addr);
  if (kind === 4) {
    if (prefix > 32) return null;
    const i = _ipv4ToInt(addr);
    if (i === null) return null;
    const ai = BigInt(i >>> 0);
    const hostBits = BigInt(32 - prefix);
    const first = hostBits === 32n ? 0n : (ai >> hostBits) << hostBits;
    const last = first | ((1n << hostBits) - 1n);
    return { v: 4, first, last };
  }
  if (kind === 6) {
    if (prefix > 128) return null;
    const hextets = _ipv6Hextets(addr);
    if (hextets === null) return null;
    const ai = _ipv6ToInt(hextets);
    const hostBits = BigInt(128 - prefix);
    const first = hostBits === 128n ? 0n : (ai >> hostBits) << hostBits;
    const last = first | ((1n << hostBits) - 1n);
    return { v: 6, first, last };
  }
  return null;
}

// Special-purpose / non-global ranges a CIDR allowlist entry must not OVERLAP
// (byte-for-byte the Python network_policy._DENIED_SUPERNETS list). A broad CIDR
// supernet can contain these with a public-looking network address.
const _DENIED_SUPERNETS: ReadonlyArray<{
  v: 4 | 6;
  first: bigint;
  last: bigint;
  cidr: string;
}> = (
  [
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
    // IPv4-in-IPv6 transition prefixes: a broad CIDR over IPv4-mapped
    // (::ffff:0.0.0.0/96), 6to4 (2002::/16), NAT64 (64:ff9b::/96), or the
    // deprecated IPv4-compatible (::/96) space can embed denied IPv4 ranges with
    // a public-looking IPv6 network address (e.g. ::800:0/102 spans ::a00:0 ==
    // 10.0.0.0). Mirrors the Python _DENIED_SUPERNETS transition entries; ::/96
    // subsumes the ::1/128 and ::/128 specials above. The IPv4-mapped entry is
    // written in DOTTED form (::ffff:0.0.0.0/96, not ::ffff:0:0/96) so the
    // denied_cidr envelope byte matches Python's str(ip_network(...)) -- CPython
    // renders the IPv4-mapped /96 dotted; both forms parse to the same range.
    "::ffff:0.0.0.0/96",
    "2002::/16",
    "64:ff9b::/96",
    "::/96",
  ] as const
).map((c) => {
  const r = _cidrToRange(c);
  /* c8 ignore next */
  if (r === null) throw new Error(`bad denied supernet literal: ${c}`);
  return { v: r.v, first: r.first, last: r.last, cidr: c };
});

/** Return ``[denied_reason, denied_cidr]`` or ``null`` if ``host`` is not
 * denied by the SSRF guard. Mirrors the Python ``_classify`` chokepoint:
 * normalise surrounding whitespace + trailing FQDN-root dots, match the
 * cloud-metadata literals first, then IPv4 / IPv6 ranges (including
 * numeric-form normalisation and IPv4-in-IPv6 unwrap), then the
 * reserved-hostname denylist. */
function _classify(host: string): readonly [string, string] | null {
  if (!host) return null;
  host = host.trim().replace(/\.+$/, "");
  if (!host) return null;
  if (_CLOUD_METADATA_IPS.has(host)) {
    return ["cloud_metadata", host];
  }
  // CIDR-block entry (e.g. "10.0.0.0/8", "fc00::/7"): the replay sandbox accepts
  // CIDR allowlist entries, so a private/reserved RANGE must be denied like a
  // single internal address. Byte-for-byte mirror of the Python `_classify`
  // CIDR branch.
  if (host.includes("/")) {
    // (1) network/address portion internal -> denied (the common case).
    const direct = _classify(host.split("/", 1)[0] ?? "");
    if (direct !== null) return direct;
    // (2) a BROAD CIDR supernet can CONTAIN internal ranges with a public-looking
    // network address (8.0.0.0/6 contains 10.0.0.0/8). Deny any CIDR that
    // OVERLAPS a special-purpose range (mirrors Python _DENIED_SUPERNETS).
    const range = _cidrToRange(host);
    if (range === null) return null;
    for (const d of _DENIED_SUPERNETS) {
      if (d.v === range.v && range.first <= d.last && d.first <= range.last) {
        return ["rfc1918", d.cidr];
      }
    }
    return null;
  }
  const kind = isIP(host);
  if (kind === 4) {
    return _classifyIpv4(host);
  }
  if (kind === 6) {
    return _classifyIpv6(host);
  }
  // Not a literal IP per the strict parser. First, the numeric-IPv4
  // encodings the libc resolver accepts (integer / hex / octal / short-form):
  // canonicalise and re-classify so e.g. ``2130706433`` is rejected as
  // 127.0.0.1 while ``134744072`` stays allowed as the public 8.8.8.8.
  const canonical = _canonicalNumericIpv4(host);
  if (canonical !== null && canonical !== host) {
    return _classify(canonical);
  }
  // Hostname denylist. Normalise: lowercase + strip a single trailing dot.
  let normalized = host.toLowerCase();
  if (normalized.endsWith(".")) {
    normalized = normalized.slice(0, -1);
  }
  if (_HOSTNAME_DENYLIST_EXACT.has(normalized)) {
    return ["reserved_hostname", normalized];
  }
  for (const suffix of _HOSTNAME_DENYLIST_SUFFIXES) {
    if (normalized.endsWith(suffix)) {
      return ["reserved_hostname", suffix];
    }
  }
  // Hostname not in the denylist. General hostname-based SSRF is out of
  // scope for this SDK-boundary guard (it requires DNS-pinning policy owned
  // by the replay-sandbox network primitive).
  return null;
}

/**
 * Validate every entry in ``entries`` against the SSRF guard. Throws
 * {@link EgressDenied} on the FIRST rejected entry (short-circuit, parity
 * with the Python ``validate_egress_entries``); returns silently if every
 * entry passes. The thrown error carries a structured ``envelope`` ready to
 * serialise directly into an HTTP rejection body.
 */
export function validateEgressEntries(entries: readonly string[]): void {
  for (const entry of entries) {
    if (typeof entry !== "string" || entry === "") {
      continue;
    }
    const host = _extractHost(entry);
    const classification = _classify(host);
    if (classification === null) {
      continue;
    }
    const [deniedReason, deniedCidr] = classification;
    throw new EgressDenied({
      code: RELAY_REPLAY_SSRF_CODE,
      http_status: _EGRESS_DENIED_HTTP_STATUS,
      denied_entry: entry,
      denied_reason: deniedReason,
      denied_cidr: deniedCidr,
    });
  }
}

// ---------------------------------------------------------------------------
// Span types
// ---------------------------------------------------------------------------

export interface ModelCallSpan {
  readonly span_id: string;
  readonly span_kind: "model_call";
  readonly provider: string;
  readonly model: string;
  readonly model_signature: string;
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly chunk_count: number;
  readonly first_token_latency_ms: number | null;
  readonly started_at: string;
  readonly ended_at: string;
}

export interface ToolCallSpan {
  readonly span_id: string;
  readonly span_kind: "tool_call";
  readonly tool_name: string;
  readonly side_effect: boolean;
  readonly idempotency_key?: string;
  readonly replay_policy?: ReplayPolicy;
  readonly args_digest: string;
  readonly started_at: string;
  readonly ended_at: string;
}

// ---------------------------------------------------------------------------
// Streaming model-call adapter
// ---------------------------------------------------------------------------

export interface StreamChunk {
  /** Optional inferred token delta. */
  readonly tokens?: number;
  /** Optional partial output text (not persisted). */
  readonly content?: string;
  /** Provider-specific raw chunk; not persisted by the SDK. */
  readonly raw?: unknown;
}

export interface ModelCallInput {
  readonly provider: string;
  readonly model: string;
  /**
   * Provider-supplied response identifier surrogate (Anthropic uses
   * ``response.id``; OpenAI uses ``system_fingerprint`` when present).
   * Required for refresh-policy parity with the Python adapter.
   */
  readonly modelSignature: string;
  /** Optional caller-supplied prompt-token count. */
  readonly promptTokens?: number;
  /** When provided, the SDK aggregates tokens + first_token_latency from the stream. */
  readonly stream?: AsyncIterable<StreamChunk>;
  /** Optional caller-supplied non-streaming completion-token count. */
  readonly completionTokens?: number;
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

export interface RunHttpClientOptions {
  baseUrl: string;
  authHeader?: string;
  bearerDigest?: string;
  /** Test-only fetch injection. */
  fetchImpl?: (url: string, init?: RequestInit) => Promise<Response>;
}

export interface RunHttpClient {
  postIngestRun(envelope: IngestRunEnvelope): Promise<Record<string, unknown>>;
  postGateDraft(gateId: string, envelope: GateDraftEnvelope): Promise<Record<string, unknown>>;
  getGateDecision(decisionId: string): Promise<Record<string, unknown>>;
  getRunResult(runId: string): Promise<Record<string, unknown>>;
  postEvidence(envelope: EvidenceEnvelope): Promise<Record<string, unknown>>;
  postReplayCaseRun(
    caseId: string,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
  /**
   * Create a replay case (POST /v1/replay-cases). Required by
   * replayCreate() when no explicit caseId is supplied (the sidecar run
   * endpoint 404s for a case it never created). Optional on the interface so
   * stubs that only exercise the explicit-caseId path need not implement it.
   */
  postReplayCaseCreate?(
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
}

/**
 * Default RunHttpClient implementation backed by Node's native fetch.
 *
 * Every POST that creates a resource attaches an ``Idempotency-Key``
 * header carrying a fresh Crockford base32 ULID (VAL-W4-014). Every
 * non-2xx response is parsed for a structured error envelope and
 * surfaced as the appropriate typed exception.
 */
export class FetchRunHttpClient implements RunHttpClient {
  readonly baseUrl: string;
  private readonly authHeader: string | null;
  private readonly bearerDigest: string | null;
  private readonly fetchImpl: (url: string, init?: RequestInit) => Promise<Response>;

  constructor(options: RunHttpClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.authHeader = options.authHeader ?? null;
    this.bearerDigest = options.bearerDigest ?? null;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  private headers(extraIdempotencyKey?: string): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.authHeader !== null) h["X-Relay-Auth"] = this.authHeader;
    if (this.bearerDigest !== null) h["X-Relay-Bearer-Digest"] = this.bearerDigest;
    if (extraIdempotencyKey !== undefined) h["Idempotency-Key"] = extraIdempotencyKey;
    return h;
  }

  private async parseJson(resp: Response): Promise<Record<string, unknown>> {
    try {
      const obj = (await resp.json()) as unknown;
      if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return {};
      return obj as Record<string, unknown>;
    } catch {
      return {};
    }
  }

  private async raiseForError(resp: Response): Promise<void> {
    if (resp.status >= 200 && resp.status < 300) return;
    const body = await this.parseJson(resp);
    const code = String(body["code"] ?? "");
    const message = String(body["message"] ?? `sidecar returned HTTP ${resp.status}`);
    let blockedSurface = typeof body["blocked_surface"] === "string"
      ? (body["blocked_surface"] as string)
      : undefined;
    if (blockedSurface === undefined) {
      try {
        const u = new URL(resp.url);
        blockedSurface = `REQUEST ${u.pathname}`;
      } catch {
        blockedSurface = "relay-sdk";
      }
    }
    const requestId = typeof body["request_id"] === "string" ? (body["request_id"] as string) : null;
    const traceId = typeof body["trace_id"] === "string" ? (body["trace_id"] as string) : null;

    const details: Record<string, unknown> = {
      http_status: resp.status,
      code,
      url: resp.url,
      response_body: body,
    };
    if (code === RELAY_ING_022_CODE || code === RELAY_GATE_021_CODE) {
      // VAL-W4-015 / spec C.5: surface the offending anchor name(s) so
      // callers can attribute stale-handoff failures precisely.
      details["mismatched_anchor"] = body["mismatched_anchor"] ?? [];
    }
    if (code === RELAY_ING_031_CODE) {
      // VAL-W4-010: surface forged_field attribution.
      const detailsBody = body["details"];
      if (detailsBody !== undefined && typeof detailsBody === "object" && detailsBody !== null) {
        const forged = (detailsBody as Record<string, unknown>)["forbidden_field"]
          ?? (detailsBody as Record<string, unknown>)["forged_field"];
        if (forged !== undefined) {
          details["forged_field"] = forged;
        }
      }
    }

    const envelope: ErrorEnvelopeWire = {
      code: code || "RELAY-FUTURE-999",
      http_status: resp.status,
      message,
      ...(blockedSurface !== undefined ? { blocked_surface: blockedSurface } : {}),
      ...(typeof body["retry_advice"] === "string" || (typeof body["retry_advice"] === "object" && body["retry_advice"] !== null)
        ? { retry_advice: body["retry_advice"] }
        : {}),
      request_id: requestId,
      trace_id: traceId,
      details,
    };
    const targetCls = resolveClassForCode(envelope.code);
    // Special-case the canonical-write rejection: surface as the W4
    // adversarial typed leaf RelayCanonicalStatusForbidden by default;
    // tests can sub-class for finer attribution.
    if (envelope.code === RELAY_ING_031_CODE) {
      throw new RelayCanonicalStatusForbidden(message, {
        code: envelope.code,
        httpStatus: resp.status,
        ...(blockedSurface !== undefined ? { blockedSurface } : {}),
        retryAdvice: envelope.retry_advice,
        requestId,
        traceId,
        details,
      });
    }
    if (envelope.code === RELAY_REPLAY_002_CODE) {
      throw new RelayReplayPrecondition(message, {
        code: envelope.code,
        httpStatus: resp.status,
        ...(blockedSurface !== undefined ? { blockedSurface } : {}),
        retryAdvice: envelope.retry_advice,
        requestId,
        traceId,
        details,
      });
    }
    if (envelope.code === RELAY_EVID_002_CODE) {
      throw new RelayEvidenceIncomplete(message, {
        code: envelope.code,
        httpStatus: resp.status,
        ...(blockedSurface !== undefined ? { blockedSurface } : {}),
        retryAdvice: envelope.retry_advice,
        requestId,
        traceId,
        details,
      });
    }
    if (envelope.code === RELAY_ING_022_CODE) {
      throw new RelayHandoffIncomplete(message, {
        code: envelope.code,
        httpStatus: resp.status,
        ...(blockedSurface !== undefined ? { blockedSurface } : {}),
        retryAdvice: envelope.retry_advice,
        requestId,
        traceId,
        details,
      });
    }
    // Fall back to namespace intermediate / RelayUnknownError per the
    // resolver. Always surface a typed exception (never a raw Error).
    throw new (targetCls as unknown as { new (m: string, opts: object): RelayError })(message, {
      code: envelope.code || RelayUnknownError.defaultCode,
      httpStatus: resp.status,
      ...(blockedSurface !== undefined ? { blockedSurface } : {}),
      retryAdvice: envelope.retry_advice,
      requestId,
      traceId,
      details,
    });
  }

  async postIngestRun(envelope: IngestRunEnvelope): Promise<Record<string, unknown>> {
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/ingest/runs`, {
      method: "POST",
      headers: this.headers(envelope.idempotency_key),
      body: JSON.stringify(envelope),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async postGateDraft(
    gateId: string,
    envelope: GateDraftEnvelope,
  ): Promise<Record<string, unknown>> {
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/gates/${gateId}/drafts`, {
      method: "POST",
      headers: this.headers(envelope.draft_id),
      body: JSON.stringify(envelope),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async getGateDecision(decisionId: string): Promise<Record<string, unknown>> {
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/gate-decisions/${decisionId}`, {
      method: "GET",
      headers: this.headers(),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async getRunResult(runId: string): Promise<Record<string, unknown>> {
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/runs/${runId}/result`, {
      method: "GET",
      headers: this.headers(),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async postEvidence(envelope: EvidenceEnvelope): Promise<Record<string, unknown>> {
    const idempotency = newUlid();
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/evidence-bundles`, {
      method: "POST",
      headers: this.headers(idempotency),
      body: JSON.stringify(envelope),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async postReplayCaseRun(
    caseId: string,
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const idempotency = newUlid();
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/replay-cases/${caseId}/run`, {
      method: "POST",
      headers: this.headers(idempotency),
      body: JSON.stringify(body),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }

  async postReplayCaseCreate(
    body: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const idempotency = newUlid();
    const resp = await this.fetchImpl(`${this.baseUrl}/v1/replay-cases`, {
      method: "POST",
      headers: this.headers(idempotency),
      body: JSON.stringify(body),
    });
    await this.raiseForError(resp);
    return this.parseJson(resp);
  }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

export interface RunOptions {
  runId?: string;
  agent: Record<string, unknown>;
  /** Optional release_sha mapped from caller-supplied ``version``. */
  releaseSha?: string;
  actorIdentityHash: string;
  manifestCommitHash: string;
  redactionPolicyVersion: string;
  projectId?: string;
  flushPolicy?: FlushPolicy | Partial<{ mode: "sync" | "async"; onError: "raise" | "drop_and_log" }>;
  /** Pre-built HTTP client. Tests can inject a stub here. */
  httpClient: RunHttpClient;
}

export interface ToolCallOptions {
  toolName: string;
  args: unknown;
  sideEffect?: boolean;
  idempotencyKey?: string;
  replayPolicy?: ReplayPolicy;
}

export interface ReplayCreateOptions {
  caseId?: string;
  runId?: string;
  mode?: "cassette" | "live";
  acknowledgeDegradedApproximation?: boolean;
  /**
   * Optional egress allowlist for the replay case. Every entry is screened
   * by the SDK-boundary SSRF guard ({@link validateEgressEntries}) BEFORE
   * any HTTP I/O. A rejected entry throws {@link EgressDenied}; the request
   * is not sent. Parity with the Python SDK ``replay_create`` option of the
   * same name (packages/sdk-python/relay/run.py).
   */
  egressAllowlist?: string[];
}

/**
 * SDK-side run-scoped lifecycle context (W4.2).
 *
 * Open via :class:`Relay.trace`; release via :meth:`Run.close`. The
 * :class:`Run` instance carries the three-anchor handoff state, the
 * configured flush policy, and the SDK-generated ``run_id``. Per
 * CLAUDE.md invariant #1 the :class:`Run` NEVER writes canonical
 * results -- it submits drafts and reads canonical decisions the
 * control plane writes.
 */
export class Run {
  readonly runId: string;
  readonly traceId: string;
  readonly projectId: string;
  readonly agent: Record<string, unknown>;
  readonly releaseSha: string | undefined;
  readonly actorIdentityHash: string;
  readonly manifestCommitHash: string;
  readonly redactionPolicyVersion: string;
  readonly flushPolicy: FlushPolicy;
  /** Idempotency keys emitted across all envelopes (test seam). */
  readonly idempotencyKeys: string[] = [];
  /** Most recent lifecycle status the SDK observed. */
  private lastStatus: LifecycleStatus = "started";
  private sequenceNumber = 0;
  private readonly httpClient: RunHttpClient;
  private dispatcher: AsyncFlushDispatcher | null = null;
  private closed = false;

  constructor(options: RunOptions) {
    this.runId = options.runId ?? newUlid();
    this.traceId = newUlid();
    this.projectId = options.projectId ?? crypto.randomUUID();
    this.agent = { ...options.agent };
    this.releaseSha = options.releaseSha;
    this.actorIdentityHash = options.actorIdentityHash;
    this.manifestCommitHash = options.manifestCommitHash;
    this.redactionPolicyVersion = options.redactionPolicyVersion;
    this.flushPolicy =
      options.flushPolicy instanceof FlushPolicy
        ? options.flushPolicy
        : FlushPolicy.fromInput(options.flushPolicy);
    this.httpClient = options.httpClient;
  }

  /** Submit a lifecycle-metadata envelope (started/succeeded/failed/aborted). */
  async capture(args: { clientLifecycleStatus: LifecycleStatus }): Promise<Record<string, unknown>> {
    this.lastStatus = args.clientLifecycleStatus;
    return this.submitLifecycle(args.clientLifecycleStatus);
  }

  /**
   * Streaming-aware model_call (VAL-W4-012).
   *
   * Collects stream chunks (or accepts pre-aggregated counts) and emits
   * exactly ONE ``model_call`` span per logical call with summarised
   * fields. Per-chunk events do NOT become separate spans.
   */
  async modelCall(input: ModelCallInput): Promise<ModelCallSpan> {
    const startedAt = utcNowIso8601();
    const startMs = Date.now();
    let chunkCount = 0;
    // VAL-ISO-040 (correctness): when a stream is supplied the completion-token
    // count is derived from the stream's per-chunk deltas. Initialising the
    // accumulator from the caller-supplied ``completionTokens`` and then ADDING
    // each chunk delta double-counts when both are provided (base +
    // sum(deltas)). The stream path therefore starts from 0 and ignores
    // ``input.completionTokens``; the non-streaming branch below uses the
    // caller-supplied count verbatim.
    let completionTokens = input.stream !== undefined ? 0 : (input.completionTokens ?? 0);
    let firstTokenLatencyMs: number | null = null;
    if (input.stream !== undefined) {
      for await (const chunk of input.stream) {
        chunkCount += 1;
        if (firstTokenLatencyMs === null) {
          firstTokenLatencyMs = Date.now() - startMs;
        }
        if (typeof chunk.tokens === "number" && Number.isInteger(chunk.tokens)) {
          completionTokens += chunk.tokens;
        }
      }
    } else {
      // Non-streaming: caller-supplied counts.
      completionTokens = input.completionTokens ?? 0;
    }
    const endedAt = utcNowIso8601();
    const span: ModelCallSpan = {
      span_id: newUlid(),
      span_kind: "model_call",
      provider: input.provider,
      model: input.model,
      model_signature: input.modelSignature,
      prompt_tokens: input.promptTokens ?? 0,
      completion_tokens: completionTokens,
      chunk_count: chunkCount,
      first_token_latency_ms: firstTokenLatencyMs,
      started_at: startedAt,
      ended_at: endedAt,
    };
    return span;
  }

  /**
   * Tool-call span (VAL-W4-013).
   *
   * If ``sideEffect: true``, both ``idempotencyKey`` AND ``replayPolicy``
   * MUST be supplied. Missing either raises
   * :class:`RelaySideEffectMissingFieldsError` BEFORE the span opens.
   */
  toolCall(options: ToolCallOptions): ToolCallSpan {
    const sideEffect = options.sideEffect === true;
    if (sideEffect) {
      const missing: string[] = [];
      if (typeof options.idempotencyKey !== "string" || options.idempotencyKey === "") {
        missing.push("idempotencyKey");
      }
      if (
        typeof options.replayPolicy !== "string" ||
        !REPLAY_POLICIES.has(options.replayPolicy)
      ) {
        missing.push("replayPolicy");
      }
      if (missing.length > 0) {
        throw new RelaySideEffectMissingFieldsError(
          `tool_call with side_effect: true requires both idempotencyKey AND replayPolicy; missing: ${JSON.stringify(missing)}`,
          {
            code: RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CODE,
            details: {
              missing_fields: missing,
              tool_name: options.toolName,
              side_effect: true,
            },
          },
        );
      }
    }
    const startedAt = utcNowIso8601();
    const argsDigest = digestArgs(options.args);
    const endedAt = utcNowIso8601();
    const span: ToolCallSpan = {
      span_id: newUlid(),
      span_kind: "tool_call",
      tool_name: options.toolName,
      side_effect: sideEffect,
      ...(sideEffect
        ? {
            idempotency_key: options.idempotencyKey as string,
            replay_policy: options.replayPolicy as ReplayPolicy,
          }
        : {}),
      args_digest: argsDigest,
      started_at: startedAt,
      ended_at: endedAt,
    };
    return span;
  }

  /**
   * Submit a gate-decision DRAFT and read the canonical decision
   * (VAL-W4-015). The SDK NEVER computes pass/fail.
   */
  async gateEvaluate(args: {
    gateId: string;
    releaseSha: string;
    evalRunIds: string[];
    workerId?: string;
    scopeType?: string;
    round?: number;
    evidenceRefs?: string[];
  }): Promise<{ envelope: GateDraftEnvelope; decision: Record<string, unknown> }> {
    const envelope = buildGateDraftEnvelope({
      gateId: args.gateId,
      releaseSha: args.releaseSha,
      evalRunIds: args.evalRunIds,
      manifestCommitHash: this.manifestCommitHash,
      actorIdentityHash: this.actorIdentityHash,
      ...(args.workerId !== undefined ? { workerId: args.workerId } : {}),
      ...(args.scopeType !== undefined ? { scopeType: args.scopeType } : {}),
      ...(args.round !== undefined ? { round: args.round } : {}),
      ...(args.evidenceRefs !== undefined ? { evidenceRefs: args.evidenceRefs } : {}),
    });
    this.idempotencyKeys.push(envelope.draft_id);
    const draftResp = await this.httpClient.postGateDraft(args.gateId, envelope);
    const decisionId =
      (typeof draftResp["decision_id"] === "string" && (draftResp["decision_id"] as string)) ||
      (typeof draftResp["draft_id"] === "string" && (draftResp["draft_id"] as string));
    if (!decisionId) {
      throw new RelayError("sidecar gate draft response omitted decision_id", {
        details: { response: draftResp },
      });
    }
    const decision = await this.httpClient.getGateDecision(decisionId);
    return { envelope, decision };
  }

  /**
   * Create a replay case bound to the canonical RunResult (VAL-W4-017).
   *
   * Defaults to cassette mode. Live mode requires the caller to opt in
   * via ``{mode: 'live', acknowledgeDegradedApproximation: true}``.
   */
  async replayCreate(options: ReplayCreateOptions = {}): Promise<Record<string, unknown>> {
    const mode: "cassette" | "live" = options.mode ?? "cassette";
    if (mode !== "cassette" && mode !== "live") {
      throw new RelayConfigError(
        `replay mode must be 'cassette' or 'live'; received ${JSON.stringify(mode)}`,
        { details: { field: "mode", received: mode } },
      );
    }
    if (mode === "live" && options.acknowledgeDegradedApproximation !== true) {
      throw new RelayReplayLiveModeUnacknowledgedError(
        "live replay is a degraded approximation; pass {mode: 'live', acknowledgeDegradedApproximation: true} to opt in",
        {
          code: RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CODE,
          details: {
            mode: "live",
            acknowledge_required: true,
          },
        },
      );
    }
    // SDK-boundary SSRF screen (parity with the Python SDK
    // build_replay_case_envelope -> validate_egress_entries). Every
    // caller-supplied egress-allowlist entry is validated BEFORE any HTTP
    // I/O (including the getRunResult preflight); a rejected entry throws
    // EgressDenied and the request is not sent.
    //
    // TOCTOU (roborev HIGH): snapshot the caller's array NOW, by value, and
    // validate + send ONLY this private copy. The previous code aliased
    // ``options.egressAllowlist`` by reference and reused that same array to
    // build the POST body AFTER the awaited getRunResult() preflight -- so a
    // caller (or a concurrent mutator) could append an unvalidated internal
    // host between validation and POST and have it sent to the sidecar. The
    // copy closes that window: the validated bytes are exactly the sent bytes.
    const egressAllowlist = [...(options.egressAllowlist ?? [])];
    if (egressAllowlist.length > 0) {
      validateEgressEntries(egressAllowlist);
    }
    const runIdRef = options.runId ?? this.runId;
    // Pre-flight: confirm the canonical RunResult exists (parity with
    // Python, spec line 2122-2178). The sidecar returns RELAY-REPLAY-002
    // when the run is still in flight; raiseForError() surfaces it as
    // RelayReplayPrecondition.
    await this.httpClient.getRunResult(runIdRef);
    // The sidecar run endpoint POST /v1/replay-cases/{case_id}/run 404s for a
    // case it never created. So when no explicit caseId is supplied, perform
    // the real create-then-run flow (parity with the Python SDK): POST
    // /v1/replay-cases with from_run_id to CREATE, then run the returned id.
    // An explicit caseId is run directly (the caller owns the case lifecycle).
    let caseRef: string;
    if (options.caseId !== undefined) {
      caseRef = options.caseId;
    } else {
      if (this.httpClient.postReplayCaseCreate === undefined) {
        throw new RelayConfigError(
          "replayCreate without an explicit caseId requires an HTTP client that " +
            "implements postReplayCaseCreate (POST /v1/replay-cases)",
          { details: { field: "caseId", reason: "no_create_capability" } },
        );
      }
      const createBody = {
        schema_version: "relay.replay_case.create.v1",
        from_run_id: runIdRef,
        run_id: runIdRef,
        mode,
        manifest_commit_hash: this.manifestCommitHash,
        actor_identity_hash: this.actorIdentityHash,
        egress_allowlist: egressAllowlist,
      };
      const created = await this.httpClient.postReplayCaseCreate(createBody);
      const createdId = created["replay_case_id"] ?? created["case_id"];
      if (typeof createdId !== "string" || createdId === "") {
        throw new RelayConfigError(
          "sidecar replay-case create response omitted a case id (replay_case_id/case_id)",
          { details: { field: "replay_case_id" } },
        );
      }
      caseRef = createdId;
    }
    const body = {
      schema_version: "relay.replay_case.run.v1",
      case_id: caseRef,
      run_id: runIdRef,
      mode,
      manifest_commit_hash: this.manifestCommitHash,
      actor_identity_hash: this.actorIdentityHash,
      egress_allowlist: egressAllowlist,
      ...(mode === "live"
        ? { acknowledge_degraded_approximation: true }
        : {}),
    };
    return this.httpClient.postReplayCaseRun(caseRef, body);
  }

  /**
   * Submit an evidence-bundle envelope bound to its claim (VAL-W4-016).
   *
   * Per CLAUDE.md invariant #2 every required field MUST be present and
   * bound. A missing field raises :class:`RelayEvidenceIncomplete` at
   * the SDK boundary BEFORE the request is sent. The wire payload
   * carries metadata + content digests only -- never plaintext.
   */
  async submitEvidence(args: {
    artifactDigestSha256: string;
    commandId: string;
    exitCode: number;
    spanIds: string[];
    assertionIds: string[];
    runId?: string;
  }): Promise<{ envelope: EvidenceEnvelope; response: Record<string, unknown> }> {
    const envelope = buildEvidenceEnvelope({
      runId: args.runId ?? this.runId,
      artifactDigestSha256: args.artifactDigestSha256,
      commandId: args.commandId,
      exitCode: args.exitCode,
      spanIds: args.spanIds,
      assertionIds: args.assertionIds,
      actorIdentityHash: this.actorIdentityHash,
      manifestCommitHash: this.manifestCommitHash,
      redactionPolicyVersion: this.redactionPolicyVersion,
    });
    const response = await this.httpClient.postEvidence(envelope);
    return { envelope, response };
  }

  /** Wait for any background-dispatched work to drain (test seam). */
  async flush(): Promise<void> {
    if (this.dispatcher !== null) {
      await this.dispatcher.waitIdle();
    }
  }

  /**
   * Release SDK-side resources. Submits the terminal lifecycle envelope
   * per the configured flush policy. Per VAL-W4-018, async mode does
   * NOT block on outbound HTTP I/O.
   */
  async close(args: { exception?: unknown } = {}): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    let terminal: LifecycleStatus;
    if (args.exception !== undefined && this.lastStatus === "started") {
      terminal = "client_failed";
    } else if (this.lastStatus === "started") {
      terminal = "client_succeeded";
    } else {
      terminal = this.lastStatus;
    }
    try {
      await this.submitLifecycle(terminal);
    } finally {
      // Release the dispatcher; do not block in async mode.
      if (this.dispatcher !== null) {
        // Best-effort drain in async/drop_and_log; in sync mode this
        // is a no-op because no work was enqueued.
        if (this.flushPolicy.mode === "sync") {
          await this.dispatcher.close();
        } else {
          // Fire-and-forget close: do not await the chain here so the
          // caller's close() returns immediately (VAL-W4-018).
          void this.dispatcher.close();
        }
      }
    }
  }

  // -- internals ---------------------------------------------------------

  private async submitLifecycle(
    clientLifecycleStatus: LifecycleStatus,
  ): Promise<Record<string, unknown>> {
    this.sequenceNumber += 1;
    const envelope = buildIngestRunEnvelope({
      runId: this.runId,
      traceId: this.traceId,
      projectId: this.projectId,
      agent: this.agent,
      clientLifecycleStatus,
      startedAt: utcNowIso8601(),
      sdkVersion: SDK_VERSION,
      sdkClock: utcNowIso8601(),
      manifestCommitHash: this.manifestCommitHash,
      actorIdentityHash: this.actorIdentityHash,
      redactionPolicyVersion: this.redactionPolicyVersion,
      sequenceNumber: this.sequenceNumber,
    });
    this.idempotencyKeys.push(envelope.idempotency_key);
    if (this.flushPolicy.mode === "sync") {
      try {
        return await this.httpClient.postIngestRun(envelope);
      } catch (err) {
        if (this.flushPolicy.onError === "drop_and_log") {
          // VAL-W4-018: emit one structured stderr envelope and swallow.
          try {
            process.stderr.write(
              `${JSON.stringify({
                schema_version: "relay.error.v1",
                level: "warning",
                code: "RELAY-SDK-FLUSH-DROP-AND-LOG",
                message: err instanceof Error ? err.message : String(err),
                error_class: err instanceof Error ? err.name : "UnknownError",
                details: {
                  on_error: "drop_and_log",
                  run_id: this.runId,
                  sequence_number: envelope.sequence_number,
                },
              })}\n`,
            );
          } catch {
            // Stderr write must never throw into host application.
          }
          return { dropped: true, idempotent_replay: false };
        }
        throw err;
      }
    }
    // async path -- enqueue and return immediately.
    const dispatcher = this.ensureDispatcher();
    dispatcher.submit(async () => {
      await this.httpClient.postIngestRun(envelope);
    });
    return {
      queued: true,
      idempotent_replay: false,
      idempotency_key: envelope.idempotency_key,
    };
  }

  private ensureDispatcher(): AsyncFlushDispatcher {
    if (this.dispatcher === null) {
      this.dispatcher = new AsyncFlushDispatcher({ onError: this.flushPolicy.onError });
    }
    return this.dispatcher;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function digestArgs(args: unknown): string {
  // VAL-ISO-022 (determinism): tool-call args are serialised with the RFC 8785
  // JCS canonicalizer (sorted keys, compact separators) -- the same algorithm
  // the rest of the SDK uses -- so the digest is byte-identical to the Python
  // SDK's json.dumps(..., sort_keys=True, separators=(",", ":")) and is
  // independent of object key insertion order. Plain JSON.stringify serialised
  // keys in insertion order, so the same logical args could yield different
  // digests across processes/SDKs and break cross-SDK/replay determinism.
  //
  // VAL-ISO-041 (correctness): if the args cannot be canonicalised (circular
  // reference, BigInt, or any other unserialisable shape) we raise a typed
  // RelayConfigError. The pre-fix code fell back to String(args), which is the
  // constant "[object Object]" for any non-primitive object -- every
  // unserialisable arg collapsed to the SAME content-free, collision-prone
  // digest. The digest is the evidence binding for the tool call, so a
  // colliding/content-free digest is unacceptable; fail closed instead.
  let serialised: string;
  try {
    serialised = _canonicalJsonStringify(args ?? null);
  } catch (cause) {
    throw new RelayConfigError(
      "tool_call args could not be canonicalised for the args_digest; " +
        "the arguments must be a finite JSON value (no circular references, " +
        "BigInt, or other non-serialisable types)",
      {
        details: {
          field: "args",
          reason: "unserializable_tool_args",
          cause: cause instanceof Error ? cause.message : String(cause),
        },
      },
    );
  }
  return "sha256-" + crypto.createHash("sha256").update(serialised, "utf8").digest("hex");
}
