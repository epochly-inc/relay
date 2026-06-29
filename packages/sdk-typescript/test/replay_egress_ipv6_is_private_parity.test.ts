// F6 (keystone #16): native-IPv6 ``is_private`` SSRF parity between the TS
// egress guard (_classifyIpv6 in src/run.ts) and CPython
// ``ipaddress.IPv6Address.is_private`` (the oracle the Python SDK
// network_policy._classify delegates to).
//
// Bug (pre-fix): TS _classifyIpv6 hand-rolled only a SUBSET of CPython's
// _private_networks -- ::, ::1, 2001:db8::/32, 100::/64, fc00::/7 -- and OMITTED
// the IETF special-registry private blocks 2001::/23 and 3fff::/20 (and the
// NAT64 local-use 64:ff9b:1::/48). So 2001::1, 2001:2::1, 2001:10::1, 3fff::1
// (and their [bracket] / URL forms) were ALLOWED by the TS replay egress
// allowlist while CPython is_private DENIES them -- a Py<->TS verdict divergence
// and an SSRF default-deny bypass (keystone #7 + #16). CPython is_private is
// ``addr in ANY _private_networks AND addr in NO _private_networks_exceptions``,
// so the GLOBAL carve-outs inside 2001::/23 (2001:1::1, 2001:1::2, 2001:3::/32,
// 2001:4:112::/48, 2001:20::/28, 2001:30::/28) stay ALLOWED -- TS must NOT
// over-block them either.
//
// Fix: TS _classifyIpv6 now delegates to _ipv6IsPrivate (a faithful replica of
// CPython _private_networks MINUS _private_networks_exceptions). This suite is
// the structural tripwire: every expected verdict below is the verbatim output
// of the REAL CPython network_policy._classify (captured from CPython 3.14.3 --
// see the mirror Python test
// packages/sdk-python/tests/test_f6_ipv6_is_private_egress_parity.py, which
// drives the live oracle so a future CPython is_private table change is caught
// and signals this TS copy needs updating).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { describe, expect, it } from "vitest";

import {
  EgressDenied,
  RELAY_REPLAY_SSRF_CODE,
  validateEgressEntries,
} from "../src/run.js";

// validateEgressEntries throws EgressDenied for a denied entry and returns
// silently for an allowed one. Mirror the helper used by the existing native
// reserved-IPv6 parity suite (replay_egress_allowlist_ssrf.test.ts).
function classifyEntry(
  entry: string,
): { reason: string; cidr: string } | null {
  try {
    validateEgressEntries([entry]);
    return null;
  } catch (e) {
    expect(e).toBeInstanceOf(EgressDenied);
    const env = (e as EgressDenied).envelope;
    expect(env.code).toBe(RELAY_REPLAY_SSRF_CODE);
    return { reason: env.denied_reason, cidr: env.denied_cidr };
  }
}

describe("F6: native-IPv6 is_private egress parity with CPython", () => {
  // CPython is_private == True -> network_policy._classify == ("rfc1918",
  // "fc00::/7"). The first four are the FINDING addresses the TS subset
  // previously ALLOWED; the rest are the other private blocks (pin no
  // regression). Captured from CPython 3.14.3 ipaddress.ip_address(a).is_private.
  const PRIVATE_DENY = [
    // 2001::/23 IETF protocol-assignments block (Teredo etc.) -- the gap.
    "2001::1",
    "2001:2::1",
    "2001:10::1",
    // 3fff::/20 documentation block (RFC 9637) -- the gap.
    "3fff::1",
    // NAT64 local-use 64:ff9b:1::/48 (the GLOBAL 64:ff9b::/96 is unwrapped).
    "64:ff9b:1::1",
    // Pre-existing private blocks (must stay denied).
    "::1", // loopback
    "fc00::1", // ULA fc00::/7
    "fdff::1", // ULA fc00::/7 upper half
    "2001:db8::1", // documentation 2001:db8::/32
    "100::1", // discard-only 100::/64
  ] as const;

  for (const host of PRIVATE_DENY) {
    it(`denies private IPv6 ${host} as rfc1918/fc00::/7 (CPython is_private)`, () => {
      expect(classifyEntry(host)).toEqual({
        reason: "rfc1918",
        cidr: "fc00::/7",
      });
    });
  }

  // CPython is_private == False (is_global == True) -> _classify == None
  // (ALLOWED). These are the _private_networks_exceptions: GLOBAL carve-outs
  // INSIDE the 2001::/23 private supernet. TS must NOT over-block them, else a
  // fresh Py<->TS divergence in the OPPOSITE direction (TS deny, CPython allow).
  const GLOBAL_EXCEPTION_ALLOW = [
    "2001:1::1",
    "2001:1::2",
    "2001:3::1", // 2001:3::/32
    "2001:4:112::1", // 2001:4:112::/48
    "2001:20::1", // 2001:20::/28
    "2001:2f:ffff::1", // 2001:20::/28 upper edge
    "2001:30::1", // 2001:30::/28
  ] as const;

  for (const host of GLOBAL_EXCEPTION_ALLOW) {
    it(`allows global carve-out ${host} inside 2001::/23 (CPython is_private False)`, () => {
      expect(classifyEntry(host)).toBeNull();
    });
  }

  // Public global-unicast controls: never denied.
  for (const host of ["2606:4700:4700::1111", "2620:fe::fe"] as const) {
    it(`allows public global-unicast ${host}`, () => {
      expect(classifyEntry(host)).toBeNull();
    });
  }

  // /20 UPPER-boundary: 3fff::/20 covers ONLY 3fff:0000::-3fff:0fff:..., so
  // 3fff:ffff::1 (second hextet 0xffff, top 4 bits 0xf != 0x0) is OUTSIDE the
  // block and CPython is_private is False -> ALLOWED. Pins that the F6 change
  // matched the /20 width exactly and did NOT over-block the rest of 3xxx.
  // (CPython 3.14.3: _classify("3fff:ffff::1") == None.)
  it("allows 3fff:ffff::1 just ABOVE the 3fff::/20 private block (no over-block)", () => {
    expect(classifyEntry("3fff:ffff::1")).toBeNull();
  });

  // The NAT64 well-known GLOBAL prefix 64:ff9b::/96 wraps an embedded IPv4 and
  // is UNWRAPPED + reclassified on the embedded address (CPython is_private is
  // False for the wrapper; _classify unwraps it before the is_private check).
  // 64:ff9b::8.8.8.8 wraps public 8.8.8.8 -> ALLOWED. This pins that the F6
  // change did NOT start blocking the global NAT64 prefix.
  it("allows NAT64 global 64:ff9b::8.8.8.8 (unwrapped to public 8.8.8.8)", () => {
    expect(classifyEntry("64:ff9b::0808:0808")).toBeNull();
  });

  // The DENY verdict must hold through the bracketed host:port and URL host
  // forms too (the egress guard extracts the host before classifying). 2001::1
  // is the finding's canonical regressed address.
  it("denies the finding address through the bracketed [2001::1]:443 form", () => {
    expect(classifyEntry("[2001::1]:443")).toEqual({
      reason: "rfc1918",
      cidr: "fc00::/7",
    });
  });

  it("denies the finding address through the https://[2001::1]/ URL form", () => {
    expect(classifyEntry("https://[2001::1]/path")).toEqual({
      reason: "rfc1918",
      cidr: "fc00::/7",
    });
  });

  // CIDR-OVERLAP path (run.ts _classify "/" branch -> _DENIED_SUPERNETS +
  // exception-aware 2001::/23). A BROAD CIDR whose literal network address is
  // public but whose range CONTAINS a private block was admitted before the
  // _DENIED_SUPERNETS extension -- an SSRF gap and an inconsistency with the
  // single-host deny. A CIDR FULLY CONTAINED in a 2001::/23 global exception
  // (2001:20::/28 etc.) is NOT over-blocked (it is all-global space). Every
  // verdict is the verbatim CPython network_policy._classify output.
  describe("CIDR overlap with the new private blocks", () => {
    const CIDR_CASES: ReadonlyArray<{
      entry: string;
      expected: { reason: string; cidr: string } | null;
      why: string;
    }> = [
      {
        entry: "3fff:ffff::1/16",
        expected: { reason: "rfc1918", cidr: "3fff::/20" },
        why: "the /16 range contains private 3fff::/20 (network addr public)",
      },
      {
        entry: "2001:3::1/31",
        expected: { reason: "rfc1918", cidr: "2001::/23" },
        why: "the /31 straddles private 2001:2::/48 and exception 2001:3::/32 -> denied",
      },
      // Exception-aware: a CIDR fully inside a 2001::/23 global carve-out is
      // ALLOWED (not over-blocked) -- it is all-global space.
      {
        entry: "2001:20::/28",
        expected: null,
        why: "the whole CIDR is the global exception 2001:20::/28 (ORCHIDv2)",
      },
      {
        entry: "2001:3::/32",
        expected: null,
        why: "the whole CIDR is the global exception 2001:3::/32 (AMT)",
      },
      {
        entry: "2001:20::1/128",
        expected: null,
        why: "a /128 inside the global exception 2001:20::/28",
      },
      {
        entry: "2001:20::/27",
        expected: null,
        why: "spans ADJACENT exceptions 2001:20::/28 + 2001:30::/28 (all global, no private gap)",
      },
      {
        entry: "2001:20::/26",
        expected: { reason: "rfc1918", cidr: "2001::/23" },
        why: "broader than the merged exceptions -> reaches private 2001:40:: remainder",
      },
      {
        entry: "2606:4700::/32",
        expected: null,
        why: "a public global-unicast CIDR overlaps no denied supernet",
      },
      {
        entry: "2001:db8::/32",
        expected: { reason: "rfc1918", cidr: "fc00::/7" },
        why: "pre-existing: the 2001:db8:: network address is itself private",
      },
    ];

    for (const c of CIDR_CASES) {
      it(`${c.entry} -> ${c.expected ? c.expected.cidr : "ALLOWED"} (${c.why})`, () => {
        expect(classifyEntry(c.entry)).toEqual(c.expected);
      });
    }
  });
});

// RFC 6874 IPv6 zone identifiers (scoped addresses, ``addr%zone``). CPython
// ``ipaddress.ip_address`` parses ``fe80::1%eth0`` (scope kept as metadata,
// classification uses the address bits) and REJECTS an empty/multi-``%`` zone.
// Found by the egress parity property test: the TS hand-rolled IPv6 parser
// passed the ``%zone`` suffix into hextet splitting -> the trailing group
// ``%eth0`` -> ``parseInt("%eth0",16)`` = NaN -> ``BigInt(NaN)`` RangeError,
// a non-EgressDenied crash where CPython returns a clean verdict (keystone
// #16 / #9 Py<->TS divergence). ``fe80::1%eth0`` survived only by luck
// (``parseInt("1%eth0",16)`` == 1). Verdicts captured from CPython 3.14.3
// ``relay.network_policy._classify`` (via validate_egress_entries).
describe("IPv6 zone identifiers (RFC 6874) parity with CPython", () => {
  // Valid zone (non-empty, single ``%``; Node net.isIP == 6, CPython parses):
  // classify on the address part, scope ignored.
  const VALID_ZONE_DENY = [
    { entry: "::%eth0", reason: "rfc1918", cidr: "fc00::/7" },
    { entry: "[::%eth0]", reason: "rfc1918", cidr: "fc00::/7" },
    { entry: "::1%lo0", reason: "rfc1918", cidr: "fc00::/7" },
    { entry: "fe80::1%eth0", reason: "link_local", cidr: "fe80::/10" },
    { entry: "[fe80::1%eth0]", reason: "link_local", cidr: "fe80::/10" },
    // IPv4-mapped with a zone unwraps to the embedded IPv4 (loopback).
    { entry: "::ffff:127.0.0.1%eth0", reason: "loopback", cidr: "127.0.0.0/8" },
  ] as const;
  for (const c of VALID_ZONE_DENY) {
    it(`denies ${c.entry} as ${c.reason}/${c.cidr} (zone stripped)`, () => {
      expect(classifyEntry(c.entry)).toEqual({ reason: c.reason, cidr: c.cidr });
    });
  }

  // A PUBLIC address with a valid zone stays allowed (scope is not a reason
  // to block a globally-routable host).
  it("allows a public address with a valid zone 2606:4700::%x", () => {
    expect(classifyEntry("2606:4700::%x")).toBeNull();
  });

  // Invalid zone (empty, or contains a second ``%``): Node net.isIP == 0 and
  // CPython ip_address RAISES -> _classify returns None -> ALLOWED. TS must
  // agree (return null), NOT crash.
  for (const entry of ["::%", "fe80::1%", "::%e%t"] as const) {
    it(`allows ${entry} (invalid zone; CPython ip_address rejects -> None)`, () => {
      expect(classifyEntry(entry)).toBeNull();
    });
  }
});
