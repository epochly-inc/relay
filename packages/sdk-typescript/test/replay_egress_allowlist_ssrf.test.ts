/**
 * SDK-boundary SSRF guard on Run.replayCreate egress allowlist (LOW #11).
 *
 * Parity with the Python SDK
 * (packages/sdk-python/relay/run.py::Run.replay_create +
 * packages/sdk-python/relay/network_policy.py::validate_egress_entries,
 * exercised by packages/sdk-python/tests/test_audit_r3_ssrf.py).
 *
 * The Python SDK accepts an ``egress_allowlist`` on replay-case creation
 * and raises ``EgressDenied`` at the SDK boundary BEFORE any HTTP I/O when
 * an entry resolves into an RFC 1918 / link-local / loopback / multicast /
 * reserved / cloud-metadata range or a reserved-hostname denylist entry.
 * The rejection carries a structured envelope:
 *
 *   code         == "RELAY-REPLAY-SSRF"
 *   http_status  == 400
 *   denied_entry == the verbatim caller-supplied entry
 *   denied_reason in {rfc1918, link_local, loopback, multicast, reserved,
 *                     cloud_metadata, reserved_hostname}
 *   denied_cidr  == the matching CIDR / endpoint / suffix
 *
 * Before this fix the TS Run.replayCreate exposed NO egress allowlist and
 * NO SSRF screen -- dropping that defense-in-depth on the TS side. These
 * tests pin the mirrored behaviour: same denied-host semantics, same error
 * surface, same envelope shape, and NO outbound replay POST when denied.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import {
  EgressDenied,
  RELAY_REPLAY_SSRF_CODE,
  Run,
  type RunHttpClient,
  validateEgressEntries,
} from "../src/run.js";

const VALID_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor";
const VALID_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife";
const VALID_AGENT = { name: "ops-agent", version: "0.1.0" };

class StubHttpClient implements RunHttpClient {
  postReplayCalls: Array<{ caseId: string; body: Record<string, unknown> }> = [];
  getRunResultCalls = 0;
  postIngestRun = async () => ({ accepted: true });
  postGateDraft = async () => ({ decision_id: "dec-001" });
  getGateDecision = async () => ({ decision: "accepted" });
  getRunResult = async () => {
    this.getRunResultCalls += 1;
    return { run_result_id: "rr-001", run_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV" };
  };
  postEvidence = async () => ({ stored: true });
  postReplayCaseRun = async (caseId: string, body: Record<string, unknown>) => {
    this.postReplayCalls.push({ caseId, body });
    return { replayed: true, mode: body["mode"] };
  };
}

function makeRun(stub: RunHttpClient): Run {
  return new Run({
    agent: VALID_AGENT,
    actorIdentityHash: VALID_ACTOR,
    manifestCommitHash: VALID_MANIFEST,
    redactionPolicyVersion: "v1",
    flushPolicy: { mode: "sync", onError: "raise" },
    httpClient: stub,
  });
}

describe("LOW #11: Run.replayCreate enforces the egress allowlist SSRF guard", () => {
  it("rejects a loopback (127.0.0.1) allowlist entry BEFORE any HTTP I/O", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", egressAllowlist: ["127.0.0.1"] });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    const env = (raised as EgressDenied).envelope;
    expect(env.code).toBe(RELAY_REPLAY_SSRF_CODE);
    expect(env.http_status).toBe(400);
    expect(env.denied_entry).toBe("127.0.0.1");
    expect(env.denied_reason).toBe("loopback");
    // No HTTP I/O happened: the guard runs before the preflight + POST.
    expect(stub.getRunResultCalls).toBe(0);
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  it("rejects an RFC 1918 entry with reason rfc1918", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", egressAllowlist: ["10.0.0.5:8080"] });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_reason).toBe("rfc1918");
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  it("rejects the cloud-metadata endpoint (169.254.169.254) with reason cloud_metadata", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({
        caseId: "case-001",
        egressAllowlist: ["http://169.254.169.254/latest/meta-data"],
      });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_reason).toBe("cloud_metadata");
    expect((raised as EgressDenied).envelope.denied_entry).toBe(
      "http://169.254.169.254/latest/meta-data",
    );
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  it("rejects the localhost reserved-hostname entry with reason reserved_hostname", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({
        caseId: "case-001",
        egressAllowlist: ["http://localhost:8080"],
      });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_reason).toBe("reserved_hostname");
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  it("rejects a link-local entry (169.254.x.x non-metadata) with reason link_local", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", egressAllowlist: ["169.254.1.1"] });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_reason).toBe("link_local");
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  it("rejects the metadata.google.internal reserved-hostname entry", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({
        caseId: "case-001",
        egressAllowlist: ["metadata.google.internal"],
      });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_reason).toBe("reserved_hostname");
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  it("rejects a numeric-form loopback (2130706433 == 127.0.0.1) the libc resolver accepts", async () => {
    // Parity with network_policy._canonical_numeric_ipv4: a numeric IPv4
    // encoding the OS resolver dials must not bypass the SSRF screen.
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", egressAllowlist: ["2130706433"] });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_reason).toBe("loopback");
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  // Round-2 #11 regression: multi-part inet_aton forms with octal/hex octets
  // and NAT64-wrapped IPv4 must NOT escape the screen (they did before the
  // _canonicalNumericIpv4 5-n fix + the NAT64 /96-prefix fix).
  it.each([
    ["0177.0.0.1", "loopback"], // octal first octet -> 127.0.0.1
    ["0x7f.0.0.1", "loopback"], // hex first octet -> 127.0.0.1
    ["0xa.0.0.1", "rfc1918"], //   hex first octet -> 10.0.0.1
  ])("blocks octal/hex inet_aton loopback/private form %s (%s)", async (host, reason) => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", egressAllowlist: [host] });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_reason).toBe(reason);
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  // Round-6 re-hunt: a 1-part numeric IPv4 literal whose value exceeds
  // 0xffffffff is MASKED to its low 32 bits by inet_aton / getaddrinfo (the
  // resolver the replay client uses), e.g. 7147006462 -> 169.254.169.254 and
  // 0x17f000001 -> 127.0.0.1. The guard previously REJECTED the overflow form
  // (returned null -> treated as non-IP -> ALLOWED) while Python (inet_aton)
  // masks + denies -- a Py<->TS verdict split + SSRF under-block. The masked
  // internal/metadata IP must be DENIED.
  it.each([
    ["7147006462", "cloud_metadata"], //  -> 169.254.169.254
    ["0x17f000001", "loopback"], //        -> 127.0.0.1
  ])("blocks an overflow 1-part numeric IPv4 that masks to internal %s (%s)", async (host, reason) => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", egressAllowlist: [host] });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_reason).toBe(reason);
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  it("allows an overflow 1-part numeric IPv4 that masks to a PUBLIC IP (4429711368 -> 8.8.8.8)", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    const result = await run.replayCreate({
      caseId: "case-001",
      egressAllowlist: ["4429711368"], // & 0xffffffff == 8.8.8.8
    });
    expect(stub.postReplayCalls.length).toBe(1);
    expect(result["mode"]).toBe("cassette");
    await run.close();
  });

  // CIDR-block allowlist entries over an internal network are denied (parity
  // with Python network_policy._classify CIDR branch); a public-network CIDR
  // is allowed.
  it.each([
    "10.0.0.0/8",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "fc00::/7",
    // Broad supernets with a public-looking network address that CONTAIN
    // internal ranges (overlap, not just the network address).
    "0.0.0.0/0",
    "8.8.8.8/0",
    "8.8.8.0/1",
    "8.0.0.0/6",
    "64.0.0.0/2",
  ])(
    "blocks an internal CIDR-block allowlist entry %s",
    async (cidr) => {
      const stub = new StubHttpClient();
      const run = makeRun(stub);
      let raised: unknown;
      try {
        await run.replayCreate({ caseId: "case-001", egressAllowlist: [cidr] });
      } catch (e) {
        raised = e;
      }
      expect(raised).toBeInstanceOf(EgressDenied);
      expect(stub.postReplayCalls.length).toBe(0);
      await run.close();
    },
  );

  it("allows a public-network CIDR allowlist entry (8.8.8.0/24)", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    const result = await run.replayCreate({
      caseId: "case-001",
      egressAllowlist: ["8.8.8.0/24"],
    });
    expect(stub.postReplayCalls.length).toBe(1);
    expect(result["mode"]).toBe("cassette");
    await run.close();
  });

  // A BROAD CIDR over an IPv4-in-IPv6 transition prefix (IPv4-mapped
  // ::ffff:0:0/96, 6to4 2002::/16, NAT64 64:ff9b::/96) has a public-looking
  // IPv6 network address while spanning denied embedded IPv4 ranges. Without
  // the transition supernets in _DENIED_SUPERNETS the overlap check passes
  // them (SSRF default-deny bypass). Byte-for-byte parity with the Python
  // test_ipv4_in_ipv6_transition_cidr_blocks_are_denied.
  it.each([
    "::ffff:0:0/96", //        entire IPv4-mapped space
    "::ffff:800:0/102", //     ::ffff:8.0.0.0/X sub-block (public-looking network)
    "2002::/16", //            entire 6to4 space
    "2002:800::/22", //        6to4 sub-block
    "64:ff9b::/96", //         entire NAT64 space
    "64:ff9b::800:0/102", //   NAT64 sub-block
    "::/96", //                entire deprecated IPv4-compatible space
    "::800:0/102", //          IPv4-compatible: public-looking net, spans ::a00:0 (10.0.0.0)
    "::a00:0/104", //          IPv4-compatible wrapping 10.0.0.0/8
  ])("blocks an IPv4-in-IPv6 transition CIDR-block entry %s", async (cidr) => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", egressAllowlist: [cidr] });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  // Round-7 re-hunt: the denied_cidr envelope byte for an IPv4-mapped overlap
  // entry MUST equal Python's str(ip_network("::ffff:0:0/96")) == the DOTTED
  // "::ffff:0.0.0.0/96" (CPython renders the IPv4-mapped /96 dotted). The
  // EgressDenied envelope is a declared byte-identical Py<->TS contract.
  it("reports denied_cidr in Python's dotted IPv4-mapped form (::ffff:0.0.0.0/96)", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", egressAllowlist: ["::ffff:800:0/102"] });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_cidr).toBe("::ffff:0.0.0.0/96");
    await run.close();
  });

  // A SINGLE transition address unwraps + classifies on its embedded IPv4: an
  // internal embedded IPv4 is denied, a PUBLIC embedded IPv4 stays allowed (no
  // over-block). Parity with Python test_single_transition_addresses_*.
  it.each(["::ffff:10.0.0.1", "2002:a00:1::", "64:ff9b::a00:1"])(
    "blocks a single transition address wrapping an internal IPv4 (%s)",
    async (host) => {
      const stub = new StubHttpClient();
      const run = makeRun(stub);
      let raised: unknown;
      try {
        await run.replayCreate({ caseId: "case-001", egressAllowlist: [host] });
      } catch (e) {
        raised = e;
      }
      expect(raised).toBeInstanceOf(EgressDenied);
      expect((raised as EgressDenied).envelope.denied_reason).toBe("rfc1918");
      expect(stub.postReplayCalls.length).toBe(0);
      await run.close();
    },
  );

  it("allows a single transition address wrapping a PUBLIC IPv4 (::ffff:8.8.8.8)", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    const result = await run.replayCreate({
      caseId: "case-001",
      egressAllowlist: ["::ffff:8.8.8.8"],
    });
    expect(stub.postReplayCalls.length).toBe(1);
    expect(result["mode"]).toBe("cassette");
    await run.close();
  });

  // Round-5 re-hunt: URL-form host extraction MUST match Python urlparse(),
  // NOT the WHATWG `new URL()` parser. WHATWG treats `\` as a path delimiter and
  // throws on an embedded space, so it extracted a DIFFERENT host than urlparse
  // for these forms -- a Py<->TS verdict split and a default-deny SSRF
  // under-block (TS allowed an entry whose real host urlparse/the HTTP client
  // dials as internal). After the urlparse-port fix both SDKs agree.
  it.each([
    "http://evil.com\\@10.0.0.1/", // urlparse host = 10.0.0.1 (userinfo split at last @)
    "http://10.0.0.1 /", // urlparse host = "10.0.0.1 " -> _classify strips -> 10.0.0.1
    "http://10.0.0\t.1/", // CPython urlparse strips the embedded \t -> 10.0.0.1
  ])(
    "denies a URL whose urlparse host is internal even when WHATWG sees a public host (%s)",
    async (entry) => {
      const stub = new StubHttpClient();
      const run = makeRun(stub);
      let raised: unknown;
      try {
        await run.replayCreate({ caseId: "case-001", egressAllowlist: [entry] });
      } catch (e) {
        raised = e;
      }
      expect(raised).toBeInstanceOf(EgressDenied);
      expect((raised as EgressDenied).envelope.denied_reason).toBe("rfc1918");
      expect(stub.postReplayCalls.length).toBe(0);
      await run.close();
    },
  );

  it("allows a URL whose urlparse host is public even when WHATWG sees an internal host (parity with Python)", async () => {
    // http://10.0.0.1\@evil.com/ -> urlparse host = evil.com (public). Python
    // ALLOWS it; the old WHATWG extractor saw 10.0.0.1 and DENIED -- a parity
    // break in the opposite direction. The fix makes TS allow it like Python.
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    const result = await run.replayCreate({
      caseId: "case-001",
      egressAllowlist: ["http://10.0.0.1\\@evil.com/"],
    });
    expect(stub.postReplayCalls.length).toBe(1);
    expect(result["mode"]).toBe("cassette");
    await run.close();
  });

  it("blocks a NAT64-wrapped loopback (64:ff9b::7f00:1 == 127.0.0.1)", async () => {
    // 64:ff9b::/96 carries the embedded IPv4 in the low 32 bits; the wrapper
    // must unwrap+re-classify exactly like Python `ip in _NAT64_NETWORK`.
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", egressAllowlist: ["64:ff9b::7f00:1"] });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_reason).toBe("loopback");
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  it("the first rejected entry short-circuits a mixed allowlist", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    let raised: unknown;
    try {
      await run.replayCreate({
        caseId: "case-001",
        egressAllowlist: ["api.openai.com", "192.168.1.1", "example.com"],
      });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_entry).toBe("192.168.1.1");
    expect((raised as EgressDenied).envelope.denied_reason).toBe("rfc1918");
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });

  it("a clean public allowlist passes through and lands on the replay body", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    const allowlist = ["api.openai.com", "https://api.anthropic.com/v1", "8.8.8.8"];
    const result = await run.replayCreate({
      caseId: "case-001",
      egressAllowlist: allowlist,
    });
    expect(stub.postReplayCalls.length).toBe(1);
    expect(stub.postReplayCalls[0]?.body["egress_allowlist"]).toEqual(allowlist);
    expect(result["mode"]).toBe("cassette");
    await run.close();
  });

  it("an absent allowlist is a no-op (no egress_allowlist key forced empty)", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    const result = await run.replayCreate({ caseId: "case-001" });
    expect(stub.postReplayCalls.length).toBe(1);
    expect(result["mode"]).toBe("cassette");
    await run.close();
  });
});

// ---------------------------------------------------------------------------
// Native reserved-IPv6 SSRF parity (round-N re-hunt).
//
// Python network_policy._classify denies a NATIVE reserved IPv6 address via
// ``ipaddress.is_reserved`` -> ("reserved", "ipv6_reserved"). The TS
// _classifyIpv6 mirrored every other native-special branch (link-local,
// is_private, multicast, the ::/96 IPv4-compatible unwrap) but was MISSING
// the final is_reserved branch, so a reserved address like 4000::1 fell
// through to ALLOW -- a Py<->TS verdict divergence and an SSRF defense gap
// (the TS replay allowlist accepted a host the Python SDK rejects).
//
// CPython runs is_private BEFORE is_reserved, so the 100::/64 "discard-only"
// private carve-out INSIDE reserved 100::/8 tags rfc1918/fc00::/7, while the
// rest of 100::/8 tags reserved. These cases pin both the verdict AND the
// (denied_reason, denied_cidr) bytes against the cel-python reference
// (packages/sdk-python/relay/network_policy.py::_classify).
//
// Reference verdicts captured from cel-python:
//   4000::1 8000::1 c000::1 e000::1 f800::1 fe00::1 1000::abcd 200::1
//   400::1 800::1 100:0:0:1::1 101::1 1ff::1  -> ("reserved","ipv6_reserved")
//   100::1 100::ffff:ffff:ffff:ffff           -> ("rfc1918","fc00::/7")
//   2000::1                                    -> None (global unicast ALLOW)
// ---------------------------------------------------------------------------
describe("validateEgressEntries native reserved-IPv6 parity", () => {
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

  const RESERVED_DENY = [
    "4000::1",
    "8000::1",
    "c000::1",
    "e000::1",
    "f800::1",
    "fe00::1",
    "1000::abcd",
    "200::1",
    "400::1",
    "800::1",
    "100:0:0:1::1",
    "101::1",
    "1ff::1",
  ] as const;

  for (const host of RESERVED_DENY) {
    it(`denies native reserved IPv6 ${host} as reserved/ipv6_reserved`, () => {
      expect(classifyEntry(host)).toEqual({
        reason: "reserved",
        cidr: "ipv6_reserved",
      });
    });
  }

  // Bracketed host:port form must reach the same verdict (mirrors fe80:: ).
  it("denies a bracketed [4000::1]:443 allowlist entry as reserved", () => {
    expect(classifyEntry("[4000::1]:443")).toEqual({
      reason: "reserved",
      cidr: "ipv6_reserved",
    });
  });

  // 100::/64 is the is_private discard-only carve-out INSIDE reserved
  // 100::/8; CPython is_private precedence tags it rfc1918/fc00::/7, NOT
  // reserved.
  for (const host of ["100::1", "100::ffff:ffff:ffff:ffff"] as const) {
    it(`tags the 100::/64 private carve-out ${host} as rfc1918 (is_private precedence)`, () => {
      expect(classifyEntry(host)).toEqual({
        reason: "rfc1918",
        cidr: "fc00::/7",
      });
    });
  }

  // Control: 2000::/3 global unicast stays ALLOWED (is_reserved == False).
  it("allows global-unicast 2000::1 (not reserved)", () => {
    expect(classifyEntry("2000::1")).toBeNull();
  });
});
