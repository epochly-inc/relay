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
