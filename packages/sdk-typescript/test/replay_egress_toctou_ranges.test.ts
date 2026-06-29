/**
 * Follow-on hardening for the SDK-boundary SSRF egress guard on
 * Run.replayCreate (roborev HIGH+MED on run.ts ~1104 / ~356).
 *
 * Two gaps in the round-2 #11 egress screen are closed here:
 *
 *   (HIGH TOCTOU) The egress allowlist was validated BY REFERENCE and then
 *   the SAME array object was reused to build the POST body AFTER the awaited
 *   getRunResult() preflight. A caller (or a concurrent mutator) could append
 *   an internal entry between validation and POST, sending an UNVALIDATED host
 *   to the sidecar. The fix snapshots the array BEFORE validation and sends
 *   ONLY that copy; a mutation of the passed array after the call begins must
 *   NOT reach the wire.
 *
 *   (MED range completeness) The hand-coded IPv4/IPv6 classifier missed the
 *   non-global / documentation / benchmarking ranges Python's stdlib rejects.
 *   The Python SDK
 *   (packages/sdk-python/relay/network_policy.py::_classify) is authoritative:
 *   it routes every address through ipaddress.ip_address(...).is_private /
 *   is_reserved. These tests pin the TS verdict AND envelope bytes to that
 *   reference for the previously-missed ranges:
 *
 *     192.0.2.0/24   (TEST-NET-1)     -> rfc1918 / private
 *     198.51.100.0/24 (TEST-NET-2)    -> rfc1918 / private
 *     203.0.113.0/24 (TEST-NET-3)     -> rfc1918 / private
 *     240.0.0.0/4    (future use)     -> rfc1918 / private
 *     192.0.0.0/24   (IETF protocol)  -> rfc1918 / private
 *     198.18.0.0/15  (benchmarking)   -> rfc1918 / private
 *     255.255.255.255 (broadcast)     -> rfc1918 / private
 *     2001:db8::/32  (doc, IPv6)      -> rfc1918 / fc00::/7
 *     ::             (unspecified)    -> rfc1918 / fc00::/7
 *
 *   Note: the named reference is authoritative. 100.64.0.0/10 (CGNAT) is
 *   is_private == False AND is_reserved == False on CPython 3.12 / 3.13 /
 *   3.14, so Python ALLOWS it -- the TS classifier must ALLOW it too (parity),
 *   even though the task brief assumed otherwise.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { describe, expect, it } from "vitest";

import {
  EgressDenied,
  RELAY_REPLAY_SSRF_CODE,
  Run,
  validateEgressEntries,
  type RunHttpClient,
} from "../src/run.js";

const VALID_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor";
const VALID_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife";
const VALID_AGENT = { name: "ops-agent", version: "0.1.0" };

class StubHttpClient implements RunHttpClient {
  postReplayCalls: Array<{ caseId: string; body: Record<string, unknown> }> = [];
  getRunResultCalls = 0;
  /** Optional side effect invoked during the getRunResult preflight (TOCTOU). */
  onGetRunResult: (() => void) | null = null;
  postIngestRun = async () => ({ accepted: true });
  postGateDraft = async () => ({ decision_id: "dec-001" });
  getGateDecision = async () => ({ decision: "accepted" });
  getRunResult = async () => {
    this.getRunResultCalls += 1;
    if (this.onGetRunResult !== null) {
      this.onGetRunResult();
    }
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

describe("egress range completeness: TS classifier matches Python _classify for non-global ranges", () => {
  // [entry, denied_reason, denied_cidr] -- authoritative Python output on
  // CPython 3.12 / 3.13 / 3.14 (ipaddress.is_private precedes is_reserved, so
  // every one of these reserved/documentation/benchmarking blocks tags as
  // rfc1918 / private; the IPv6 doc + unspecified blocks tag fc00::/7).
  it.each([
    ["192.0.2.1", "rfc1918", "private"], //     TEST-NET-1
    ["198.51.100.1", "rfc1918", "private"], //  TEST-NET-2
    ["203.0.113.1", "rfc1918", "private"], //   TEST-NET-3
    ["240.0.0.1", "rfc1918", "private"], //     240.0.0.0/4 future use
    ["192.0.0.1", "rfc1918", "private"], //     192.0.0.0/24 IETF protocol
    ["198.18.0.1", "rfc1918", "private"], //    198.18.0.0/15 benchmarking
    ["198.19.255.255", "rfc1918", "private"], //198.18.0.0/15 benchmarking top
    ["255.255.255.255", "rfc1918", "private"], //limited broadcast
    ["2001:db8::1", "rfc1918", "fc00::/7"], //  IPv6 documentation 2001:db8::/32
    ["2001:db8:dead:beef::1", "rfc1918", "fc00::/7"], // doc, deep
    ["::", "rfc1918", "fc00::/7"], //           IPv6 unspecified (is_private)
  ])(
    "denies %s as %s / %s (parity with Python _classify)",
    async (entry, reason, cidr) => {
      const stub = new StubHttpClient();
      const run = makeRun(stub);
      let raised: unknown;
      try {
        await run.replayCreate({ caseId: "case-001", egressAllowlist: [entry] });
      } catch (e) {
        raised = e;
      }
      expect(raised).toBeInstanceOf(EgressDenied);
      const env = (raised as EgressDenied).envelope;
      expect(env.code).toBe(RELAY_REPLAY_SSRF_CODE);
      expect(env.http_status).toBe(400);
      expect(env.denied_entry).toBe(entry);
      expect(env.denied_reason).toBe(reason);
      expect(env.denied_cidr).toBe(cidr);
      // No outbound replay POST when denied.
      expect(stub.getRunResultCalls).toBe(0);
      expect(stub.postReplayCalls.length).toBe(0);
      await run.close();
    },
  );

  // CGNAT 100.64.0.0/10 is is_private == False AND is_reserved == False on
  // CPython 3.12/3.13/3.14 -- Python ALLOWS it, so the TS classifier must too.
  it.each([["100.64.0.1"], ["100.127.255.255"]])(
    "ALLOWS CGNAT %s (parity: Python is_private/is_reserved both False)",
    async (entry) => {
      const stub = new StubHttpClient();
      const run = makeRun(stub);
      const result = await run.replayCreate({
        caseId: "case-001",
        egressAllowlist: [entry],
      });
      expect(stub.postReplayCalls.length).toBe(1);
      expect(stub.postReplayCalls[0]?.body["egress_allowlist"]).toEqual([entry]);
      expect(result["mode"]).toBe("cassette");
      await run.close();
    },
  );

  // The unit-level classifier surface must agree too (validateEgressEntries is
  // the shared chokepoint both the SDK and any direct caller use).
  it("validateEgressEntries denies the TEST-NET / benchmarking ranges directly", () => {
    for (const entry of [
      "192.0.2.7",
      "198.51.100.7",
      "203.0.113.7",
      "240.10.20.30",
      "198.18.5.5",
    ]) {
      let raised: unknown;
      try {
        validateEgressEntries([entry]);
      } catch (e) {
        raised = e;
      }
      expect(raised, `expected ${entry} to be denied`).toBeInstanceOf(EgressDenied);
      expect((raised as EgressDenied).envelope.denied_reason).toBe("rfc1918");
      expect((raised as EgressDenied).envelope.denied_cidr).toBe("private");
    }
  });

  it("validateEgressEntries ALLOWS CGNAT and public addresses (parity)", () => {
    // No throw == allowed.
    expect(() => validateEgressEntries(["100.64.0.1", "8.8.8.8", "1.1.1.1"])).not.toThrow();
  });
});

describe("egress TOCTOU: the allowlist is snapshotted before validation and only the snapshot is sent", () => {
  it("a mutation of the passed array during the preflight does NOT reach the wire", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    // Caller-controlled array. Validation must operate on a snapshot taken
    // BEFORE the awaited getRunResult preflight, and the POST body must carry
    // ONLY that snapshot -- never a later-injected internal host.
    const allowlist = ["api.openai.com", "https://api.anthropic.com/v1"];
    stub.onGetRunResult = () => {
      // Inject an internal RFC1918 host AFTER validation has already run.
      // With a by-reference build this would be sent UNVALIDATED.
      allowlist.push("169.254.169.254");
      allowlist.push("10.0.0.1");
    };
    const result = await run.replayCreate({
      caseId: "case-001",
      egressAllowlist: allowlist,
    });
    expect(stub.postReplayCalls.length).toBe(1);
    const sent = stub.postReplayCalls[0]?.body["egress_allowlist"] as string[];
    expect(sent).toEqual(["api.openai.com", "https://api.anthropic.com/v1"]);
    expect(sent).not.toContain("169.254.169.254");
    expect(sent).not.toContain("10.0.0.1");
    expect(result["mode"]).toBe("cassette");
    await run.close();
  });

  it("validation operates on the snapshot, so a denied entry present at call time is still caught", async () => {
    const stub = new StubHttpClient();
    const run = makeRun(stub);
    const allowlist = ["api.openai.com", "192.168.1.1"];
    let raised: unknown;
    try {
      await run.replayCreate({ caseId: "case-001", egressAllowlist: allowlist });
    } catch (e) {
      raised = e;
    }
    expect(raised).toBeInstanceOf(EgressDenied);
    expect((raised as EgressDenied).envelope.denied_entry).toBe("192.168.1.1");
    // Mutating the original array afterwards must not retroactively change the
    // already-computed rejection envelope.
    allowlist.length = 0;
    expect((raised as EgressDenied).envelope.denied_entry).toBe("192.168.1.1");
    expect(stub.getRunResultCalls).toBe(0);
    expect(stub.postReplayCalls.length).toBe(0);
    await run.close();
  });
});
