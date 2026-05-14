/**
 * W4.3 SDK-side redaction -- binary attachment digest tests (VAL-W4-025).
 *
 * Binary attachment fields (Buffer, Uint8Array, ArrayBuffer) MUST be
 * replaced by ``{_digest_sha256: "<hex>"}`` references in the wire body.
 * The raw bytes MUST NOT cross localhost. This guards against bypass via
 * file-upload tool args, OCR pipelines, image attachments, etc.
 *
 * Per CLAUDE.md keystone invariant #7 (default-deny raw capture), the SDK
 * never sends binary plaintext over the localhost transport on the
 * default policy. The hosted ingest re-validates as defense in depth.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";
import { describe, expect, it } from "vitest";

import { loadRedactionPolicy, redactCapturePayload, RedactionEngine } from "../src/redaction.js";
import { RelayRedactionPolicyError } from "../src/index.js";

const POLICY = {
  schema_version: "relay.redaction.v1",
  policy_version: "2026-05-12.001",
  raw_capture: false,
  matchers: [
    {
      id: "api_key",
      kind: "regex",
      pattern: "(sk-|key_)[A-Za-z0-9]{20,}",
      action: "redact",
    },
  ],
  action_policy: {
    hash: { algorithm: "hmac-sha256", salt_ref: "tenant_salt_v3" },
    redact: { placeholder: "<redacted>" },
    drop: { placeholder: null },
  },
};

const TENANT_SALT = new TextEncoder().encode("test-tenant-salt-v3-do-not-use-in-prod");
const saltProvider = (saltRef: string): Uint8Array => {
  if (saltRef === "tenant_salt_v3") return TENANT_SALT;
  throw new Error(`unknown salt_ref: ${saltRef}`);
};

function expectedSha256Hex(bytes: Uint8Array): string {
  return crypto.createHash("sha256").update(Buffer.from(bytes)).digest("hex");
}

// -----------------------------------------------------------------------------
// VAL-W4-025: binary attachments stored as digest-only references.
// -----------------------------------------------------------------------------

describe("VAL-W4-025: binary attachments are stored as digest-only references", () => {
  it("a 10 KB Uint8Array tool_call arg is replaced by a {_digest_sha256: hex} reference", () => {
    const policy = loadRedactionPolicy(POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    const tenKb = new Uint8Array(10 * 1024);
    // Fill with non-zero so the digest is non-trivial.
    for (let i = 0; i < tenKb.length; i++) tenKb[i] = (i * 37) & 0xff;
    const expectedDigest = expectedSha256Hex(tenKb);

    const body = redactCapturePayload(engine, {
      tool_call: {
        args: { file: tenKb },
      },
    });

    // Outbound body MUST be smaller than the raw payload (10 KB) -- the
    // digest reference is only ~80 bytes.
    expect(body.byteLength).toBeLessThan(1024);
    // The digest reference MUST appear in the output.
    const text = Buffer.from(body).toString("utf8");
    expect(text).toContain("_digest_sha256");
    expect(text).toContain(expectedDigest);
  });

  it("a Buffer (subclass of Uint8Array) is also rewritten to a digest reference", () => {
    const policy = loadRedactionPolicy(POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    const buf = Buffer.from("attachment-bytes-some-payload-data", "utf8");
    const expectedDigest = expectedSha256Hex(new Uint8Array(buf));

    const body = redactCapturePayload(engine, {
      retrieval: {
        documents: [{ bytes: buf }],
      },
    });

    const text = Buffer.from(body).toString("utf8");
    expect(text).toContain(expectedDigest);
    // Raw bytes must not appear verbatim.
    expect(text).not.toContain("attachment-bytes-some-payload-data");
  });

  it("an ArrayBuffer is rewritten to a digest reference", () => {
    const policy = loadRedactionPolicy(POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    const ab = new ArrayBuffer(64);
    const view = new Uint8Array(ab);
    for (let i = 0; i < 64; i++) view[i] = i;
    const expectedDigest = expectedSha256Hex(view);

    const body = redactCapturePayload(engine, {
      tool_call: { args: { blob: ab } },
    });

    const text = Buffer.from(body).toString("utf8");
    expect(text).toContain(expectedDigest);
  });

  it("an embedded secret inside a binary buffer cannot leak (digest is opaque)", () => {
    const policy = loadRedactionPolicy(POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    // Embed a literal secret in raw bytes; the digest path means the
    // secret cannot reach the wire.
    const bytes = Buffer.from("secret-payload-with-sk-ABCDEFGHIJKLMNOPQRSTUV-end", "utf8");
    const body = redactCapturePayload(engine, {
      retrieval: { documents: [{ bytes }] },
    });
    const text = Buffer.from(body).toString("utf8");
    expect(text).not.toContain("sk-ABCDEFGHIJKLMNOPQRSTUV");
    expect(text).not.toContain("secret-payload");
    expect(text).toContain("_digest_sha256");
  });

  it("nested arrays of binary attachments each get their own digest reference", () => {
    const policy = loadRedactionPolicy(POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    const a = Buffer.from([1, 2, 3]);
    const b = Buffer.from([4, 5, 6]);
    const c = Buffer.from([7, 8, 9]);
    const body = redactCapturePayload(engine, {
      retrieval: { documents: [{ blobs: [a, b, c] }] },
    });
    const text = Buffer.from(body).toString("utf8");
    const matches = text.match(/_digest_sha256/g) ?? [];
    expect(matches.length).toBe(3);
    expect(text).toContain(expectedSha256Hex(new Uint8Array(a)));
    expect(text).toContain(expectedSha256Hex(new Uint8Array(b)));
    expect(text).toContain(expectedSha256Hex(new Uint8Array(c)));
  });

  it("a Blob payload (async-only read) is refused with a typed error", () => {
    const policy = loadRedactionPolicy(POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    if (typeof Blob === "undefined") {
      // Older Node runtimes; skip.
      return;
    }
    const blob = new Blob(["some bytes"], { type: "application/octet-stream" });
    expect(() =>
      redactCapturePayload(engine, { retrieval: { documents: [{ blob }] } }),
    ).toThrowError(RelayRedactionPolicyError);
  });

  it("the wire body size is dominated by the digest (NOT the binary)", () => {
    const policy = loadRedactionPolicy(POLICY);
    const engine = new RedactionEngine({ policy, saltProvider });
    const huge = new Uint8Array(64 * 1024); // 64 KB
    crypto.randomFillSync(huge);
    const body = redactCapturePayload(engine, {
      tool_call: { args: { file: huge } },
    });
    // The redacted body MUST be at least an order of magnitude smaller
    // than the input bytes (proves no buffer slipped through).
    expect(body.byteLength).toBeLessThan(huge.byteLength / 100);
  });
});
