/**
 * W4.1 sidecar locator + /health handshake tests.
 *
 *   VAL-W4-002: new Relay(...) resolves the sidecar at
 *               ${RELAY_HOME:-os.homedir()/.relay}/sidecar.lock only.
 *   VAL-W4-003: SDK construction performs /health bearer-digest handshake
 *               before first request.
 *
 * Tier-1 plumbing. Uses an in-process loopback HTTP server as a mock
 * sidecar; tests never touch ~/.relay.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import type { AddressInfo } from "node:net";

import { Relay } from "../src/client.js";
import {
  RelayConfigError,
  RelaySidecarAuthError,
  RelaySidecarLocatorError,
  RelaySidecarVersionMismatch,
} from "../src/errors.js";
import { readLockfile, relayHome, resolveLockfilePath } from "../src/lockfile.js";

interface MockSidecarHandle {
  port: number;
  digest: string;
  observedHeaders: ReadonlyArray<http.IncomingHttpHeaders>;
  close: () => Promise<void>;
}

async function startMockSidecar(
  options: {
    version?: string;
    rejectHandshake?: boolean;
    omitVersion?: boolean;
  } = {},
): Promise<MockSidecarHandle> {
  const token = crypto.randomBytes(16).toString("hex");
  const digest = `sha256-${crypto
    .createHash("sha256")
    .update(token, "utf8")
    .digest("hex")}`;
  const observed: http.IncomingHttpHeaders[] = [];
  const server = http.createServer((req, res) => {
    observed.push(req.headers);
    if (req.url !== "/health") {
      res.statusCode = 404;
      res.end();
      return;
    }
    if (options.rejectHandshake) {
      res.statusCode = 401;
      res.end();
      return;
    }
    const got = req.headers["x-relay-bearer-digest"];
    if (got !== digest) {
      res.statusCode = 401;
      res.end();
      return;
    }
    res.setHeader("content-type", "application/json");
    const body: Record<string, unknown> = {};
    if (!options.omitVersion) {
      body["sidecar_version"] = options.version ?? "0.0.0";
    }
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    digest,
    observedHeaders: observed,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

function writeLockfile(
  home: string,
  port: number,
  digest: string,
  version = "0.0.0",
): void {
  fs.mkdirSync(home, { recursive: true });
  const body = JSON.stringify({
    pid: process.pid,
    port,
    launched_at: new Date().toISOString(),
    launched_by: "test",
    sidecar_version: version,
    bearer_token_digest: digest,
  });
  fs.writeFileSync(path.join(home, "sidecar.lock"), body);
}

describe("VAL-W4-002: Relay sidecar locator", () => {
  let tmpHome: string;
  let priorRelayHome: string | undefined;
  let priorSidecarUrl: string | undefined;
  let priorAllowExplicit: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "relay-w42-"));
    priorRelayHome = process.env["RELAY_HOME"];
    priorSidecarUrl = process.env["RELAY_SIDECAR_URL"];
    priorAllowExplicit = process.env["RELAY_ALLOW_EXPLICIT_SIDECAR"];
    delete process.env["RELAY_SIDECAR_URL"];
    delete process.env["RELAY_ALLOW_EXPLICIT_SIDECAR"];
  });
  afterEach(() => {
    if (priorRelayHome !== undefined) process.env["RELAY_HOME"] = priorRelayHome;
    else delete process.env["RELAY_HOME"];
    if (priorSidecarUrl !== undefined) process.env["RELAY_SIDECAR_URL"] = priorSidecarUrl;
    else delete process.env["RELAY_SIDECAR_URL"];
    if (priorAllowExplicit !== undefined)
      process.env["RELAY_ALLOW_EXPLICIT_SIDECAR"] = priorAllowExplicit;
    else delete process.env["RELAY_ALLOW_EXPLICIT_SIDECAR"];
    try {
      fs.rmSync(tmpHome, { recursive: true, force: true });
    } catch {
      // best effort
    }
  });

  it("relayHome() honors $RELAY_HOME when set", () => {
    process.env["RELAY_HOME"] = "/some/explicit/path";
    expect(relayHome()).toBe("/some/explicit/path");
  });

  it("relayHome() falls back to ~/.relay when env unset", () => {
    delete process.env["RELAY_HOME"];
    expect(relayHome()).toBe(path.join(os.homedir(), ".relay"));
  });

  it("resolveLockfilePath() composes home + 'sidecar.lock' and nothing else", () => {
    expect(resolveLockfilePath("/x")).toBe(path.join("/x", "sidecar.lock"));
  });

  it("readLockfile rejects missing file with RelaySidecarLocatorError", () => {
    expect(() => readLockfile(tmpHome)).toThrowError(RelaySidecarLocatorError);
  });

  it("readLockfile rejects malformed JSON with RelaySidecarLocatorError", () => {
    fs.mkdirSync(tmpHome, { recursive: true });
    fs.writeFileSync(path.join(tmpHome, "sidecar.lock"), "{not json");
    expect(() => readLockfile(tmpHome)).toThrowError(RelaySidecarLocatorError);
  });

  it("readLockfile rejects lockfile with missing required fields", () => {
    fs.mkdirSync(tmpHome, { recursive: true });
    fs.writeFileSync(path.join(tmpHome, "sidecar.lock"), JSON.stringify({ pid: 1 }));
    expect(() => readLockfile(tmpHome)).toThrowError(RelaySidecarLocatorError);
  });

  it("readLockfile rejects bearer_token_digest that is not sha256-<64hex>", () => {
    writeLockfile(tmpHome, 1234, "sha256-notenoughhex");
    expect(() => readLockfile(tmpHome)).toThrowError(RelaySidecarLocatorError);
  });

  it("readLockfile accepts a well-formed lockfile body", () => {
    const digest = `sha256-${"a".repeat(64)}`;
    writeLockfile(tmpHome, 1234, digest);
    const body = readLockfile(tmpHome);
    expect(body.port).toBe(1234);
    expect(body.bearer_token_digest).toBe(digest);
  });

  it("Relay refuses construction when RELAY_SIDECAR_URL is set without the escape hatch", () => {
    process.env["RELAY_SIDECAR_URL"] = "http://127.0.0.1:9999";
    const ulid = "01HABCDEFGHJKMNPQRSTVWXYZ0";
    expect(() => new Relay(ulid, { relayHome: tmpHome })).toThrowError(RelayConfigError);
  });

  it("Relay tolerates RELAY_SIDECAR_URL when RELAY_ALLOW_EXPLICIT_SIDECAR=1", () => {
    process.env["RELAY_SIDECAR_URL"] = "http://127.0.0.1:9999";
    process.env["RELAY_ALLOW_EXPLICIT_SIDECAR"] = "1";
    const ulid = "01HABCDEFGHJKMNPQRSTVWXYZ0";
    expect(() => new Relay(ulid, { relayHome: tmpHome })).not.toThrow();
  });

  it("Relay rejects invalid project keys synchronously", () => {
    expect(() => new Relay(undefined as unknown as string)).toThrowError(RelayConfigError);
    expect(() => new Relay("")).toThrowError(RelayConfigError);
    expect(() => new Relay("not-a-ulid-or-token")).toThrowError(RelayConfigError);
  });
});

describe("VAL-W4-003: SDK construction performs /health bearer-digest handshake before first request", () => {
  let tmpHome: string;
  let priorRelayHome: string | undefined;
  let sidecar: MockSidecarHandle | null = null;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "relay-w43-"));
    priorRelayHome = process.env["RELAY_HOME"];
    delete process.env["RELAY_HOME"];
  });
  afterEach(async () => {
    if (sidecar) await sidecar.close();
    sidecar = null;
    if (priorRelayHome !== undefined) process.env["RELAY_HOME"] = priorRelayHome;
    else delete process.env["RELAY_HOME"];
    try {
      fs.rmSync(tmpHome, { recursive: true, force: true });
    } catch {
      // best effort
    }
  });

  it("trace() performs the /health handshake and returns a live trace handle", async () => {
    sidecar = await startMockSidecar();
    writeLockfile(tmpHome, sidecar.port, sidecar.digest);
    const ulid = "01HABCDEFGHJKMNPQRSTVWXYZ0";
    const client = new Relay(ulid, { relayHome: tmpHome });
    const handle = await client.trace("test-trace");
    expect(handle.name).toBe("test-trace");
    expect(handle.port).toBe(sidecar.port);
    expect(handle.bearerTokenDigest).toBe(sidecar.digest);
    expect(handle.authHeader).toBe(sidecar.digest);
    expect(handle.spawned).toBe(false);
    // VAL-W4-003: at least one /health request was made with the
    // X-Relay-Bearer-Digest header set to the lockfile digest.
    expect(sidecar.observedHeaders.length).toBeGreaterThanOrEqual(1);
    expect(sidecar.observedHeaders[0]?.["x-relay-bearer-digest"]).toBe(sidecar.digest);
    client.close();
  });

  it("construction does not call /health (handshake is lazy on first operation)", async () => {
    sidecar = await startMockSidecar();
    writeLockfile(tmpHome, sidecar.port, sidecar.digest);
    const ulid = "01HABCDEFGHJKMNPQRSTVWXYZ0";
    // Just construct -- the spec is explicit that handshake happens on
    // first operation, not at construction.
    const _client = new Relay(ulid, { relayHome: tmpHome });
    // No /health call observed yet.
    expect(sidecar.observedHeaders.length).toBe(0);
    _client.close();
  });

  it("handshake against a sidecar that returns 401 raises RelaySidecarAuthError", async () => {
    sidecar = await startMockSidecar({ rejectHandshake: true });
    writeLockfile(tmpHome, sidecar.port, sidecar.digest);
    const ulid = "01HABCDEFGHJKMNPQRSTVWXYZ0";
    const client = new Relay(ulid, { relayHome: tmpHome });
    await expect(client.trace("x")).rejects.toThrow(RelaySidecarAuthError);
    client.close();
  });

  it("handshake against a sidecar whose /health omits sidecar_version raises RelaySidecarVersionMismatch", async () => {
    sidecar = await startMockSidecar({ omitVersion: true });
    writeLockfile(tmpHome, sidecar.port, sidecar.digest);
    const ulid = "01HABCDEFGHJKMNPQRSTVWXYZ0";
    const client = new Relay(ulid, { relayHome: tmpHome });
    await expect(client.trace("x")).rejects.toThrow(RelaySidecarVersionMismatch);
    client.close();
  });

  it("handshake against a sidecar whose version is incompatible raises RelaySidecarVersionMismatch", async () => {
    sidecar = await startMockSidecar({ version: "99.0.0" });
    writeLockfile(tmpHome, sidecar.port, sidecar.digest, "99.0.0");
    const ulid = "01HABCDEFGHJKMNPQRSTVWXYZ0";
    const client = new Relay(ulid, { relayHome: tmpHome });
    await expect(client.trace("x")).rejects.toThrow(RelaySidecarVersionMismatch);
    client.close();
  });

  it("trace() refuses an empty name", async () => {
    sidecar = await startMockSidecar();
    writeLockfile(tmpHome, sidecar.port, sidecar.digest);
    const ulid = "01HABCDEFGHJKMNPQRSTVWXYZ0";
    const client = new Relay(ulid, { relayHome: tmpHome });
    await expect(client.trace("")).rejects.toThrow(RelayConfigError);
    await expect(client.trace("  ")).rejects.toThrow(RelayConfigError);
    client.close();
  });
});
