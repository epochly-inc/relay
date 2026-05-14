/**
 * Sidecar HTTP transport for the TS SDK (W4.1).
 *
 * Parity with the Python ``relay._transport`` module. The transport is
 * import-side-effect-free; the side-effecting work happens inside
 * :meth:`SidecarTransport.ensureAttached`, invoked lazily by the first
 * :class:`Relay` operation that needs the sidecar.
 *
 * VAL-W4-002: the lockfile is read from
 * ``${RELAY_HOME:-os.homedir()/.relay}/sidecar.lock`` AND ONLY there.
 *
 * VAL-W4-003: construction of a usable connection performs the
 * ``/health`` bearer-digest handshake before any business request. The
 * SDK never speaks to the hosted control plane directly; it speaks only
 * to the loopback sidecar (CLAUDE.md keystone invariant #1).
 *
 * v0.1 attach-only path:
 *   The TS SDK W4.1 surface does NOT auto-spawn the sidecar -- that is
 *   delivered separately via ``npx @epochly/relay sidecar`` (VAL-W4-004
 *   et seq). The transport here implements the cross-process attach
 *   branch of the Python transport: it requires the sidecar already to
 *   be running, reads the lockfile, completes the ``/health`` bearer
 *   digest handshake, and returns a typed connection. If no sidecar is
 *   reachable, it raises :class:`RelaySidecarNotReachable`. The full
 *   auto-spawn flow lands in W4.2 alongside the lifecycle ingest path.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";

import {
  RELAY_SDK_AUTH_MISMATCH_CODE,
  RELAY_SDK_NO_SIDECAR_CODE,
  RELAY_SDK_VERSION_MISMATCH_CODE,
  RelaySidecarAuthError,
  RelaySidecarNotReachable,
  RelaySidecarVersionMismatch,
} from "./errors.js";
import { readLockfile, type LockfileBody } from "./lockfile.js";

/**
 * SDK <-> sidecar compatibility range (VAL-W3-007 parity).
 *
 * v0.1 pins both ends to ``0.0.0``; the range widens as the sidecar
 * stabilises.
 */
export const MIN_COMPATIBLE_SIDECAR_VERSION = "0.0.0";
export const MAX_COMPATIBLE_SIDECAR_VERSION = "0.0.0";

/** Default per-request HTTP timeout for loopback sidecar calls. */
export const HTTP_TIMEOUT_MS = 10_000;

/**
 * Live, authenticated connection to the local sidecar.
 */
export interface SidecarConnection {
  readonly baseUrl: string;
  readonly port: number;
  readonly pid: number;
  readonly sidecarVersion: string;
  readonly bearerTokenDigest: string;
  /**
   * Header value to present on subsequent requests. For W4.1 cross-process
   * attach this is the bearer digest; W4.2 SDK-spawn path widens this to
   * carry the nonce proof produced by ``/health/nonce`` -> sign flow.
   */
  readonly authHeader: string;
  /** True iff this SDK instance spawned the sidecar. */
  readonly spawned: boolean;
}

/**
 * Compute the canonical ``sha256-<hex>`` digest of a bearer token.
 *
 * Byte-equal to Python ``relay._transport._digest_of_token``.
 */
export function digestOfToken(token: string): string {
  const hex = crypto.createHash("sha256").update(token, "utf8").digest("hex");
  return `sha256-${hex}`;
}

/**
 * Compute the canonical nonce proof: ``SHA-256("<nonce>:<token>")`` (hex).
 *
 * Matches Python ``relay._transport._nonce_proof`` byte for byte.
 */
export function nonceProof(nonce: string, token: string): string {
  return crypto.createHash("sha256").update(`${nonce}:${token}`, "utf8").digest("hex");
}

/** Parse a dotted version string into a numeric tuple. */
function versionTuple(version: string): number[] {
  return version
    .trim()
    .split(".")
    .map((part) => {
      const n = Number(part);
      if (!Number.isInteger(n) || n < 0) {
        throw new Error(`malformed version component: ${part}`);
      }
      return n;
    });
}

/** Compare two numeric tuples component-wise, padding the shorter with 0. */
function compareTuples(a: number[], b: number[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const av = i < a.length ? (a[i] as number) : 0;
    const bv = i < b.length ? (b[i] as number) : 0;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  return 0;
}

/** Return true iff ``version`` is within the SDK compatibility range. */
export function isSidecarVersionCompatible(version: string): boolean {
  try {
    const observed = versionTuple(version);
    const low = versionTuple(MIN_COMPATIBLE_SIDECAR_VERSION);
    const high = versionTuple(MAX_COMPATIBLE_SIDECAR_VERSION);
    return compareTuples(low, observed) <= 0 && compareTuples(observed, high) <= 0;
  } catch {
    return false;
  }
}

export interface SidecarTransportOptions {
  /** Override the relay home directory; tests inject a tmp dir here. */
  relayHome?: string;
  /** Override the per-request HTTP timeout in ms. */
  httpTimeoutMs?: number;
  /**
   * Test-only hook to inject a mock HTTP client. Production code MUST
   * leave this undefined; the default uses Node's native ``fetch``.
   */
  fetchImpl?: (url: string, init?: RequestInit) => Promise<Response>;
}

/**
 * Lazy sidecar HTTP transport tied to one ``Relay`` instance.
 *
 * Construction is side-effect-free: no lockfile read, no HTTP call, no
 * port bind. The first call to :meth:`ensureAttached` runs the lockfile
 * resolve + handshake exactly once; subsequent calls return the cached
 * connection.
 */
export class SidecarTransport {
  private readonly relayHomeOverride: string | undefined;
  private readonly httpTimeoutMs: number;
  private readonly fetchImpl: (url: string, init?: RequestInit) => Promise<Response>;
  private connection: SidecarConnection | null = null;
  private inflight: Promise<SidecarConnection> | null = null;

  constructor(options: SidecarTransportOptions = {}) {
    this.relayHomeOverride = options.relayHome;
    this.httpTimeoutMs = options.httpTimeoutMs ?? HTTP_TIMEOUT_MS;
    // Node 22+ has fetch on the global object.
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  /** Return the bound relay home (override if set, otherwise computed). */
  get relayHome(): string | undefined {
    return this.relayHomeOverride;
  }

  /**
   * Lazily attach to the sidecar and return the live connection.
   *
   * Idempotent: the lockfile read + handshake runs at most once per
   * transport instance. Concurrent callers share the in-flight promise.
   */
  async ensureAttached(): Promise<SidecarConnection> {
    if (this.connection !== null) return this.connection;
    if (this.inflight !== null) return this.inflight;
    this.inflight = (async () => {
      try {
        const body = readLockfile(this.relayHomeOverride);
        const conn = await this.attachToRunning(body);
        this.connection = conn;
        return conn;
      } finally {
        this.inflight = null;
      }
    })();
    return this.inflight;
  }

  /**
   * Drop the cached connection so the next call re-handshakes.
   *
   * Does NOT signal the sidecar; the SDK never kills the sidecar
   * (CLAUDE.md process-safety rule).
   */
  close(): void {
    this.connection = null;
  }

  // -- internals ---------------------------------------------------------

  private async attachToRunning(body: LockfileBody): Promise<SidecarConnection> {
    const baseUrl = `http://127.0.0.1:${body.port}`;
    const bearerDigest = body.bearer_token_digest;
    let healthResp: Response;
    try {
      healthResp = await this.timedFetch(`${baseUrl}/health`, {
        method: "GET",
        headers: { "X-Relay-Bearer-Digest": bearerDigest },
      });
    } catch (cause) {
      throw new RelaySidecarNotReachable(
        `sidecar /health call failed during attach: ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
        {
          code: RELAY_SDK_NO_SIDECAR_CODE,
          details: {
            base_url: baseUrl,
            phase: "health-attach",
            cause_message: cause instanceof Error ? cause.message : String(cause),
          },
          cause,
        },
      );
    }
    if (healthResp.status !== 200) {
      throw new RelaySidecarAuthError(
        `sidecar rejected the lockfile bearer digest on attach (HTTP ${healthResp.status})`,
        {
          code: RELAY_SDK_AUTH_MISMATCH_CODE,
          httpStatus: healthResp.status,
          details: {
            base_url: baseUrl,
            phase: "health-attach",
            http_status: healthResp.status,
          },
        },
      );
    }
    let healthBody: Record<string, unknown>;
    try {
      healthBody = (await healthResp.json()) as Record<string, unknown>;
    } catch (cause) {
      throw new RelaySidecarAuthError("sidecar /health body was not valid JSON", {
        code: RELAY_SDK_AUTH_MISMATCH_CODE,
        details: {
          base_url: baseUrl,
          phase: "health-attach",
          cause_message: cause instanceof Error ? cause.message : String(cause),
        },
        cause,
      });
    }
    const sidecarVersion = healthBody["sidecar_version"];
    if (typeof sidecarVersion !== "string" || !sidecarVersion) {
      throw new RelaySidecarVersionMismatch(
        "sidecar /health response omitted sidecar_version; cannot verify compatibility",
        {
          code: RELAY_SDK_VERSION_MISMATCH_CODE,
          details: { base_url: baseUrl, health_body: healthBody },
        },
      );
    }
    if (!isSidecarVersionCompatible(sidecarVersion)) {
      throw new RelaySidecarVersionMismatch(
        `sidecar version '${sidecarVersion}' is outside the SDK compatibility range ` +
          `[${MIN_COMPATIBLE_SIDECAR_VERSION}, ${MAX_COMPATIBLE_SIDECAR_VERSION}]`,
        {
          code: RELAY_SDK_VERSION_MISMATCH_CODE,
          details: {
            base_url: baseUrl,
            sidecar_version: sidecarVersion,
            min_compatible: MIN_COMPATIBLE_SIDECAR_VERSION,
            max_compatible: MAX_COMPATIBLE_SIDECAR_VERSION,
          },
        },
      );
    }
    return {
      baseUrl,
      port: body.port,
      pid: body.pid,
      sidecarVersion,
      bearerTokenDigest: bearerDigest,
      authHeader: bearerDigest,
      spawned: false,
    };
  }

  /** Apply ``httpTimeoutMs`` via AbortController to a fetch call. */
  private async timedFetch(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.httpTimeoutMs);
    try {
      const merged: RequestInit = { ...init, signal: controller.signal };
      return await this.fetchImpl(url, merged);
    } finally {
      clearTimeout(timer);
    }
  }
}
