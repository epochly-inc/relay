/**
 * Relay TypeScript SDK client surface (W4.1).
 *
 * :class:`Relay` is the SDK entry point. Construction validates
 * configuration and stores it. It does NOT spawn the sidecar, touch the
 * lockfile, or make any HTTP request (VAL-W4-001b). All side effects are
 * deferred to the first operation that needs the sidecar -- the v0.1
 * trigger surface is :func:`trace`.
 *
 * Per CLAUDE.md keystone invariant #1 the SDK submits lifecycle metadata
 * ONLY. It never writes ``run_results.status`` or any other canonical
 * outcome -- the sidecar control plane is the sole writer.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import {
  RELAY_SDK_CONFIG_CODE,
  RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CODE,
  RelayConfigError,
} from "./errors.js";
import { SidecarTransport, type SidecarConnection } from "./transport.js";
import type { TraceHandle } from "./types.js";

// Project-key validation patterns mirror the Python SDK
// (``packages/sdk-python/relay/client.py:_ULID_RE / _PROJECT_TOKEN_RE``).
const ULID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const PROJECT_TOKEN_RE = /^relay_pk_[A-Za-z0-9_-]{16,}$/;

/** Env var that opts into the explicit-sidecar-url test-mode escape hatch. */
export const ALLOW_EXPLICIT_SIDECAR_ENV = "RELAY_ALLOW_EXPLICIT_SIDECAR";

/** Env var that bypasses the sidecar lockfile entirely (test-only). */
export const EXPLICIT_SIDECAR_URL_ENV = "RELAY_SIDECAR_URL";

function validateProjectKey(value: unknown): string {
  if (value === undefined || value === null) {
    throw new RelayConfigError("project_key is required; received null/undefined", {
      code: RELAY_SDK_CONFIG_CODE,
      details: { reason: "missing", received: value === undefined ? "undefined" : "null" },
    });
  }
  if (typeof value !== "string") {
    throw new RelayConfigError(
      `project_key must be a string; received ${typeof value}`,
      {
        code: RELAY_SDK_CONFIG_CODE,
        details: { reason: "wrong_type", received_type: typeof value },
      },
    );
  }
  const stripped = value.trim();
  if (!stripped) {
    throw new RelayConfigError("project_key must be a non-empty string; received a blank value", {
      code: RELAY_SDK_CONFIG_CODE,
      details: { reason: "empty" },
    });
  }
  if (!ULID_RE.test(stripped) && !PROJECT_TOKEN_RE.test(stripped)) {
    throw new RelayConfigError(
      "project_key is not a recognised Relay project key; expected a 26-character ULID or a 'relay_pk_' project token",
      {
        code: RELAY_SDK_CONFIG_CODE,
        details: { reason: "malformed" },
      },
    );
  }
  return stripped;
}

export interface RelayOptions {
  /**
   * Override the Relay home directory. Mainly a test-injection seam;
   * production callers leave this undefined and rely on ``$RELAY_HOME``
   * or ``~/.relay``.
   */
  relayHome?: string;
  /** Override the per-request HTTP timeout in ms. */
  httpTimeoutMs?: number;
  /**
   * Test-only fetch injection. Production code MUST leave this undefined.
   */
  fetchImpl?: (url: string, init?: RequestInit) => Promise<Response>;
}

/**
 * The Relay SDK client.
 *
 * Construction validates ``project_key`` synchronously and resolves
 * configuration -- no sidecar spawn, no lockfile touch, no HTTP call.
 * Per VAL-W4-002, the SDK reads the sidecar lockfile from
 * ``${RELAY_HOME:-os.homedir()/.relay}/sidecar.lock`` AND ONLY there;
 * setting ``RELAY_SIDECAR_URL`` without
 * ``RELAY_ALLOW_EXPLICIT_SIDECAR=1`` (the test-mode escape hatch) is
 * refused with :class:`RelayTrustRootOverrideDenied`-class errors.
 */
export class Relay {
  private readonly _projectKey: string;
  private readonly _relayHome: string | undefined;
  private readonly _transport: SidecarTransport;

  constructor(projectKey: unknown, options: RelayOptions = {}) {
    // VAL-W4-002 forbids alternative sidecar locator overrides outside of
    // the test-mode escape hatch.
    const explicitUrl = process.env[EXPLICIT_SIDECAR_URL_ENV];
    const explicitAllowed = process.env[ALLOW_EXPLICIT_SIDECAR_ENV] === "1";
    if (explicitUrl !== undefined && explicitUrl !== "" && !explicitAllowed) {
      throw new RelayConfigError(
        `${EXPLICIT_SIDECAR_URL_ENV} is set but ${ALLOW_EXPLICIT_SIDECAR_ENV}=1 is not; ` +
          "the SDK does not honor explicit sidecar URLs outside of test mode",
        {
          code: RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CODE,
          details: {
            reason: "explicit_sidecar_url_without_escape_hatch",
            env_var: EXPLICIT_SIDECAR_URL_ENV,
            allow_var: ALLOW_EXPLICIT_SIDECAR_ENV,
          },
        },
      );
    }
    this._projectKey = validateProjectKey(projectKey);
    this._relayHome = options.relayHome;
    this._transport = new SidecarTransport({
      relayHome: options.relayHome,
      ...(options.httpTimeoutMs !== undefined ? { httpTimeoutMs: options.httpTimeoutMs } : {}),
      ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
    });
  }

  get projectKey(): string {
    return this._projectKey;
  }

  get relayHome(): string | undefined {
    return this._relayHome;
  }

  /**
   * Open a trace -- the W4.1 SDK operation that lazily attaches to the
   * sidecar and performs the ``/health`` bearer-digest handshake
   * (VAL-W4-003).
   *
   * Returns a :class:`TraceHandle` describing the live connection; the
   * full lifecycle span surface lands in W4.2.
   */
  async trace(name: string): Promise<TraceHandle> {
    if (typeof name !== "string" || !name.trim()) {
      throw new RelayConfigError("trace name must be a non-empty string", {
        code: RELAY_SDK_CONFIG_CODE,
        details: { reason: "invalid_trace_name" },
      });
    }
    const conn: SidecarConnection = await this._transport.ensureAttached();
    return {
      name: name.trim(),
      baseUrl: conn.baseUrl,
      port: conn.port,
      pid: conn.pid,
      sidecarVersion: conn.sidecarVersion,
      bearerTokenDigest: conn.bearerTokenDigest,
      authHeader: conn.authHeader,
      spawned: conn.spawned,
    };
  }

  /**
   * Release SDK-side resources. Does NOT stop the sidecar -- the sidecar
   * owns its own lifecycle and the SDK never signals it.
   */
  close(): void {
    this._transport.close();
  }
}

/**
 * Top-level ``trace`` convenience: equivalent to constructing a Relay
 * client and calling :meth:`Relay.trace`. Required as a named export by
 * VAL-W4-001 contract snapshot. Project key is taken from the
 * ``RELAY_PROJECT_KEY`` env var; an invalid key raises
 * :class:`RelayConfigError`.
 */
export async function trace(name: string, options: RelayOptions = {}): Promise<TraceHandle> {
  const key = process.env["RELAY_PROJECT_KEY"];
  if (key === undefined || key === "") {
    throw new RelayConfigError(
      "RELAY_PROJECT_KEY env var is required for top-level relay.trace(); " +
        "pass a project_key explicitly via new Relay(key).trace(name)",
      {
        code: RELAY_SDK_CONFIG_CODE,
        details: { reason: "missing_env_var", env_var: "RELAY_PROJECT_KEY" },
      },
    );
  }
  const client = new Relay(key, options);
  return client.trace(name);
}

// Re-export for tests that want to bypass the env-var requirement.
export { validateProjectKey as _validateProjectKey };
