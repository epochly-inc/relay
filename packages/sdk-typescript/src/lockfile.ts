/**
 * Sidecar lockfile parsing for the TS SDK (W4.1).
 *
 * Parity with the Python ``relay_sidecar.lockfile`` module. The lockfile
 * at ``${RELAY_HOME:-os.homedir()/.relay}/sidecar.lock`` contains a
 * canonical JSON object with exactly the keys:
 *
 *   { pid, port, launched_at, launched_by, sidecar_version,
 *     bearer_token_digest }
 *
 * Missing any key fails the parse. Per VAL-W4-002 the SDK reads the
 * lockfile from this path AND ONLY this path.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { RELAY_SDK_SIDECAR_LOCATOR_CODE, RelaySidecarLocatorError } from "./errors.js";

export const LOCKFILE_FILENAME = "sidecar.lock";

export interface LockfileBody {
  readonly pid: number;
  readonly port: number;
  readonly launched_at: string;
  readonly launched_by: string;
  readonly sidecar_version: string;
  readonly bearer_token_digest: string;
}

/**
 * Resolve the Relay home directory.
 *
 * Per VAL-W4-002: ``RELAY_HOME`` env var if set and non-empty,
 * otherwise ``os.homedir()/.relay``. The returned path is NOT created.
 */
export function relayHome(): string {
  const override = process.env["RELAY_HOME"]?.trim() ?? "";
  if (override) return override;
  return path.join(os.homedir(), ".relay");
}

/** Resolve the lockfile path under the given (or default) home. */
export function resolveLockfilePath(home?: string): string {
  return path.join(home ?? relayHome(), LOCKFILE_FILENAME);
}

/**
 * Parse the lockfile JSON body.
 *
 * Throws ``RelaySidecarLocatorError`` (code ``RELAY-SDK-011``) on any
 * malformed input -- missing keys, wrong types, JSON parse failure.
 */
export function parseLockfileBody(raw: Buffer | string): LockfileBody {
  const text = typeof raw === "string" ? raw : raw.toString("utf8");
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch (cause) {
    throw new RelaySidecarLocatorError("sidecar lockfile is not valid JSON", {
      code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
      details: {
        reason: "json_parse_failed",
        cause_message: cause instanceof Error ? cause.message : String(cause),
      },
      cause,
    });
  }
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    throw new RelaySidecarLocatorError(
      "sidecar lockfile body must be a JSON object",
      {
        code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
        details: { reason: "not_an_object" },
      },
    );
  }
  const o = obj as Record<string, unknown>;
  const required: ReadonlyArray<keyof LockfileBody> = [
    "pid",
    "port",
    "launched_at",
    "launched_by",
    "sidecar_version",
    "bearer_token_digest",
  ];
  for (const key of required) {
    if (!(key in o)) {
      throw new RelaySidecarLocatorError(
        `sidecar lockfile is missing required field '${key}'`,
        {
          code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
          details: { reason: "missing_field", field: key },
        },
      );
    }
  }
  const pid = o["pid"];
  const port = o["port"];
  const launchedAt = o["launched_at"];
  const launchedBy = o["launched_by"];
  const sidecarVersion = o["sidecar_version"];
  const bearerTokenDigest = o["bearer_token_digest"];
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) {
    throw new RelaySidecarLocatorError("sidecar lockfile 'pid' must be a positive integer", {
      code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
      details: { reason: "invalid_pid", received: pid },
    });
  }
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new RelaySidecarLocatorError("sidecar lockfile 'port' must be an integer in [1,65535]", {
      code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
      details: { reason: "invalid_port", received: port },
    });
  }
  if (typeof launchedAt !== "string" || !launchedAt) {
    throw new RelaySidecarLocatorError("sidecar lockfile 'launched_at' must be a non-empty string", {
      code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
      details: { reason: "invalid_launched_at" },
    });
  }
  if (typeof launchedBy !== "string" || !launchedBy) {
    throw new RelaySidecarLocatorError("sidecar lockfile 'launched_by' must be a non-empty string", {
      code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
      details: { reason: "invalid_launched_by" },
    });
  }
  if (typeof sidecarVersion !== "string" || !sidecarVersion) {
    throw new RelaySidecarLocatorError(
      "sidecar lockfile 'sidecar_version' must be a non-empty string",
      {
        code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
        details: { reason: "invalid_sidecar_version" },
      },
    );
  }
  if (
    typeof bearerTokenDigest !== "string" ||
    !/^sha256-[0-9a-f]{64}$/.test(bearerTokenDigest)
  ) {
    throw new RelaySidecarLocatorError(
      "sidecar lockfile 'bearer_token_digest' must be a 'sha256-<64-hex>' string",
      {
        code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
        details: { reason: "invalid_bearer_token_digest" },
      },
    );
  }
  return {
    pid,
    port,
    launched_at: launchedAt,
    launched_by: launchedBy,
    sidecar_version: sidecarVersion,
    bearer_token_digest: bearerTokenDigest,
  };
}

/**
 * Read and parse the sidecar lockfile under the resolved home.
 *
 * Per VAL-W4-002 this is the SINGLE permitted lockfile discovery path:
 * no `/tmp`, no cwd-relative, no fallback env vars besides ``RELAY_HOME``.
 *
 * Throws ``RelaySidecarLocatorError`` if the lockfile is missing,
 * unreadable, or malformed.
 */
export function readLockfile(home?: string): LockfileBody {
  const lockfilePath = resolveLockfilePath(home);
  let raw: Buffer;
  try {
    raw = fs.readFileSync(lockfilePath);
  } catch (cause) {
    throw new RelaySidecarLocatorError(
      `sidecar lockfile not found or unreadable at ${lockfilePath}`,
      {
        code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
        details: {
          reason: "not_found_or_unreadable",
          path: lockfilePath,
          cause_message: cause instanceof Error ? cause.message : String(cause),
        },
        cause,
      },
    );
  }
  if (raw.length === 0) {
    throw new RelaySidecarLocatorError(`sidecar lockfile at ${lockfilePath} is empty`, {
      code: RELAY_SDK_SIDECAR_LOCATOR_CODE,
      details: { reason: "empty", path: lockfilePath },
    });
  }
  return parseLockfileBody(raw);
}
