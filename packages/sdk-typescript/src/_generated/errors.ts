/* GENERATED FILE - DO NOT EDIT BY HAND.
 *
 * Source: packages/schemas/raw/openapi.yaml (W1.5 OpenAPI 3.1 source-of-truth).
 * Regenerate: uv run python packages/schemas/scripts/codegen.py
 * Drift check: uv run python scripts/check-codegen-drift.py
 */

/**
 * Forward-compat unknown schema_version handler for VAL-W1-036.
 *
 * Per CLAUDE.md keystone invariant #10 and spec B.7 lines 3618-3621:
 * engines refuse to write objects whose schema_version is unknown. The
 * generated TS types pin `schema_version` to a const string literal; this
 * helper raises a structured error when a payload carries an unregistered
 * version.
 */

export class RelayUnknownSchemaVersionError extends Error {
  public readonly envelopeKind: string;
  public readonly observedVersion: string;
  public readonly expectedVersion: string;

  constructor(
    envelopeKind: string,
    observedVersion: string,
    expectedVersion: string,
  ) {
    super(
      `unknown schema_version for ${envelopeKind}: ` +
        `observed=${JSON.stringify(observedVersion)} ` +
        `expected=${JSON.stringify(expectedVersion)} (VAL-W1-036, spec B.7)`,
    );
    this.name = "RelayUnknownSchemaVersionError";
    this.envelopeKind = envelopeKind;
    this.observedVersion = observedVersion;
    this.expectedVersion = expectedVersion;
  }
}

/**
 * Validate that `payload.schema_version` equals `expectedVersion`. Throw
 * RelayUnknownSchemaVersionError on mismatch.
 *
 * The TS type system pins schema_version statically; this runtime check
 * handles documents loaded from JSON.parse where the static type is lost.
 *
 * Usage:
 *
 *   const payload: unknown = JSON.parse(input);
 *   parseEnvelope("RunResult", "relay.run_result.v1", payload);
 *   // ... downstream consumers can now cast to RunResult.
 */
export function parseEnvelope(
  envelopeKind: string,
  expectedVersion: string,
  payload: unknown,
): void {
  if (typeof payload !== "object" || payload === null) {
    throw new RelayUnknownSchemaVersionError(
      envelopeKind,
      "<not-an-object>",
      expectedVersion,
    );
  }
  const raw = (payload as Record<string, unknown>)["schema_version"];
  if (typeof raw !== "string") {
    throw new RelayUnknownSchemaVersionError(
      envelopeKind,
      typeof raw === "undefined" ? "<missing>" : String(raw),
      expectedVersion,
    );
  }
  if (raw !== expectedVersion) {
    throw new RelayUnknownSchemaVersionError(
      envelopeKind,
      raw,
      expectedVersion,
    );
  }
}
