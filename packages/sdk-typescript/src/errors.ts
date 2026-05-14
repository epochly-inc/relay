/**
 * Relay TypeScript SDK error hierarchy (W4.1).
 *
 * Parity with the Python SDK error hierarchy in
 * ``packages/sdk-python/relay/errors.py``. The hierarchy is two-deep:
 *
 *   * RelayError -- the abstract root.
 *   * Namespace intermediates, one per RELAY-{AREA}-* code prefix
 *     (RelayIngestError, RelayAuthError, RelayRateLimitError,
 *     RelayGateError, RelayEvidenceError, RelayReplayError,
 *     RelaySchemaError, RelaySidecarError, RelaySdkError,
 *     RelaySQLiteError).
 *   * Typed leaves for the codes the v0.1 SDK surface explicitly maps
 *     (RelayConfigError, RelaySidecarVersionMismatch,
 *     RelaySidecarNotReachable, RelaySidecarAuthError,
 *     RelayCanonicalStatusForbidden, RelayHandoffIncomplete,
 *     RelayPolicyError, RelayEvidenceIncomplete,
 *     RelayReplayPrecondition, RelayLifecycleInvalid).
 *   * A forward-compat fallback RelayUnknownError for any sidecar
 *     code the SDK does not recognise (VAL-W4-030).
 *
 * retry_advice is always a discriminated union (VAL-W4-027), never a
 * boolean. ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

// -----------------------------------------------------------------------------
// Wire code constants. Mirrors Python relay.errors RELAY_*_CODE constants.
// Source of truth: packages/schemas/raw/relay-error-codes.yaml.
// -----------------------------------------------------------------------------

export const RELAY_SDK_CONFIG_CODE = "RELAY-SDK-001";
export const RELAY_SDK_VERSION_MISMATCH_CODE = "RELAY-SDK-002";
export const RELAY_SDK_NO_SIDECAR_CODE = "RELAY-SDK-003";
export const RELAY_SDK_AUTH_MISMATCH_CODE = "RELAY-SDK-004";
export const RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE = "RELAY-SDK-005";
export const RELAY_SDK_LIFECYCLE_INVALID_CODE = "RELAY-SDK-006";
export const RELAY_SDK_HANDOFF_INCOMPLETE_CODE = "RELAY-SDK-007";
export const RELAY_SDK_EVIDENCE_INCOMPLETE_CODE = "RELAY-SDK-008";
export const RELAY_SDK_REPLAY_PRECONDITION_CODE = "RELAY-SDK-009";
export const RELAY_SDK_POLICY_INVALID_CODE = "RELAY-SDK-010";

// Wire codes from the sidecar.
export const RELAY_ING_001_CODE = "RELAY-ING-001";
export const RELAY_ING_022_CODE = "RELAY-ING-022";
export const RELAY_ING_031_CODE = "RELAY-ING-031";
export const RELAY_ING_032_CODE = "RELAY-ING-032";
export const RELAY_REPLAY_002_CODE = "RELAY-REPLAY-002";
export const RELAY_EVID_002_CODE = "RELAY-EVID-002";
// Gate-handoff stale (spec B.4 RELAY-GATE-021). Maps to RelayHandoffIncomplete
// per VAL-W4-015 (stale handoff surface).
export const RELAY_GATE_021_CODE = "RELAY-GATE-021";

// Namespace defaults.
export const RELAY_ING_DEFAULT_CODE = "RELAY-ING-001";
export const RELAY_AUTH_DEFAULT_CODE = "RELAY-AUTH-001";
export const RELAY_RATE_DEFAULT_CODE = "RELAY-RATE-001";
export const RELAY_GATE_DEFAULT_CODE = "RELAY-GATE-001";
export const RELAY_EVID_DEFAULT_CODE = "RELAY-EVID-001";
export const RELAY_REPLAY_DEFAULT_CODE = "RELAY-REPLAY-001";
export const RELAY_SCHEMA_DEFAULT_CODE = "RELAY-SCHEMA-001";
export const RELAY_SIDECAR_DEFAULT_CODE = "RELAY-SIDECAR-001";
export const RELAY_SQLITE_DEFAULT_CODE = "RELAY-SQLITE-001";
export const RELAY_FUTURE_999_CODE = "RELAY-FUTURE-999";

// W4-specific sidecar bundle codes (npx wrapper). Allocated under the
// RELAY-SIDECAR-* and RELAY-SDK-* namespaces. These match the names
// referenced verbatim in contract.md VAL-W4-004..VAL-W4-011b.
export const RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE = "RELAY-SIDECAR-020";
export const RELAY_SIDECAR_BUNDLE_DIGEST_MISMATCH_CODE = "RELAY-SIDECAR-021";
export const RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE = "RELAY-SIDECAR-022";
export const RELAY_SIDECAR_BUNDLE_ARCH_UNSUPPORTED_CODE = "RELAY-SIDECAR-023";
export const RELAY_SDK_SIDECAR_LOCATOR_CODE = "RELAY-SDK-011";
export const RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CODE = "RELAY-SDK-012";
export const RELAY_SDK_BUNDLE_VERIFY_TIMEOUT_CODE = "RELAY-SDK-013";
// W4.2 lifecycle codes (VAL-W4-013, VAL-W4-017).
export const RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CODE = "RELAY-SDK-014";
export const RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CODE = "RELAY-SDK-015";

// Descriptive error_class tokens (contract.md prose).
export const RELAY_SDK_CONFIG_CLASS = "RELAY-SDK-CONFIG-001";
export const RELAY_SDK_VERSION_MISMATCH_CLASS = "RELAY-SDK-VERSION-MISMATCH";
export const RELAY_SDK_NO_SIDECAR_CLASS = "RELAY-SDK-NO-SIDECAR";
export const RELAY_SDK_AUTH_MISMATCH_CLASS = "RELAY-SDK-AUTH-MISMATCH";
export const RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CLASS =
  "RELAY-SDK-CANONICAL-STATUS-FORBIDDEN";
export const RELAY_SDK_LIFECYCLE_INVALID_CLASS = "RELAY-SDK-LIFECYCLE-INVALID";
export const RELAY_SDK_HANDOFF_INCOMPLETE_CLASS = "RELAY-SDK-HANDOFF-INCOMPLETE";
export const RELAY_SDK_EVIDENCE_INCOMPLETE_CLASS = "RELAY-SDK-EVIDENCE-INCOMPLETE";
export const RELAY_SDK_REPLAY_PRECONDITION_CLASS = "RELAY-SDK-REPLAY-PRECONDITION";
export const RELAY_SDK_POLICY_INVALID_CLASS = "RELAY-SDK-POLICY-INVALID";
export const RELAY_SIDECAR_BUNDLE_UNVERIFIED_CLASS = "RELAY-SIDECAR-BUNDLE-UNVERIFIED";
export const RELAY_SIDECAR_BUNDLE_DIGEST_MISMATCH_CLASS =
  "RELAY-SIDECAR-BUNDLE-DIGEST-MISMATCH";
export const RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CLASS = "RELAY-SIDECAR-BUNDLE-UNAVAILABLE";
export const RELAY_SIDECAR_BUNDLE_ARCH_UNSUPPORTED_CLASS =
  "RELAY-SIDECAR-BUNDLE-ARCH-UNSUPPORTED";
export const RELAY_SDK_SIDECAR_LOCATOR_CLASS = "RELAY-SDK-SIDECAR-LOCATOR";
export const RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CLASS =
  "RELAY-SDK-TRUST-ROOT-OVERRIDE-DENIED";
export const RELAY_SDK_BUNDLE_VERIFY_TIMEOUT_CLASS = "RELAY-SDK-BUNDLE-VERIFY-TIMEOUT";
// W4.2 lifecycle classes.
export const RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CLASS =
  "RELAY-SDK-SIDE-EFFECT-FIELDS-MISSING";
export const RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CLASS =
  "RELAY-SDK-REPLAY-LIVE-MODE-UNACKNOWLEDGED";

const DEFAULT_DOC_URL_PREFIX = "https://relay.epochly.com/docs/errors/";

// -----------------------------------------------------------------------------
// Retry advice -- a discriminated union (VAL-W4-027), never a boolean.
// -----------------------------------------------------------------------------

export type RetryAdviceMode =
  | "no_retry"
  | "retryable"
  | "after_state_change"
  | "after_retry_after";

export interface RetryAdvice {
  mode: RetryAdviceMode;
  delay_seconds?: number;
  max_attempts?: number;
  raw?: string;
  // Extra fields are preserved when ``mode`` resolves from a known input.
  [key: string]: unknown;
}

const WIRE_RETRY_ADVICE_TO_DICT: Record<string, RetryAdvice> = {
  do_not_retry: { mode: "no_retry" },
  after_fix: { mode: "after_state_change" },
  after_retry_after: { mode: "after_retry_after" },
  after_split: { mode: "after_state_change" },
  after_recapture: { mode: "after_state_change" },
  after_re_auth: { mode: "after_state_change" },
};

const KNOWN_MODES: ReadonlySet<string> = new Set([
  "no_retry",
  "retryable",
  "after_state_change",
  "after_retry_after",
]);

export function coerceRetryAdvice(value: unknown): RetryAdvice {
  if (value === null || value === undefined) {
    return { mode: "no_retry" };
  }
  // Booleans are explicitly forbidden (VAL-W4-027).
  if (typeof value === "boolean") {
    return { mode: "no_retry" };
  }
  if (typeof value === "string") {
    const wire = WIRE_RETRY_ADVICE_TO_DICT[value];
    if (wire !== undefined) {
      return { ...wire };
    }
    if (KNOWN_MODES.has(value)) {
      return { mode: value as RetryAdviceMode };
    }
    return { mode: "no_retry", raw: value };
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const mode = obj["mode"];
    if (typeof mode !== "string" || !mode) {
      const rest: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(obj)) {
        if (k !== "mode") rest[k] = v;
      }
      return { mode: "no_retry", ...rest };
    }
    if (KNOWN_MODES.has(mode)) {
      return { ...(obj as RetryAdvice), mode: mode as RetryAdviceMode };
    }
    return { mode: "no_retry", raw: mode };
  }
  return { mode: "no_retry" };
}

// -----------------------------------------------------------------------------
// Wire envelope shape (mirrors spec B.4 and python to_envelope).
// -----------------------------------------------------------------------------

export interface ErrorEnvelopeWire {
  schema_version?: string;
  code: string;
  http_status?: number;
  message?: string;
  blocked_surface?: string;
  documentation_url?: string;
  retry_advice?: unknown;
  request_id?: string | null;
  trace_id?: string | null;
  error_class?: string;
  details?: Record<string, unknown> | null;
}

export interface RelayErrorOptions {
  code?: string;
  httpStatus?: number;
  blockedSurface?: string;
  retryAdvice?: unknown;
  requestId?: string | null;
  traceId?: string | null;
  documentationUrl?: string;
  details?: Record<string, unknown>;
  cause?: unknown;
}

// -----------------------------------------------------------------------------
// RelayError base class.
// -----------------------------------------------------------------------------

export class RelayError extends Error {
  static defaultCode = "RELAY-SDK-001";
  static defaultErrorClass = "RELAY-SDK-ERROR";
  static defaultHttpStatus = 500;
  static defaultRetryAdvice: RetryAdviceMode = "no_retry";
  static defaultBlockedSurface = "relay-sdk";
  static envelopeSchemaVersion = "relay.sdk_error.v1";

  readonly code: string;
  readonly errorClass: string;
  readonly httpStatus: number;
  readonly blockedSurface: string;
  readonly retryAdvice: RetryAdvice;
  readonly requestId: string | null;
  readonly traceId: string | null;
  readonly documentationUrl: string;
  readonly details: Record<string, unknown>;

  constructor(message: string, options: RelayErrorOptions = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    const ctor = this.constructor as typeof RelayError;
    this.name = ctor.name;
    this.code = options.code ?? ctor.defaultCode;
    this.errorClass = ctor.defaultErrorClass;
    this.httpStatus = options.httpStatus ?? ctor.defaultHttpStatus;
    this.blockedSurface = options.blockedSurface ?? ctor.defaultBlockedSurface;
    this.retryAdvice = coerceRetryAdvice(options.retryAdvice ?? ctor.defaultRetryAdvice);
    this.requestId = options.requestId ?? null;
    this.traceId = options.traceId ?? null;
    this.documentationUrl =
      options.documentationUrl ?? `${DEFAULT_DOC_URL_PREFIX}${this.code}`;
    this.details = options.details ? { ...options.details } : {};
  }

  toEnvelope(): Required<Omit<ErrorEnvelopeWire, "details">> & {
    details: Record<string, unknown>;
    retry_advice: RetryAdvice;
  } {
    const ctor = this.constructor as typeof RelayError;
    return {
      schema_version: ctor.envelopeSchemaVersion,
      code: this.code,
      http_status: this.httpStatus,
      message: this.message,
      blocked_surface: this.blockedSurface,
      documentation_url: this.documentationUrl,
      retry_advice: { ...this.retryAdvice },
      request_id: this.requestId,
      trace_id: this.traceId,
      error_class: this.errorClass,
      details: { ...this.details },
    };
  }

  static fromEnvelope(envelope: ErrorEnvelopeWire): RelayError {
    const code = String(envelope.code ?? "");
    const message = String(envelope.message ?? "");
    const targetCls = resolveClassForCode(code);
    const httpStatus =
      typeof envelope.http_status === "number" ? envelope.http_status : undefined;
    const blockedSurface =
      typeof envelope.blocked_surface === "string" ? envelope.blocked_surface : undefined;
    const requestId =
      typeof envelope.request_id === "string" && envelope.request_id
        ? envelope.request_id
        : null;
    const traceId =
      typeof envelope.trace_id === "string" && envelope.trace_id ? envelope.trace_id : null;
    const documentationUrl =
      typeof envelope.documentation_url === "string" ? envelope.documentation_url : undefined;
    const details =
      envelope.details && typeof envelope.details === "object" && !Array.isArray(envelope.details)
        ? (envelope.details as Record<string, unknown>)
        : undefined;
    return new targetCls(message, {
      code,
      httpStatus,
      blockedSurface,
      retryAdvice: envelope.retry_advice,
      requestId,
      traceId,
      documentationUrl,
      details,
    });
  }
}

// -----------------------------------------------------------------------------
// Namespace intermediates.
// -----------------------------------------------------------------------------

export class RelayIngestError extends RelayError {
  static override defaultCode = RELAY_ING_DEFAULT_CODE;
  static override defaultErrorClass = "RELAY-ING-ERROR";
  static override defaultHttpStatus = 400;
  static override defaultBlockedSurface = "POST /v1/ingest/runs";
}

export class RelayAuthError extends RelayError {
  static override defaultCode = RELAY_AUTH_DEFAULT_CODE;
  static override defaultErrorClass = "RELAY-AUTH-ERROR";
  static override defaultHttpStatus = 401;
  static override defaultBlockedSurface = "POST /v1/ingest/runs";
}

export class RelayRateLimitError extends RelayError {
  static override defaultCode = RELAY_RATE_DEFAULT_CODE;
  static override defaultErrorClass = "RELAY-RATE-ERROR";
  static override defaultHttpStatus = 429;
  static override defaultRetryAdvice: RetryAdviceMode = "after_retry_after";
  static override defaultBlockedSurface = "POST /v1/ingest/runs";
}

export class RelayGateError extends RelayError {
  static override defaultCode = RELAY_GATE_DEFAULT_CODE;
  static override defaultErrorClass = "RELAY-GATE-ERROR";
  static override defaultHttpStatus = 404;
  static override defaultBlockedSurface = "POST /v1/gates/{gate_id}/drafts";
}

export class RelayEvidenceError extends RelayError {
  static override defaultCode = RELAY_EVID_DEFAULT_CODE;
  static override defaultErrorClass = "RELAY-EVID-ERROR";
  static override defaultHttpStatus = 422;
  static override defaultBlockedSurface = "POST /v1/evidence";
}

export class RelayReplayError extends RelayError {
  static override defaultCode = RELAY_REPLAY_DEFAULT_CODE;
  static override defaultErrorClass = "RELAY-REPLAY-ERROR";
  static override defaultHttpStatus = 422;
  static override defaultBlockedSurface = "POST /v1/runs/{run_id}/replays";
}

export class RelaySchemaError extends RelayError {
  static override defaultCode = RELAY_SCHEMA_DEFAULT_CODE;
  static override defaultErrorClass = "RELAY-SCHEMA-ERROR";
  static override defaultHttpStatus = 422;
  static override defaultBlockedSurface = "POST /v1/ingest/runs";
}

export class RelaySidecarError extends RelayError {
  static override defaultCode = RELAY_SIDECAR_DEFAULT_CODE;
  static override defaultErrorClass = "RELAY-SIDECAR-ERROR";
  static override defaultHttpStatus = 503;
  static override defaultRetryAdvice: RetryAdviceMode = "after_state_change";
  static override defaultBlockedSurface = "relay-sidecar";
}

export class RelaySdkError extends RelayError {
  static override defaultCode = RELAY_SDK_CONFIG_CODE;
  static override defaultErrorClass = "RELAY-SDK-ERROR";
  static override defaultHttpStatus = 400;
  static override defaultBlockedSurface = "relay-sdk";
}

export class RelaySQLiteError extends RelayError {
  static override defaultCode = RELAY_SQLITE_DEFAULT_CODE;
  static override defaultErrorClass = "RELAY-SQLITE-ERROR";
  static override defaultHttpStatus = 500;
  static override defaultBlockedSurface = "relay-sidecar-sqlite";
}

// -----------------------------------------------------------------------------
// Typed leaves.
// -----------------------------------------------------------------------------

export class RelayConfigError extends RelaySdkError {
  static override defaultCode = RELAY_SDK_CONFIG_CODE;
  static override defaultErrorClass = RELAY_SDK_CONFIG_CLASS;
  static override defaultHttpStatus = 400;
  static override defaultBlockedSurface = "relay-sdk";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

export class RelaySidecarVersionMismatch extends RelaySidecarError {
  static override defaultCode = RELAY_SDK_VERSION_MISMATCH_CODE;
  static override defaultErrorClass = RELAY_SDK_VERSION_MISMATCH_CLASS;
  static override defaultHttpStatus = 503;
  static override defaultBlockedSurface = "GET /health";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

export class RelaySidecarNotReachable extends RelaySidecarError {
  static override defaultCode = RELAY_SDK_NO_SIDECAR_CODE;
  static override defaultErrorClass = RELAY_SDK_NO_SIDECAR_CLASS;
  static override defaultHttpStatus = 503;
  static override defaultBlockedSurface = "GET /health";
  static override defaultRetryAdvice: RetryAdviceMode = "after_state_change";
}

// VAL-W4-003 typed leaf -- handshake bearer-digest mismatch.
export class RelaySidecarAuthError extends RelayAuthError {
  static override defaultCode = RELAY_SDK_AUTH_MISMATCH_CODE;
  static override defaultErrorClass = RELAY_SDK_AUTH_MISMATCH_CLASS;
  static override defaultHttpStatus = 401;
  static override defaultBlockedSurface = "GET /health";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

// Python parity alias.
export const RelayAuthMismatch = RelaySidecarAuthError;
export type RelayAuthMismatch = RelaySidecarAuthError;

export class RelayCanonicalStatusForbidden extends RelayIngestError {
  static override defaultCode = RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE;
  static override defaultErrorClass = RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CLASS;
  static override defaultHttpStatus = 422;
  static override defaultBlockedSurface = "POST /v1/ingest/runs";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

export class RelayControlPlaneOwnershipError extends RelayCanonicalStatusForbidden {
  // Distinct typed leaf for the W4 adversarial canonical-write tests
  // (VAL-W4-010). Carries forged_field through the details map.
}

export class RelayLifecycleInvalid extends RelaySdkError {
  static override defaultCode = RELAY_SDK_LIFECYCLE_INVALID_CODE;
  static override defaultErrorClass = RELAY_SDK_LIFECYCLE_INVALID_CLASS;
  static override defaultHttpStatus = 400;
  static override defaultBlockedSurface = "POST /v1/ingest/runs";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

export class RelayHandoffIncomplete extends RelayIngestError {
  static override defaultCode = RELAY_SDK_HANDOFF_INCOMPLETE_CODE;
  static override defaultErrorClass = RELAY_SDK_HANDOFF_INCOMPLETE_CLASS;
  static override defaultHttpStatus = 422;
  static override defaultBlockedSurface = "POST /v1/ingest/runs";
  static override defaultRetryAdvice: RetryAdviceMode = "after_state_change";
}

export class RelayEvidenceIncomplete extends RelayEvidenceError {
  static override defaultCode = RELAY_SDK_EVIDENCE_INCOMPLETE_CODE;
  static override defaultErrorClass = RELAY_SDK_EVIDENCE_INCOMPLETE_CLASS;
  static override defaultHttpStatus = 422;
  static override defaultBlockedSurface = "POST /v1/evidence";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

export class RelayReplayPrecondition extends RelayReplayError {
  static override defaultCode = RELAY_SDK_REPLAY_PRECONDITION_CODE;
  static override defaultErrorClass = RELAY_SDK_REPLAY_PRECONDITION_CLASS;
  static override defaultHttpStatus = 422;
  static override defaultBlockedSurface = "POST /v1/runs/{run_id}/replays";
  static override defaultRetryAdvice: RetryAdviceMode = "after_state_change";
}

export class RelayPolicyError extends RelayIngestError {
  static override defaultCode = RELAY_SDK_POLICY_INVALID_CODE;
  static override defaultErrorClass = RELAY_SDK_POLICY_INVALID_CLASS;
  static override defaultHttpStatus = 422;
  static override defaultBlockedSurface = "POST /v1/ingest/runs";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

/**
 * VAL-W4-013: side-effecting tool_call missing idempotencyKey or replayPolicy.
 *
 * The SDK refuses to open the span when ``side_effect: true`` is set
 * without both companion fields. The control plane never sees the
 * malformed span (defense-in-depth: spec X side-effect idempotency,
 * CLAUDE.md keystone invariant #6).
 */
export class RelaySideEffectMissingFieldsError extends RelaySdkError {
  static override defaultCode = RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CODE;
  static override defaultErrorClass = RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CLASS;
  static override defaultHttpStatus = 422;
  static override defaultBlockedSurface = "relay-sdk-tool-call";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

/**
 * VAL-W4-017: live replay called without explicit acknowledgement.
 *
 * Live mode is a "degraded approximation" (CLAUDE.md keystone invariant
 * #9). The SDK refuses to dispatch the request unless the caller passes
 * ``acknowledgeDegradedApproximation: true``.
 */
export class RelayReplayLiveModeUnacknowledgedError extends RelaySdkError {
  static override defaultCode = RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CODE;
  static override defaultErrorClass = RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CLASS;
  static override defaultHttpStatus = 422;
  static override defaultBlockedSurface = "POST /v1/replay-cases/{case_id}/run";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

// -----------------------------------------------------------------------------
// W4 sidecar-bundle typed leaves (used by npx wrapper).
// -----------------------------------------------------------------------------

export class RelaySidecarBundleUnverified extends RelaySidecarError {
  static override defaultCode = RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE;
  static override defaultErrorClass = RELAY_SIDECAR_BUNDLE_UNVERIFIED_CLASS;
  static override defaultHttpStatus = 503;
  static override defaultBlockedSurface = "npx @epochly/relay sidecar";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

export class RelaySidecarBundleDigestMismatch extends RelaySidecarError {
  static override defaultCode = RELAY_SIDECAR_BUNDLE_DIGEST_MISMATCH_CODE;
  static override defaultErrorClass = RELAY_SIDECAR_BUNDLE_DIGEST_MISMATCH_CLASS;
  static override defaultHttpStatus = 503;
  static override defaultBlockedSurface = "npx @epochly/relay sidecar";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

export class RelaySidecarBundleUnavailable extends RelaySidecarError {
  static override defaultCode = RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE;
  static override defaultErrorClass = RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CLASS;
  static override defaultHttpStatus = 503;
  static override defaultBlockedSurface = "npx @epochly/relay sidecar";
  static override defaultRetryAdvice: RetryAdviceMode = "after_state_change";
}

export class RelaySidecarBundleArchUnsupported extends RelaySidecarError {
  static override defaultCode = RELAY_SIDECAR_BUNDLE_ARCH_UNSUPPORTED_CODE;
  static override defaultErrorClass = RELAY_SIDECAR_BUNDLE_ARCH_UNSUPPORTED_CLASS;
  static override defaultHttpStatus = 503;
  static override defaultBlockedSurface = "npx @epochly/relay sidecar";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

export class RelaySidecarLocatorError extends RelaySdkError {
  static override defaultCode = RELAY_SDK_SIDECAR_LOCATOR_CODE;
  static override defaultErrorClass = RELAY_SDK_SIDECAR_LOCATOR_CLASS;
  static override defaultHttpStatus = 400;
  static override defaultBlockedSurface = "relay-sdk";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

export class RelayTrustRootOverrideDenied extends RelaySdkError {
  static override defaultCode = RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CODE;
  static override defaultErrorClass = RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CLASS;
  static override defaultHttpStatus = 400;
  static override defaultBlockedSurface = "npx @epochly/relay sidecar";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

// -----------------------------------------------------------------------------
// Forward-compat fallback.
// -----------------------------------------------------------------------------

export class RelayUnknownError extends RelayError {
  static override defaultCode = RELAY_FUTURE_999_CODE;
  static override defaultErrorClass = "RELAY-UNKNOWN-ERROR";
  static override defaultHttpStatus = 500;
  static override defaultBlockedSurface = "relay-unknown";
  static override defaultRetryAdvice: RetryAdviceMode = "no_retry";
}

// -----------------------------------------------------------------------------
// Routing tables.
// -----------------------------------------------------------------------------

const CODE_LEAF_REGISTRY: Record<string, typeof RelayError> = {
  [RELAY_ING_031_CODE]: RelayCanonicalStatusForbidden,
  [RELAY_ING_022_CODE]: RelayHandoffIncomplete,
  [RELAY_ING_032_CODE]: RelayPolicyError,
  [RELAY_REPLAY_002_CODE]: RelayReplayPrecondition,
  [RELAY_EVID_002_CODE]: RelayEvidenceIncomplete,
  [RELAY_SIDECAR_BUNDLE_UNVERIFIED_CODE]: RelaySidecarBundleUnverified,
  [RELAY_SIDECAR_BUNDLE_DIGEST_MISMATCH_CODE]: RelaySidecarBundleDigestMismatch,
  [RELAY_SIDECAR_BUNDLE_UNAVAILABLE_CODE]: RelaySidecarBundleUnavailable,
  [RELAY_SIDECAR_BUNDLE_ARCH_UNSUPPORTED_CODE]: RelaySidecarBundleArchUnsupported,
  [RELAY_SDK_SIDECAR_LOCATOR_CODE]: RelaySidecarLocatorError,
  [RELAY_SDK_TRUST_ROOT_OVERRIDE_DENIED_CODE]: RelayTrustRootOverrideDenied,
  [RELAY_SDK_AUTH_MISMATCH_CODE]: RelaySidecarAuthError,
  [RELAY_SDK_VERSION_MISMATCH_CODE]: RelaySidecarVersionMismatch,
  [RELAY_SDK_NO_SIDECAR_CODE]: RelaySidecarNotReachable,
  [RELAY_SDK_CONFIG_CODE]: RelayConfigError,
  [RELAY_SDK_CANONICAL_STATUS_FORBIDDEN_CODE]: RelayCanonicalStatusForbidden,
  [RELAY_SDK_LIFECYCLE_INVALID_CODE]: RelayLifecycleInvalid,
  [RELAY_SDK_HANDOFF_INCOMPLETE_CODE]: RelayHandoffIncomplete,
  [RELAY_GATE_021_CODE]: RelayHandoffIncomplete,
  [RELAY_SDK_EVIDENCE_INCOMPLETE_CODE]: RelayEvidenceIncomplete,
  [RELAY_SDK_REPLAY_PRECONDITION_CODE]: RelayReplayPrecondition,
  [RELAY_SDK_POLICY_INVALID_CODE]: RelayPolicyError,
  [RELAY_SDK_SIDE_EFFECT_FIELDS_MISSING_CODE]: RelaySideEffectMissingFieldsError,
  [RELAY_SDK_REPLAY_LIVE_MODE_UNACK_CODE]: RelayReplayLiveModeUnacknowledgedError,
};

// Order matters: longest namespace prefix first.
const NAMESPACE_PREFIX_REGISTRY: ReadonlyArray<readonly [string, typeof RelayError]> = [
  ["RELAY-ING-", RelayIngestError],
  ["RELAY-AUTH-", RelayAuthError],
  ["RELAY-RATE-", RelayRateLimitError],
  ["RELAY-GATE-", RelayGateError],
  ["RELAY-EVID-", RelayEvidenceError],
  ["RELAY-REPLAY-", RelayReplayError],
  ["RELAY-SCHEMA-", RelaySchemaError],
  ["RELAY-SIDECAR-", RelaySidecarError],
  ["RELAY-SDK-", RelaySdkError],
  ["RELAY-SQLITE-", RelaySQLiteError],
];

export function resolveClassForCode(code: string): typeof RelayError {
  const leaf = CODE_LEAF_REGISTRY[code];
  if (leaf !== undefined) return leaf;
  for (const [prefix, cls] of NAMESPACE_PREFIX_REGISTRY) {
    if (code.startsWith(prefix)) return cls;
  }
  return RelayUnknownError;
}
