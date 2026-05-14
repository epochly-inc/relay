/**
 * @epochly/relay public package surface (W4.1).
 *
 * Per VAL-W4-001 the named exports here are snapshot-frozen against
 * ``packages/sdk-typescript/.api/v0.1.snapshot.json``. Any unintended
 * addition or removal of a named export fails the snapshot test and is
 * caught in CI.
 *
 * IMPORT SIDE EFFECTS:
 *   ``import '@epochly/relay'`` (ESM) and ``require('@epochly/relay')``
 *   (CJS) MUST NOT:
 *     - spawn a sidecar process
 *     - touch the sidecar lockfile
 *     - bind any port
 *     - make any HTTP request
 *   (VAL-W4-001b). All side effects are deferred to the first SDK
 *   operation that needs the sidecar.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

export { Relay, trace } from "./client.js";

// Error hierarchy: the base class plus the four W4 wire-code typed leaves
// (the "four error-envelope subclasses" referenced by VAL-W4-001) and the
// transport-layer typed leaves the W4.1 surface raises directly. The full
// hierarchy lives in ./errors.ts and is re-exported via the namespace
// import below for advanced callers (the snapshot pins only the
// flat-named exports).
export {
  RelayError,
  // The four error-envelope subclasses per VAL-W4-001 cross-reference --
  // the wire codes RELAY-ING-031, RELAY-ING-022, RELAY-REPLAY-002,
  // RELAY-EVID-002 each map to a single typed leaf.
  RelayCanonicalStatusForbidden,
  RelayHandoffIncomplete,
  RelayReplayPrecondition,
  RelayEvidenceIncomplete,
  // Namespace intermediates -- the parent classes the four leaves extend.
  RelayIngestError,
  RelayAuthError,
  RelayRateLimitError,
  RelayGateError,
  RelayEvidenceError,
  RelayReplayError,
  RelaySchemaError,
  RelaySidecarError,
  RelaySdkError,
  RelaySQLiteError,
  // Transport / sidecar typed leaves exercised by W4.1.
  RelayConfigError,
  RelaySidecarNotReachable,
  RelaySidecarVersionMismatch,
  RelaySidecarAuthError,
  RelayAuthMismatch,
  // Adversarial canonical-write subclass (VAL-W4-010 surface).
  RelayControlPlaneOwnershipError,
  // W4.2 lifecycle typed leaves.
  RelayLifecycleInvalid,
  RelayPolicyError,
  RelaySideEffectMissingFieldsError,
  RelayReplayLiveModeUnacknowledgedError,
  // W4.3 redaction typed leaves (VAL-W4-022, VAL-W4-024).
  RelayRedactionPolicyError,
  RelayRedactionRawCaptureDeniedError,
  // Sidecar-bundle (npx wrapper) typed leaves.
  RelaySidecarBundleUnverified,
  RelaySidecarBundleDigestMismatch,
  RelaySidecarBundleUnavailable,
  RelaySidecarBundleArchUnsupported,
  RelaySidecarLocatorError,
  RelayTrustRootOverrideDenied,
  // Forward-compat fallback.
  RelayUnknownError,
} from "./errors.js";

export type {
  RetryAdvice,
  RetryAdviceMode,
  ErrorEnvelopeWire,
  RelayErrorOptions,
} from "./errors.js";

// Public runtime + type surface whose implementations widen additively in
// sibling W4 features:
//   RedactionPolicy -> W4.3 (redaction engine + policy schema binding)
//   ContractResult  -> W4.2 (lifecycle / gate-evaluate read surface)
//   Adapters        -> W4.5 (per-provider adapter packages)
// W4.1 commits the names; later features extend these objects without
// breaking the v0.1 snapshot.
export { RedactionPolicy, ContractResult, Adapters } from "./types.js";
export type { RedactionPolicyShape, ContractResultShape, TraceHandle } from "./types.js";
