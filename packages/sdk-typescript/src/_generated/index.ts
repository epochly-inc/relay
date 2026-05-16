/* GENERATED FILE - DO NOT EDIT BY HAND.
 *
 * Source: packages/schemas/raw/openapi.yaml (W1.5 OpenAPI 3.1 source-of-truth).
 * Regenerate: uv run python packages/schemas/scripts/codegen.py
 * Drift check: uv run python scripts/check-codegen-drift.py
 */

/**
 * Named-export surface for VAL-W1-034:
 *
 *   import { RunResult, GateDecision, EvidenceBundle, ReplayFixture, ErrorEnvelope }
 *     from "./index";
 *
 * Each named export is a type alias for components["schemas"]["<Name>"] from
 * the openapi-typescript output. Re-exporting as named types keeps the
 * fixture file ergonomic and decouples it from the openapi-typescript
 * internal `paths`/`webhooks` envelope.
 */

import type { components } from "./schemas.js";

export type RunResult = components["schemas"]["RunResult"];
export type GateDecision = components["schemas"]["GateDecision"];
export type GateDecisionDraft = components["schemas"]["GateDecisionDraft"];
export type GateRound = components["schemas"]["GateRound"];
export type ManifestVersion = components["schemas"]["ManifestVersion"];
export type ScopeState = components["schemas"]["ScopeState"];
export type IdempotencyRecord = components["schemas"]["IdempotencyRecord"];
export type EventLogEntry = components["schemas"]["EventLogEntry"];
export type EvidenceBundle = components["schemas"]["EvidenceBundle"];
export type EvidenceClaim = components["schemas"]["EvidenceClaim"];
export type ReplayCase = components["schemas"]["ReplayCase"];
export type ReplayFixture = components["schemas"]["ReplayFixture"];
export type RedactionPolicy = components["schemas"]["RedactionPolicy"];
export type ErrorEnvelope = components["schemas"]["ErrorEnvelope"];
export type Actor = components["schemas"]["Actor"];
export type RunScopeState = components["schemas"]["RunScopeState"];
export type ReplayCaseScopeState = components["schemas"]["ReplayCaseScopeState"];
export type GateRoundScopeState = components["schemas"]["GateRoundScopeState"];
export type EvidenceBundleScopeState = components["schemas"]["EvidenceBundleScopeState"];
export type RedactionPolicyMatcher = components["schemas"]["RedactionPolicyMatcher"];

export { FIELD_ALIASES_BY_ENVELOPE, snakeToCamel, camelToSnake } from "./aliases.js";
export { RelayUnknownSchemaVersionError, parseEnvelope } from "./errors.js";

// Canonical envelope name list for VAL-W1-032 coverage assertions.
export const CANONICAL_ENVELOPES = [
  "RunResult",
  "GateDecision",
  "GateDecisionDraft",
  "GateRound",
  "ManifestVersion",
  "ScopeState",
  "IdempotencyRecord",
  "EventLogEntry",
  "EvidenceBundle",
  "EvidenceClaim",
  "ReplayCase",
  "ReplayFixture",
  "RedactionPolicy",
  "ErrorEnvelope",
  "GatePolicy",
  "ContractResult",
  "AssertionDefinition",
  "ReplayResult",
  "Manifest",
  "Incident",
  "RootCauseHypothesis",
  "Span",
  "ModelCallSpan",
  "ToolCallSpan",
  "RetrievalSpan",
  "EmbeddingSpan",
  "EvidenceLegalHold",
  "EvidenceBundleRegistry"
] as const;

export type CanonicalEnvelopeName = (typeof CANONICAL_ENVELOPES)[number];
