/**
 * Shared public type stubs for the v0.1 SDK surface (W4.1).
 *
 * The full implementations for redaction (W4.3), contract / gate-evaluate
 * lifecycle results (W4.2), and adapter packages (W4.5) land in their own
 * sub-features. W4.1 ships the type alias names and zero-implementation
 * placeholder values that the public package surface (VAL-W4-001) is
 * required to export. Each stub MUST type-check today, MUST NOT trigger
 * any sidecar spawn, and MUST be safely overridable by the later
 * sub-features without breaking the snapshot at v0.1.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

/**
 * RedactionPolicy v0.1 surface (full schema implemented by W4.3).
 *
 * The actual schema lives at packages/schemas/raw/redaction.policy.v1.yaml
 * and gets bound at W4.3. For W4.1 we ship both:
 *   1. A type alias :type:`RedactionPolicyShape` carrying the wire shape so
 *      callers can declare typed parameters today.
 *   2. A runtime value :const:`RedactionPolicy` exposing the canonical
 *      schema-version constant and a parse stub that throws
 *      :class:`RelayPolicyError` so any W4.1-era caller who tries to
 *      construct a real policy gets a typed error rather than a silently
 *      half-built object. W4.3 replaces the parse stub with the real
 *      redaction-engine factory while keeping the same export name.
 */
export interface RedactionPolicyShape {
  readonly schema_version: "relay.redaction_policy.v1";
  readonly policy_version: string;
  readonly raw_capture: boolean;
  readonly applies_to_fields: ReadonlyArray<string>;
  readonly rules: ReadonlyArray<{
    readonly id: string;
    readonly match: string;
    readonly action: "drop" | "mask" | "hash";
    readonly salt_ref?: string;
  }>;
}

/**
 * Public ``RedactionPolicy`` namespace (widened by W4.3).
 *
 * Frozen runtime object; the snapshot test pins ``RedactionPolicy`` as a
 * named export. Now exposes the W4.3 factory surface alongside the W4.1
 * SCHEMA_VERSION constant: ``parse`` builds a validated policy from a
 * wire dict, ``createEngine`` returns a redactor bound to the policy and
 * a salt provider, ``redactPayload`` is the canonical JCS-bytes entry
 * point used by the SDK transport before any HTTP body leaves the
 * process (VAL-W4-019, VAL-W4-020, VAL-W4-021).
 *
 * Calling ``parse`` on a policy that requests ``raw_capture: true``
 * without both ``dpa_ref`` and ``approver_user_id`` throws
 * :class:`RelayRedactionRawCaptureDeniedError` synchronously
 * (VAL-W4-022, CLAUDE.md banned pattern #11).
 */
import {
  loadRedactionPolicy,
  redactCapturePayload,
  RedactionEngine,
  type RedactionPolicyImpl,
  type SaltProvider,
} from "./redaction.js";

export const RedactionPolicy: Readonly<{
  readonly SCHEMA_VERSION: "relay.redaction_policy.v1";
  readonly parse: (body: unknown) => RedactionPolicyImpl;
  readonly createEngine: (args: {
    policy: RedactionPolicyImpl;
    saltProvider: SaltProvider;
  }) => RedactionEngine;
  readonly redactPayload: (
    engine: RedactionEngine,
    payload: Record<string, unknown>,
  ) => Uint8Array;
}> = Object.freeze({
  SCHEMA_VERSION: "relay.redaction_policy.v1" as const,
  parse: loadRedactionPolicy,
  createEngine: (args: { policy: RedactionPolicyImpl; saltProvider: SaltProvider }) =>
    new RedactionEngine(args),
  redactPayload: redactCapturePayload,
});

/**
 * Public namespace placeholder for the W4.5 adapter packages.
 *
 * The OpenAI, Anthropic, Vercel AI SDK, LangChain, and MCP adapter
 * surfaces land in W4.5. The W4.1 contract snapshot fixes ``Adapters`` as
 * a frozen namespace object with no exported leaves so the snapshot is
 * stable across early imports; W4.5 attaches its leaves additively.
 */
export const Adapters: Readonly<Record<string, unknown>> = Object.freeze({});

/**
 * Public result shape returned by gate evaluation, contract publish, and
 * evidence submit calls (full surface implemented in W4.2).
 *
 * W4.1 ships a discriminated-union shape that captures the canonical
 * accepted / rejected / invalid / pending decision states. The control
 * plane is the sole writer of ``decision`` (keystone invariant #1); the
 * SDK only reads it.
 */
export type ContractResultShape =
  | {
      readonly schema_version: "relay.contract_result.v1";
      readonly decision: "accepted";
      readonly scope_id: string;
      readonly written_by: "control_plane";
      readonly accepted_at: string;
      readonly evidence_count: number;
    }
  | {
      readonly schema_version: "relay.contract_result.v1";
      readonly decision: "rejected";
      readonly scope_id: string;
      readonly written_by: "control_plane";
      readonly primary_failure_class: string;
      readonly failure_reason: string;
    }
  | {
      readonly schema_version: "relay.contract_result.v1";
      readonly decision: "invalid";
      readonly scope_id: string;
      readonly written_by: "control_plane";
      readonly primary_failure_class: string;
      readonly failure_reason: string;
    }
  | {
      readonly schema_version: "relay.contract_result.v1";
      readonly decision: "pending";
      readonly scope_id: string;
      readonly written_by: "control_plane";
    };

/**
 * Public ``ContractResult`` namespace.
 *
 * Frozen runtime object exposing canonical schema-version and
 * decision-enum constants. The full reader surface (parse, decision
 * predicates) lands additively in W4.2.
 */
export const ContractResult: Readonly<{
  readonly SCHEMA_VERSION: "relay.contract_result.v1";
  readonly DECISIONS: ReadonlyArray<"accepted" | "rejected" | "invalid" | "pending">;
}> = Object.freeze({
  SCHEMA_VERSION: "relay.contract_result.v1" as const,
  DECISIONS: Object.freeze(["accepted", "rejected", "invalid", "pending"] as const),
});

/**
 * Top-level trace handle returned by ``relay.trace(...)`` (W4.1 surface).
 *
 * W4.1 returns a minimal handle exposing the live sidecar connection
 * coordinates plus the validated trace name. The W4.2 lifecycle Run
 * envelope attaches richer span APIs on top of this handle additively.
 */
export interface TraceHandle {
  readonly name: string;
  readonly baseUrl: string;
  readonly port: number;
  readonly pid: number;
  readonly sidecarVersion: string;
  readonly bearerTokenDigest: string;
  readonly authHeader: string;
  readonly spawned: boolean;
}
