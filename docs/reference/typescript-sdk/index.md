# TypeScript SDK reference (`@epochly/relay`)

> Generated from packages/sdk-typescript/src/index.ts. Do not edit by hand.

This page enumerates every named export from
`packages/sdk-typescript/src/index.ts` (the W4.1 snapshot-frozen public
surface, pinned by `packages/sdk-typescript/.api/v0.1.snapshot.json`).
Any unintended addition or removal of a named export fails the snapshot
test in CI.

**Import side effects:** `import '@epochly/relay'` (ESM) and
`require('@epochly/relay')` (CJS) MUST NOT spawn a sidecar process,
touch the sidecar lockfile, bind a port, or make an HTTP request
(VAL-W4-001b). All side effects are deferred to the first SDK
operation that needs the sidecar.

## Client

### `class Relay`

```ts
class Relay {
  constructor(projectKey: unknown, options?: RelayOptions);
  readonly projectKey: string;
  readonly relayHome: string | undefined;
  trace(name: string): Promise<TraceHandle>;
  close(): void;
}
```

The Relay SDK client. Construction validates `projectKey` synchronously
and resolves configuration -- no sidecar spawn, no lockfile touch, no
HTTP call. Per VAL-W4-002 the SDK reads the sidecar lockfile from
`${RELAY_HOME:-os.homedir()/.relay}/sidecar.lock` AND ONLY there;
setting `RELAY_SIDECAR_URL` without `RELAY_ALLOW_EXPLICIT_SIDECAR=1`
(the test-mode escape hatch) is refused.

### `function trace(name, options?)`

```ts
function trace(name: string, options?: RelayOptions): Promise<TraceHandle>;
```

Top-level convenience: equivalent to constructing a `Relay` client and
calling `Relay.trace`. The project key is taken from the
`RELAY_PROJECT_KEY` env var; an invalid or missing key raises
`RelayConfigError`.

## Error hierarchy

All Relay errors descend from `RelayError`. The four envelope subclasses
named below correspond to the W4 wire codes `RELAY-ING-031`,
`RELAY-ING-022`, `RELAY-REPLAY-002`, and `RELAY-EVID-002`.

### Base class

#### `class RelayError extends Error`

The root of the Relay error hierarchy. Carries `code`, `errorClass`,
`httpStatus`, `blockedSurface`, `retryAdvice`, `requestId`, `traceId`,
`documentationUrl`, and `details`. Exposes `toEnvelope()` and the
static `fromEnvelope(envelope)` factory used by the SDK transport to
deserialize wire errors.

### Four envelope subclasses (per VAL-W4-001)

#### `class RelayCanonicalStatusForbidden extends RelayIngestError`
Wire code `RELAY-ING-031`. The SDK or agent attempted to set
`run_results.status` directly. The control plane is the sole writer of
canonical run status (CLAUDE.md keystone invariant #1).

#### `class RelayHandoffIncomplete extends RelayIngestError`
Wire code `RELAY-ING-022`. The three-anchor handoff is missing one of
`scope_id`, `actor_identity_hash`, or `manifest_commit_hash` (CLAUDE.md
keystone invariant #4).

#### `class RelayReplayPrecondition extends RelayReplayError`
Wire code `RELAY-REPLAY-002`. A replay was requested but its
precondition (cassette presence, side-effect policy, or sandbox state)
was not satisfied.

#### `class RelayEvidenceIncomplete extends RelayEvidenceError`
Wire code `RELAY-EVID-002`. An evidence bundle is missing one of the
required pairings (artifact hash, command, exit code, span IDs,
assertion IDs, manifest hash).

### Namespace intermediates

These are the parent classes the typed leaves extend; advanced callers
can match the broader category in a single `catch`.

#### `class RelayIngestError extends RelayError`
Ingest-surface parent. Default HTTP status 400, default
`blockedSurface` value identifies the ingest endpoint
(`/v1/ingest/runs`).

#### `class RelayAuthError extends RelayError`
Auth-failure parent. Default HTTP status 401.

#### `class RelayRateLimitError extends RelayError`
Rate-limit parent. Default HTTP status 429 with
`retryAdvice: "after_retry_after"`.

#### `class RelayGateError extends RelayError`
Gate-surface parent. Default HTTP status 404, default
`blockedSurface` value identifies the gate-draft endpoint
(`/v1/gates/{gate_id}/drafts`).

#### `class RelayEvidenceError extends RelayError`
Evidence-surface parent. Default HTTP status 422, default
`blockedSurface` value identifies the evidence endpoint
(`/v1/evidence`).

#### `class RelayReplayError extends RelayError`
Replay-surface parent. Default HTTP status 422, default
`blockedSurface` value identifies the replay endpoint
(`/v1/runs/{run_id}/replays`).

#### `class RelaySchemaError extends RelayError`
Schema-validation parent. Default HTTP status 422.

#### `class RelaySidecarError extends RelayError`
Sidecar-transport parent. Default HTTP status 503,
`retryAdvice: "after_state_change"`.

#### `class RelaySdkError extends RelayError`
Client-side SDK parent. Default HTTP status 400, default
`blockedSurface: "relay-sdk"`.

#### `class RelaySQLiteError extends RelayError`
Local sidecar SQLite parent. Default HTTP status 500.

### Transport / sidecar typed leaves

#### `class RelayConfigError extends RelaySdkError`
Wire code `RELAY-SDK-001`. SDK configuration failure (invalid project
key, invalid trace name, missing `RELAY_PROJECT_KEY` env var when using
the top-level `trace(...)` convenience).

#### `class RelaySidecarNotReachable extends RelaySidecarError`
Wire code `RELAY-SDK-003`. The sidecar lockfile was not found, the
process is not running, or `GET /health` did not respond.

#### `class RelaySidecarVersionMismatch extends RelaySidecarError`
Wire code `RELAY-SDK-002`. The sidecar reported a version the client
SDK does not support.

#### `class RelaySidecarAuthError extends RelayAuthError`
Wire code `RELAY-SDK-004`. The sidecar bearer-token digest handshake
(VAL-W4-003) failed; the SDK's locally cached digest does not match the
running sidecar's digest.

#### `const RelayAuthMismatch = RelaySidecarAuthError`
Python-parity alias for `RelaySidecarAuthError`. Re-exported as both a
runtime value and a type.

### Adversarial canonical-write subclass

#### `class RelayControlPlaneOwnershipError extends RelayCanonicalStatusForbidden`
Distinct typed leaf for the W4 adversarial canonical-write tests
(VAL-W4-010). Carries `forged_field` through the `details` map.

### W4.2 lifecycle typed leaves

#### `class RelayLifecycleInvalid extends RelaySdkError`
Wire code `RELAY-SDK-006`. The SDK rejected an invalid lifecycle
transition before any HTTP call.

#### `class RelayPolicyError extends RelayIngestError`
Wire code `RELAY-SDK-010`. Policy schema or invariant violation
detected client-side.

#### `class RelaySideEffectMissingFieldsError extends RelaySdkError`
Wire code `RELAY-SDK-014`. A `side_effect: true` tool_call span was
opened without both `idempotencyKey` and `replayPolicy` (CLAUDE.md
keystone invariant #6). The span never reaches the control plane.

#### `class RelayReplayLiveModeUnacknowledgedError extends RelaySdkError`
Wire code `RELAY-SDK-015`. Live replay was requested without
`acknowledgeDegradedApproximation: true`. Live mode is a degraded
approximation per CLAUDE.md keystone invariant #9.

### W4.3 redaction typed leaves

#### `class RelayRedactionPolicyError extends RelayPolicyError`
Wire code `RELAY-SDK-010`, error class `RELAY-SDK-REDACTION-POLICY`.
Redaction policy parse error fails closed (VAL-W4-024). The SDK refuses
to open any spans when this is raised.

#### `class RelayRedactionRawCaptureDeniedError extends RelayRedactionPolicyError`
Wire code `RELAY-SDK-016`. The caller asked for `raw_capture: true`
without supplying both `dpa_ref` and `approver_user_id` (VAL-W4-022;
CLAUDE.md keystone invariant #7 + banned pattern #11). Raised
synchronously before any HTTP call.

### W4.5 adapter + replay-mode typed leaves

#### `class RelayReplayEgressDeniedError extends RelayReplayError`
Wire code `RELAY-REPLAY-EGRESS-DENIED`. The replay-mode undici
interceptor refused a non-loopback outbound connection (VAL-W4-035).

#### `class RelayReplayProxyMissingError extends RelayReplayError`
Wire code `RELAY-REPLAY-PROXY-MISSING`. Replay-mode initialization
detected `RELAY_REPLAY=1` with an unset `HTTPS_PROXY` env var
(VAL-W4-036).

#### `class RelaySdkUninstrumentedHttpClientError extends RelaySdkError`
Wire code `RELAY-SDK-UNINSTRUMENTED-HTTP-CLIENT`. Replay-mode init
detected an uninstrumented HTTP client module (`got`, `request`,
`node-fetch`, raw `undici`, or `axios` without the Relay adapter)
(VAL-W4-036b). The `details` map carries `client_name`.

#### `class RelayAdapterUnsupportedVersionError extends RelaySdkError`
Wire code `RELAY-SDK-ADAPTER-VERSION-UNSUPPORTED`. The adapter
constructor refused to wrap an out-of-range provider SDK version
(VAL-W4-040). The `details` map carries observed and supported version
strings.

### Sidecar-bundle (`npx @epochly/relay sidecar`) typed leaves

#### `class RelaySidecarBundleUnverified extends RelaySidecarError`
Wire code `RELAY-SIDECAR-020`. The npx-distributed sidecar bundle
failed signature verification.

#### `class RelaySidecarBundleDigestMismatch extends RelaySidecarError`
Wire code `RELAY-SIDECAR-021`. The downloaded bundle's content digest
did not match the manifest's pinned digest.

#### `class RelaySidecarBundleUnavailable extends RelaySidecarError`
Wire code `RELAY-SIDECAR-022`. No bundle is available for the current
platform / channel.

#### `class RelaySidecarBundleArchUnsupported extends RelaySidecarError`
Wire code `RELAY-SIDECAR-023`. The current CPU architecture is not in
the bundle's supported set.

#### `class RelaySidecarLocatorError extends RelaySdkError`
Wire code `RELAY-SDK-011`. The SDK could not resolve which sidecar
binary to invoke (missing bundle, missing lockfile, malformed
discriminator).

#### `class RelayTrustRootOverrideDenied extends RelaySdkError`
Wire code `RELAY-SDK-012`. A caller attempted to override the
sidecar-bundle trust root without the documented escape hatch (CLAUDE.md
keystone invariant #13: changing the OSS default trust anchor is a
board-level decision, not a routine flag flip).

### Forward-compat fallback

#### `class RelayUnknownError extends RelayError`
Wire code `RELAY-FUTURE-999`. Any wire code the SDK does not recognise
deserializes to this class (VAL-W4-030). The SDK also emits a structured
warning to stderr in the `relay.error.v1` shape so operators have a
paper trail of every unrecognised code seen.

### Error supporting types

#### `type RetryAdvice`
Object literal describing the suggested retry strategy: `mode` plus
mode-specific fields (delay, condition).

#### `type RetryAdviceMode`
String-literal union: `"no_retry"`, `"after_retry_after"`,
`"after_state_change"`, or `"backoff_with_jitter"`.

#### `type ErrorEnvelopeWire`
Wire-format envelope shape consumed by `RelayError.fromEnvelope` and
produced by `RelayError.toEnvelope`. Mirrors the `relay.sdk_error.v1`
schema field-for-field.

#### `type RelayErrorOptions`
Options bag accepted by `RelayError`'s constructor: `code`,
`httpStatus`, `blockedSurface`, `retryAdvice`, `requestId`, `traceId`,
`documentationUrl`, `details`, `cause`.

## Redaction

#### `const RedactionPolicy`

```ts
const RedactionPolicy: Readonly<{
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
}>;
```

Frozen runtime namespace for the redaction surface. `parse` builds a
validated policy from a wire dict; `createEngine` returns a redactor
bound to the policy and a salt provider; `redactPayload` is the
canonical JCS-bytes entry point used by the SDK transport before any
HTTP body leaves the process (VAL-W4-019, VAL-W4-020, VAL-W4-021).
Calling `parse` on a policy that requests `raw_capture: true` without
both `dpa_ref` and `approver_user_id` throws
`RelayRedactionRawCaptureDeniedError` synchronously (VAL-W4-022;
CLAUDE.md keystone invariant #7).

#### `interface RedactionPolicyShape`

Readonly v0.1 wire shape: `schema_version` (literal
`"relay.redaction_policy.v1"`), `policy_version` (string),
`raw_capture` (boolean), `applies_to_fields` (readonly string array),
`rules` (readonly array of `{id, match, action: "drop" | "mask" |
"hash", salt_ref?}`). Full schema bound at W4.3 from
`packages/schemas/raw/redaction-policy.default.v1.yaml`.

## Contract result

#### `const ContractResult`

```ts
const ContractResult: Readonly<{
  readonly SCHEMA_VERSION: "relay.contract_result.v1";
  readonly DECISIONS: ReadonlyArray<"accepted" | "rejected" | "invalid" | "pending">;
}>;
```

Frozen runtime namespace exposing the canonical schema-version constant
and the `accepted | rejected | invalid | pending` decision-enum. The
full reader surface (parse, decision predicates) lands additively in
W4.2.

#### `type ContractResultShape`

Discriminated union over the four decision states. Every shape carries
`schema_version: "relay.contract_result.v1"`, `decision`, `scope_id`,
and `written_by: "control_plane"` (CLAUDE.md keystone invariant #1: the
SDK never writes the canonical row, only reads it). The `accepted`
shape adds `accepted_at` and `evidence_count`; `rejected` and `invalid`
add `primary_failure_class` and `failure_reason`; `pending` has no
extra fields.

## Adapters

#### `const Adapters`

```ts
const Adapters: Readonly<Record<string, unknown>>;
```

Frozen namespace placeholder for the W4.5 adapter packages (OpenAI,
Anthropic, Vercel AI SDK, LangChain, MCP). The W4.1 snapshot fixes
`Adapters` as a frozen namespace with no leaves so the snapshot is
stable across early imports; W4.5 attaches its leaves additively.

## Trace handle

#### `interface TraceHandle`

```ts
interface TraceHandle {
  readonly name: string;
  readonly baseUrl: string;
  readonly port: number;
  readonly pid: number;
  readonly sidecarVersion: string;
  readonly bearerTokenDigest: string;
  readonly authHeader: string;
  readonly spawned: boolean;
}
```

Minimal W4.1 handle returned by `Relay.trace()` and `trace()`,
exposing the live sidecar connection coordinates plus the validated
trace name. The W4.2 lifecycle Run envelope attaches richer span APIs
on top of this handle additively.

---

## Regenerating this page

```bash
bash scripts/docs/build-typescript-reference.sh
```

The wrapper invokes `npx typedoc --plugin typedoc-plugin-markdown`
against `packages/sdk-typescript/src/index.ts`. If `npx` is not
available, the script exits 0 with a `[SKIP]` notice so CI on machines
without Node still passes.

Spec: §A.5, §H
