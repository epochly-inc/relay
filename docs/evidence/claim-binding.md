# Claim Binding

A Relay evidence claim is the atomic unit of "this happened, and here is
proof." This page explains the load-bearing rule that turns a narrative
assertion ("the tests passed") into something an auditor, a release gate,
or an offline verifier can trust: a claim must **bind** to a specific,
checkable set of artifacts. A claim that fails to bind is not a weaker
claim. It is `invalid`.

## The pairing rule (load-bearing)

The rule comes from spec §K (Evidence Claim v1 schema) and the Relay core
thesis in the spec preamble. The verbatim text:

> Pass without evidence is not a pass: every success claim must bind to
> command output, exit code, artifact hash, trace span, replay result, or
> human-approved evidence object.

The schema-level corollary, also verbatim from the spec:

> If required evidence is missing, the status is `invalid`, not `accepted`.

And the gate-level corollary, verbatim:

> A test without an exit code is pending, not passing. A claimed validation
> command without paired result is invalid. A browser/API/manual check
> without artifact hash or reviewer identity is insufficient for gate
> acceptance.

A "pass" claim therefore must carry every one of the following bindings:

- **artifact hash** -- a SHA-256 digest of the artifact the claim is about
  (a build output, a JSON document, a recorded cassette, a screenshot).
  Referenced via an `EvidenceRef` of `kind: "artifact"` with a
  `sha256-<hex>` `digest` field.
- **command + exit code** -- the exact validation command that produced
  the claim and the integer exit code it returned. Referenced via an
  `EvidenceRef` of `kind: "exit_code"` whose `ref` names the command and
  whose `value` is the integer exit code.
- **span ID list** -- the trace spans (model calls, tool calls,
  retrievals, contract evaluations) that produced the evidence. Referenced
  via `EvidenceRef` entries of `kind: "span"` whose `ref` carries the
  span identifier.
- **assertion ID list** -- the contract assertion identifiers the claim
  evidences. Referenced via `EvidenceRef` entries of `kind:
  "contract_result"` (or similar) whose `ref` names the assertion id.
- **manifest_commit_hash** -- the SHA-256 of the manifest commit that was
  in effect during evaluation. Required at two places on every claim:
  the top-level `manifest_commit_hash` field on the envelope AND the
  nested `subject.manifest_commit_hash` field. Both must match.
- **timestamp** -- `occurred_at`, an RFC 3339 datetime distinct from
  `created_at`. `occurred_at` is when the underlying event happened;
  `created_at` is when the claim row was written.
- **environment / actor binding** -- `actor_kind` (closed enum:
  `control_plane | gate_engine | worker | sdk | user | cron`) and
  `actor_identity_hash` (SHA-256). For canonical `run_result` and
  `gate_decision` claims, `actor_kind` must be `control_plane` -- per
  keystone invariant #1, only the control plane writes the result.
- **redaction_transform_version** -- the version of the redaction policy
  that produced the claim payload (e.g. `"v1.3"`). Required so that a
  later verifier can reproduce the redaction transform on the source
  data and confirm the digest still matches.

Each of these bindings is a non-optional field on `EvidenceClaim`. The
schema rejects any claim that omits one.

## Why this rule exists

This is the operational form of CLAUDE.md keystone invariant #6:
**evidence binds, narrative doesn't.** A claim that says "the tests
passed" without naming the command, exit code, and artifact is a
narrative claim. A claim that names them is a bound claim. Only bound
claims can be:

- recomputed by an offline verifier without contacting Relay,
- compared across replay runs to detect drift,
- inspected by an auditor who does not trust the producer,
- chained through Merkle inclusion proofs into a transparency log.

The spec encodes the rule three times -- in the core thesis (§ Core
thesis, point 4), in the run-result requirements (§A.1), and in the
gate-acceptance language (§ Gate restart rule). All three say the same
thing in slightly different words. The most operational form is the §A.1
clause: **"If required evidence is missing, the status is `invalid`, not
`accepted`."** An invalid claim does not partially count, does not
trigger a retry, and does not block on a future fix. It is rejected at
the schema layer and the producer must resubmit with the missing
bindings.

## Claim structure (matches source schema)

The `EvidenceClaim` JSON shape Relay validates against is defined in
`packages/schemas/python/relay_schemas/envelopes.py` (class
`EvidenceClaim`). Every field shown below corresponds to a required or
optional attribute on that class.

```json
{
  "schema_version": "relay.evidence_claim.v1",
  "evidence_claim_id": "11111111-1111-1111-1111-111111111111",
  "evidence_bundle_id": "22222222-2222-2222-2222-222222222222",
  "claim_type": "run_result",
  "subject": {
    "kind": "run",
    "id": "33333333-3333-3333-3333-333333333333",
    "manifest_commit_hash": "sha256-abc123..."
  },
  "evidence_refs": [
    {
      "kind": "run_result",
      "ref": "run_results:33333333-3333-3333-3333-333333333333",
      "digest": "sha256-def456..."
    },
    {
      "kind": "exit_code",
      "ref": "command:claim_decision_eval",
      "value": 0
    },
    {
      "kind": "artifact",
      "ref": "object://relay-evidence/sha256-789abc...",
      "digest": "sha256-789abc..."
    },
    {
      "kind": "span",
      "ref": "span:7f3a...",
      "value": null
    }
  ],
  "claim_predicate": {
    "op": "and",
    "args": [
      { "op": "run_result_status_is", "value": "accepted" },
      { "op": "gate_decision_action_is", "value": "accept" }
    ]
  },
  "claim_digest": "sha256-...",
  "redaction_transform_version": "v1.3",
  "actor_kind": "control_plane",
  "actor_identity_hash": "sha256-...",
  "occurred_at": "2026-05-22T10:00:05Z",
  "manifest_commit_hash": "sha256-abc123...",
  "signer_key_id": "kid_2026-05_relay-evidence",
  "signature": "<JWS detached>",
  "supersedes_claim_id": null,
  "namespaces": { "x-relay": { "schema_version": "v1" } },
  "created_at": "2026-05-22T10:00:07Z"
}
```

Notes on the structure:

- `schema_version` is pinned to the literal string
  `"relay.evidence_claim.v1"`. Other values fail validation.
- `claim_type` is one of the eight closed-enum values:
  `run_result | gate_decision | contract_result | replay_result |
  human_oversight | incident | data_quality_check |
  provider_compatibility`.
- `subject.kind` is one of `run | replay | eval_run | release |
  domain_pack | ai_system`.
- `subject.manifest_commit_hash` and the top-level
  `manifest_commit_hash` are both required and must agree.
- `evidence_refs[*].kind` is free-text; the verifier checks the contents
  against the bundle's manifest of digests (an artifact ref whose digest
  is not present in the bundle's manifest is a §K violation).
- `claim_predicate` is a recursive `op` / `args` tree. Depth is bounded
  at 8 nesting layers. Leaf args are op rows that carry a `value` field.
- `supersedes_claim_id` is only legal for `human_oversight` and
  `incident` claim types. It is never legal for `run_result` or
  `gate_decision` -- canonical claims cannot be superseded.

## What is NOT a valid claim

The following claim shapes are common mistakes. None of them pass
validation.

**Missing exit_code reference.** "The tests passed" with no command +
exit-code binding:

```json
{
  "claim_type": "contract_result",
  "claim_predicate": { "op": "tests_passed", "args": [] }
}
```

Result: `invalid`. The schema rejects the envelope entirely (required
fields absent), and even with the envelope completed, a gate evaluating
this claim would refuse to mark it `accepted` because no `exit_code`
ref is present.

**Missing artifact digest.** A claim that names an artifact by URL but
not by digest:

```json
{
  "evidence_refs": [
    { "kind": "artifact", "ref": "object://bucket/path", "digest": null }
  ]
}
```

Result: `invalid` for the artifact-binding rule. The bundle-validator
also rejects any artifact ref whose digest is not in the bundle's
digest manifest (a spec §K rule).

**Worker-written canonical claim.** A `run_result` claim with
`actor_kind: "worker"`:

```json
{
  "claim_type": "run_result",
  "actor_kind": "worker"
}
```

Result: `invalid` per keystone invariant #1. Canonical `run_result` and
`gate_decision` claims must carry `actor_kind: "control_plane"`. A
worker or SDK that attempts to write a canonical status receives
`RELAY-ING-031` at ingest.

**Mismatched manifest hashes.** A claim whose top-level
`manifest_commit_hash` does not match `subject.manifest_commit_hash`:

```json
{
  "manifest_commit_hash": "sha256-aaa...",
  "subject": { "manifest_commit_hash": "sha256-bbb..." }
}
```

Result: `invalid`. The three-anchor handoff rule (spec §C.5) requires
the manifest commit hash to bind unambiguously to one value across the
claim.

**Browser / manual check without reviewer identity.** A human-oversight
claim that says "I reviewed it" without an `actor_identity_hash`:

```json
{
  "claim_type": "human_oversight",
  "actor_kind": "user"
}
```

Result: `invalid`. The spec's gate-acceptance language ("a browser/API/
manual check without artifact hash or reviewer identity is insufficient
for gate acceptance") is the operative rule.

**Missing redaction_transform_version.** A claim that names redacted
content but does not carry the redaction policy version used:

```json
{
  "evidence_refs": [
    { "kind": "artifact", "ref": "...", "digest": "sha256-..." }
  ]
}
```

Result: `invalid`. Without the redaction version, a later verifier
cannot reproduce the transform deterministically and the digest is no
longer independently verifiable.

## What happens to invalid claims

An `invalid` claim has three concrete consequences:

1. The envelope fails Pydantic validation at the schema boundary; the
   claim is never persisted.
2. If a producer attempts to submit a malformed canonical claim through
   the ingest API, the control plane returns a structured error code
   (typically `RELAY-ING-031` for canonical-status writes from a
   non-control-plane actor).
3. A bundle that contains a structurally invalid claim fails offline
   verification; the verifier reports the specific binding that was
   missing rather than silently passing the bundle through.

The remediation in every case is the same: collect the missing binding
(exit code, digest, span id, manifest hash, redaction policy version)
and resubmit. There is no "accept with warnings" path.

## See also

- [Bundle anatomy](bundle-anatomy.md) -- how individual claims compose
  into a signed, Merkle-anchored evidence bundle.
- [Trust anchor](trust-anchor.md) -- which JWKS the verifier uses to
  validate the signatures that protect these claims.
- [Offline verification](offline-verification.md) -- the
  `rly evidence verify` walkthrough that exercises the full claim-
  binding chain end-to-end.

Spec: §K
