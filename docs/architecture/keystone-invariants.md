# Keystone Invariants

## Why invariants

Relay's invariants are the load-bearing rules that distinguish it from generic
observability or trace-export tooling. They are not stylistic preferences and
they are not negotiable per release. Each invariant is enforced by code, by
guard tests, and by reviewer discipline, and each is tied back to a specific
section of the spec. Violating any of them in code is a P0 bug. This page
restates the 16 invariants in user-facing language so that a developer, an
SRE, a compliance officer, or an auditor can read Relay's behavior at the
contract level and understand why a particular response, exit code, or
evidence claim shape is what it is.

## The 16 invariants

### #1 The control plane writes the result

The canonical outcome of a run — the row in `run_results` and any
`gate_decisions` row produced from it — is written only by Relay's control
plane services. SDKs, agents, eval runners, and replay workers submit
**evidence** (draft envelopes with lifecycle metadata) but never the
canonical pass/fail verdict. In practice this is why your SDK call returns
a `pending` status until the gate finishes writing the result, and why a
direct attempt to mark a run `accepted` from your code is rejected with
`RELAY-ING-031`. The control plane owns the verdict; clients own the
evidence.

Spec: §A.1, §A.2.

### #2 Pass without evidence is not a pass

Every success claim that Relay records binds to a specific evidence
fingerprint: artifact hash, the exact command and exit code that produced
it, the trace span IDs that observed it, the contract assertion IDs it
satisfies, the agent or worker identity, the manifest commit hash, the
timestamp, the environment, and the active redaction policy version. A
claim that is missing any of these fields is recorded as `invalid`, not
`accepted`. In practice this is why "the test passed" in your terminal is
not enough on its own — the evidence bundle is what makes the pass
durable, auditable, and re-verifiable offline.

Spec: §K, §X.

### #3 Manifest is the source of truth

The manifest is the contract between you and the gate runner. Workers only
execute commands that the manifest declares, matched by `command_hash`. The
sidecar only kills ports that the manifest names (by declared port and
recorded PID) — never by process name. Tests are discovered with the globs
the manifest specifies, not by filename heuristics. Side-effect tools
declare their idempotency class and replay policy in the manifest, not at
call time. In practice this is why every Relay run is reproducible from
the manifest alone: there is no hidden environment state and no
out-of-band command that the gate runner is willing to execute.

Spec: §F.

### #4 Three-anchor handoff

Every handoff between stages of the pipeline carries three anchors
together: `scope_id`, `actor_identity_hash`, and `manifest_commit_hash`.
The receiving stage rejects the handoff if any anchor is stale (wrong
run, revoked actor identity, mismatched manifest) with `RELAY-GATE-021`
or an equivalent scope-specific code. There is no fallback path that
accepts a partial handoff. In practice this is why bumping your manifest
mid-run produces a clean error instead of a half-evidenced result, and
why CI submissions made from a forked branch with no project token are
treated as a different actor than the parent repo.

Spec: §C.5.

### #5 Gate restart on failure

If a later gate fails (for example, a testing gate after a scrutiny gate
has already passed), Relay does not retry only the failing gate. It
injects remediation and restarts the pipeline from the earliest gate
(scrutiny), because the fix that satisfies the late gate may invalidate
assumptions earlier gates made. A circuit breaker trips after
`remediation_round_cap` (default 5) rounds and the run goes to
`stalled` with `gate.stalled` recorded in `gate_rounds`. In practice
this is why your remediation commit reruns the full validation pipeline
rather than just the failing check.

Spec: §C, "Gate restart rule".

### #6 Side-effect idempotency

Tools that produce side effects (write to a database, charge a card,
send an email) must publish a pre-action marker before the side effect
runs and a post-success proof after it succeeds. Replay refuses to
execute a tool whose `side_effect_class` is `mutating` or
`external_irreversible` without an explicit, audited policy override.
In practice this is why replay-mode debugging of a payment flow plays
back the recorded response rather than re-charging the card, and why
adding a new side-effect tool requires you to declare its idempotency
class in the manifest before Relay will run it.

Spec: §X.

### #7 Default-deny raw capture

Hosted Relay does not persist raw prompts, raw outputs, raw tool
arguments, or raw retrieval documents unless the active redaction policy
explicitly enables `raw_capture`, references a signed data processing
agreement (DPA), and records an org-admin approver on that policy
version. By default only redacted projections, hashes, and structural
metadata are stored. In practice this is why an out-of-the-box Relay
install never leaks user PII into the evidence registry, and why
enabling raw capture requires a deliberate, auditable workflow rather
than a configuration flag flip.

Spec: §G.

### #8 Atomic persistence — four primitives only

All durable writes go through one of four atomic-persistence primitives:
`transactional_db_write`, `object_put_with_digest`,
`queue_publish_with_idempotency`, or `local_atomic_file_write` (with
the OSS sidecar adding `local_two_layer_locked_write` and
`acquire_or_attach` for cross-process coordination). Business logic does
not call low-level database, object-store, queue, or file-write APIs
directly. A CI lint enforces this. In practice this is why Relay's
durability story is the same on every backend — Postgres, R2, Cloudflare
Queues, and SQLite all converge on the same four-primitive contract —
and why partial writes, lost updates, and torn files do not happen even
under crash or concurrent-writer conditions.

Spec: §H.

### #9 Cassette-first replay

The default mode for replaying a run is cassette playback against
recorded provider responses, not live re-execution against the live
provider. Live replay is treated as a degraded approximation: it is
permitted, but the resulting evidence is explicitly marked as such, and
the replay sandbox enforces default-deny network egress so accidental
live calls cannot happen. In practice this is why your replay of
yesterday's incident produces the same provider output you saw at the
time, and why switching to live mode requires both an explicit flag and
acceptance of the degraded-evidence marker.

Spec: §E.

### #10 Schema versioning on every canonical envelope

Every persisted Relay object — manifest, redaction policy, evidence
bundle, run result, gate decision, contract — carries a
`schema_version` field. Engines refuse to write objects with unknown
versions and refuse to silently coerce shapes across version
boundaries. In practice this is why upgrading Relay never silently
rewrites your old evidence bundles, and why downgrading is a controlled
operation rather than a guess.

Spec: §B.7.

### #11 Trust anchor is the commercial moat

Every evidence bundle Relay issues carries a `trust_anchor` field that
identifies the JWKS that produced the bundle's signature. The OSS
verifier ships with a default trust anchor of
`https://relay.epochly.com/.well-known/jwks.json`, and the transparency
log behind that anchor is publicly readable and Merkle-verifiable
offline. Changing the OSS verifier's default trust anchor is a
board-level decision, not a routine pull request. Trust-anchor key
material (signing keys, TSA contracts, transparency-log custody) lives
only in the private hosted plane; the Apache 2.0 grant covers code, not
keys. In practice this is why an offline auditor can verify a Relay
bundle against a cached JWKS with no network access, and why
self-hosters can bring their own trust anchor via the `--trust-anchor`
flag without forking the verifier.

Spec: §AO.

### #12 Live replay against irreversible side effects is gated

Replay against tools classified as `mutating` or `external_irreversible`
is never allowed in live mode without an explicit 2-person approval and
a recorded audit entry. The default refusal returns `RELAY-REPLAY-014`.
In practice this is why debugging a "delete production row" tool in
replay-mode shows the recorded outcome rather than re-deleting the row,
and why an override path exists but is intentionally heavy enough to
make accidental use very unlikely.

Spec: §E.3.

### #13 The OSS verifier's default trust anchor does not change in a routine PR

A companion rule to #11: the default JWKS URL the OSS verifier fetches is
fixed at `https://relay.epochly.com/.well-known/jwks.json` and is not
altered by ordinary code changes. The supported path for forks,
self-hosters, and air-gapped deployments is the `--trust-anchor` flag
(or equivalent configuration) on the verifier, not a patch to the
default. In practice this is why community forks of Relay can produce
their own trust anchors without breaking compatibility with the official
verifier, and why an auditor can be confident that "default JWKS" means
the same URL across every released OSS version.

Spec: §AO.4.

### #14 No trust-anchor private key material in the OSS repo

Signing private keys, KMS or HSM references that resolve to those keys,
TSA partner credentials, and transparency-log custody keys are never
committed to the public OSS repository — not as files, not as fixtures,
not as test bundles, not as cassettes. Private keys live only inside
KMS or HSM custody operated by the hosted plane. The Apache 2.0 grant
covers source code, not key material. In practice this is why every
example evidence bundle in the OSS repo is signed by a fixture key
explicitly marked as non-production, and why a leaked OSS commit
cannot, on its own, produce a verifier-trusted bundle.

Spec: §L.1, §AO.4.

### #15 Source-boundary discipline between OSS and hosted

Code, schemas, and documentation that belong to the public OSS repo
stay in the public OSS repo; code, schemas, and documentation that
belong to the hosted plane stay in the hosted plane. The OSS repo
never embeds hosted-only architecture leaks, and the hosted plane
consumes OSS code only through pinned, signed releases — it does not
fork-and-mutate OSS code. In practice this is why the OSS verifier,
SDKs, CLI, and schemas are usable standalone for local workflows
without a Relay account, and why a behavior change that is needed by
both products lands in the public OSS repo first.

Spec: §AO.4, "Public relay repository layout".

### #16 CEL user-defined functions are deterministic

Every Relay CEL user-defined function (UDF) — `relay.coverage`,
`relay.tool_arg`, `relay.schema_match`, and any future addition — is
declared `pure`: no wall-clock reads, no network calls, no filesystem
reads outside the inputs handed to the function, no locale-dependent
comparisons without an explicit locale, no mutable process globals,
no random sources. The Relay Conformance Corpus enforces this and
requires parity between the Python and JavaScript CEL evaluators
before any change merges. In practice this is why a contract that
evaluates green today evaluates green tomorrow on the same inputs,
and why replay can re-run a contract against recorded inputs and get
the same verdict.

Spec: §D.

Spec: §A.1, §C, §K, §AO
