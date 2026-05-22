# How to Audit a Gate Decision

You are an ML safety reviewer. A release has just shipped (or just been
blocked), and you need to know *why* the gate decided what it decided.
A canonical `gate_decisions` row is the answer of record — it is signed,
content-bound to a manifest, and immutable. The accompanying `gate_rounds`
rows tell you what happened across remediation attempts. This guide walks
you from a `gate_decision_id` (or scope) to a defensible auditor-grade
answer.

The control plane writes the decision; workers only submit drafts (spec
§A.2, §A.3). If a worker tried to write a decision directly, the row
would never have appeared — the `decided_by` CHECK constraint refuses
anything other than the literal `gate_engine`. Trust the row.

## What you'll find in a `gate_decisions` row

The canonical DDL lives in
`packages/schemas/sql/0003a_canonical_run_results_and_gates.sql` (table
`gate_decisions`, spec §A.2). Columns, byte-for-byte:

| Column | Type | Meaning |
|---|---|---|
| `gate_decision_id` | `uuid PRIMARY KEY` | Stable identity for citing the decision in evidence. |
| `schema_version` | `text` | Pinned literal `relay.gate_decision.v1`. |
| `gate_id` | `uuid` (FK `gates`) | Which contract gate produced the decision. |
| `scope_type` | `text` | One of `run`, `replay`, `eval_run`, `release`, `domain_pack`. |
| `scope_id` | `uuid` | The thing being gated (release SHA, run id, etc.). |
| `round` | `int` (>= 1) | Which remediation round this decision belongs to. |
| `action` | `text` | One of `accept`, `remediate`, `block`, `invalid`. |
| `strict_pass` | `boolean` | Whether every strict-mode assertion passed. |
| `failed_assertion_ids` | `jsonb` | Array of assertion IDs (e.g. `["VAL-X-001"]`) that failed. |
| `unmet_conditions` | `jsonb` | Array of unmet contract conditions. |
| `evidence_bundle_id` | `uuid` (FK `evidence_bundles`) | The signed bundle that backs this decision. |
| `cascade_on_block` | `boolean` | If true and `action = 'block'`, restart triggers another round (subject to `remediation_round_cap`). |
| `decided_by` | `text` | Pinned literal `gate_engine`. If anything else appears here, the row is corrupt. |
| `decided_at` | `timestamptz` | When the decision was written. |
| `manifest_commit_hash` | `text` | `sha256-<hex>` of the manifest in force (three-anchor handoff). |
| `actor_identity_hash` | `text` | `sha256-<hex>` of the submitting actor's identity (three-anchor handoff). |
| `signature` | `text` | Detached signature over the canonical decision payload. |
| `signature_key_id` | `text` | Which signing key produced `signature` (see also `docs/evidence/signing-key-lifecycle.md`). |
| `decision_epoch` | `bigint` | Optional monotonic epoch used by replay parity checks. |

The `UNIQUE(gate_id, scope_type, scope_id, round)` constraint guarantees
each round has exactly one canonical decision. There is no overwrite path.

## What you'll find in `gate_rounds`

The same DDL file defines `gate_rounds` (spec §A.4). This is the per-round
audit trail — one row per round, regardless of whether that round produced
a decision.

| Column | Type | Meaning |
|---|---|---|
| `gate_round_id` | `uuid PRIMARY KEY` | Identity of this round. |
| `schema_version` | `text` | Pinned literal `relay.gate_round.v1`. |
| `gate_id` | `uuid` (FK `gates`) | Which gate this round belongs to. |
| `scope_type` | `text` | Matches the decision's `scope_type`. |
| `scope_id` | `uuid` | Matches the decision's `scope_id`. |
| `round` | `int` (>= 1) | Round number. |
| `initiated_at` | `timestamptz` | When the round opened. |
| `initiated_by` | `text` | One of `control_plane`, `cron`, `user`, `remediation`, `submission`, `admin_override`. |
| `initiation_reason` | `text` | Free-text reason. Present on remediation and admin rounds. |
| `gate_decision_id` | `uuid` (FK `gate_decisions`) | The decision produced by this round, NULL while the round is still in flight. |
| `restart_predecessor` | `uuid` (FK `gate_rounds`) | NULL on round 1; on every restart round, references the predecessor row. Walk this chain backward to reconstruct the full remediation history. |

`UNIQUE(gate_id, scope_type, scope_id, round)` keeps the round numbering
linear and gap-free per scope. A missing round number is itself a finding.

Count the `gate_rounds` rows whose joined `gate_decisions.action` is
`remediate` to reconstruct how many rounds failed for that scope. When
`current_round + 1 > gate.remediation_round_cap` (default `5`, per spec
§AD), the next event transitions the gate into `gate.stalled` rather
than starting a new round. That is the circuit breaker.

## Step 1: pull the decision

There is no `rly` subcommand that fetches a single decision today. The
public CLI currently exposes `rly gate evaluate` only (see
`docs/reference/cli/gate/`). For inspection, query the control-plane
database directly. From a psql session connected to the control-plane
database:

```sql
SELECT
    gate_decision_id,
    gate_id,
    scope_type,
    scope_id,
    round,
    action,
    strict_pass,
    failed_assertion_ids,
    unmet_conditions,
    evidence_bundle_id,
    cascade_on_block,
    decided_by,
    decided_at,
    manifest_commit_hash,
    actor_identity_hash,
    signature_key_id
FROM gate_decisions
WHERE gate_decision_id = '<paste-uuid-here>';
```

If you only have a `scope_id` (for example, a release SHA mapped to a
release scope), look up every round in order:

```sql
SELECT round, action, decided_at, gate_decision_id, evidence_bundle_id
FROM gate_decisions
WHERE scope_type = 'release'
  AND scope_id = '<scope-uuid>'
ORDER BY round ASC;
```

Confirm `decided_by = 'gate_engine'` on every row. The DDL refuses any
other value via its CHECK constraint, so a non-matching row is corruption
and warrants escalation, not interpretation.

Pair the canonical row with its evidence bundle by joining
`evidence_bundle_id` against `evidence_bundles`. The bundle is what an
external auditor verifies offline (see `docs/evidence/offline-verification.md`).

## Step 2: walk the `gate_rounds` history

For the same scope, pull every round in order:

```sql
SELECT
    round,
    initiated_by,
    initiation_reason,
    initiated_at,
    gate_decision_id,
    restart_predecessor
FROM gate_rounds
WHERE gate_id = '<gate-uuid>'
  AND scope_type = 'release'
  AND scope_id = '<scope-uuid>'
ORDER BY round ASC;
```

What each `action` on the joined `gate_decisions` row tells you:

- `accept`: gate passed. Terminal for this scope unless reopened by an
  admin.
- `remediate`: fixable. A new round was eligible to open. Walk forward
  via the next row whose `restart_predecessor` is this round's
  `gate_round_id`.
- `block`: terminal unless `cascade_on_block = true` AND
  `remediation_round_cap` not yet exceeded (spec §AD). If you see a
  `block` followed by another round, `cascade_on_block` was true.
- `invalid`: evidence or preconditions failed. Per spec §AD, this does
  NOT consume a remediation round; the same round number is reissued
  with corrected inputs.

A `gate_rounds` row whose `gate_decision_id` is NULL is a round that
opened but never produced a canonical decision. The matching
`gate_decision_drafts` row (joined on `gate_id`, `scope_type`,
`scope_id`, `round`) tells you why — pending, expired, cancelled,
rejected on three-anchor handoff, or a duplicate submission. None of
these states produce a `gate_decision`; a draft's
`resolution_state = 'rejected_handoff'` specifically means the
three-anchor handoff check failed (spec §C.5).

## Step 3: confirm the three-anchor handoff (§C.5)

Per spec §C.5, every gate submission carries three anchors that MUST
align with the active state at the moment of submission:

- `scope_id` — what is being gated.
- `actor_identity_hash` — `sha256-<hex>` of the submitting actor's
  identity, recorded on the draft AND copied onto the canonical
  decision. The DDL pins the format with a CHECK regex.
- `manifest_commit_hash` — `sha256-<hex>` of the manifest in force,
  same pinning.

For a clean audit:

```sql
SELECT
    d.draft_id,
    d.round,
    d.actor_identity_hash,
    gd.actor_identity_hash,
    d.manifest_commit_hash,
    gd.manifest_commit_hash,
    d.resolution_state
FROM gate_decision_drafts d
LEFT JOIN gate_decisions gd
       ON gd.gate_decision_id = d.resolved_gate_decision_id
WHERE d.gate_id = '<gate-uuid>'
  AND d.scope_type = 'release'
  AND d.scope_id = '<scope-uuid>'
ORDER BY d.submitted_at ASC;
```

For every resolved row, the draft's `actor_identity_hash` MUST equal the
decision's `actor_identity_hash`, and the draft's `manifest_commit_hash`
MUST equal the decision's `manifest_commit_hash`. A mismatch is an
investigation: the engine should have rejected the draft with
`resolution_state = 'rejected_handoff'` (and the corresponding error
`RELAY-GATE-021`; see `docs/reference/errors/RELAY-GATE-021/`).

Cross-check the manifest hash against the manifest you believe was in
force — see `../contracts/manifest-binding.md` for how
`manifest_commit_hash` is computed and how a stale handoff is detected.

## Step 4: spot `gate.stalled`

`gate.stalled` is the circuit-breaker state defined in spec §AD. It
appears when `current_round + 1 > gate.remediation_round_cap`. Once a
gate stalls, no automatic round will open; only an `admin.reopen` (which
records a reason in `audit_log_entries`) or an `admin.terminate` (which
seals a terminal block claim into the evidence bundle) can move it.

Symptoms in the rows:

- The last `gate_rounds.round` equals `gate.remediation_round_cap`
  (default `5` per spec §AD).
- The last `gate_decisions.action` for that scope is `remediate` (a
  fixable outcome that nonetheless could not open another round) or
  `block` with `cascade_on_block = true`.
- No subsequent `gate_rounds` row exists for the scope.

What to do:

- If the stall is expected (the work was genuinely unfixable in the
  configured cap), look for an `admin.terminate` event in
  `audit_log_entries` and verify the sealed bundle includes the
  terminate claim.
- If the stall is unexpected (you believe the work was making progress),
  inspect the per-round `initiation_reason`, `failed_assertion_ids`, and
  `unmet_conditions` to identify whether the same assertions keep
  failing for the same reason. If so, the contract or manifest may be
  the bug — escalate to the gate owner before requesting an
  `admin.reopen`.
- Never bypass the cap by inserting rows. The gate engine is the sole
  writer of `gate_decisions` (CHECK constraint) and `gate_rounds`. The
  supported path is `admin.reopen` with a recorded reason.

## Related guides

- `../contracts/manifest-binding.md` — how `manifest_commit_hash` is
  computed and what counts as a stale manifest.
- `debug-replay-failures.md` — when the failing round is a replay, this
  guide walks you from the failure code to the cassette and back.

Spec: §C, §C.5, §AD
