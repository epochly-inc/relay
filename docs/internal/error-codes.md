# Relay Error Code Naming Convention

This document is the canonical reference for the wire-format `code` field
emitted by every Relay surface (SDK, CLI, sidecar HTTP API, hosted
control plane, verifier). It pins the grammar, the domain registry, and
the sub-classification mechanism so every consumer -- log forwarders,
CI gates, dashboards, support runbooks -- can dispatch on a stable
machine-readable token.

This file is the source of truth for VAL-V3M5-021 (§X.7). When the spec
adds a new domain or sub-classification convention, this document is
updated AS PART OF that spec change; the corresponding registry file
`packages/schemas/raw/relay-error-codes.yaml` is the machine-readable
sibling.

ASCII-only per CLAUDE.md "ASCII-Safe Source".

---

## Canonical pattern

```
RELAY-<DOMAIN>-<NNN>
```

Three parts, joined by a single hyphen:

| Part | Grammar | Meaning |
|------|---------|---------|
| `RELAY` | literal `RELAY` | Vendor prefix. Identifies the emitter as Relay; lets log forwarders dispatch without parsing further. |
| `<DOMAIN>` | `[A-Z][A-Z0-9_]{1,31}` | Uppercase domain token (see Domain registry below). Underscore is permitted ONLY for two-word domains already in the registry (e.g., `SIDECAR_STORAGE`). New domains SHOULD prefer a single token. |
| `<NNN>` | `[0-9]{3}` | Three-digit zero-padded ordinal within the domain. Range `000`-`999`. Never reused once allocated, even on retirement. |

### Grammar regex (canonical)

```
^RELAY-[A-Z][A-Z0-9_]{1,31}-[0-9]{3}$
```

Reference implementation (Python):

```python
import re
RELAY_ERROR_CODE_RE = re.compile(r"^RELAY-[A-Z][A-Z0-9_]{1,31}-[0-9]{3}$")
```

Reference implementation (TypeScript):

```typescript
export const RELAY_ERROR_CODE_RE = /^RELAY-[A-Z][A-Z0-9_]{1,31}-[0-9]{3}$/;
```

Any code emitted on the wire that fails this regex is a regression and
MUST be rejected by the schema validators in
`packages/schemas/python/relay_schemas/` (Python) and
`packages/schemas/typescript/` (TypeScript).

---

## Domain registry

Domains group codes by emitting surface. Adding a new domain requires a
spec amendment (the spec authority is `planning/epochly-replay-spec.md`,
§A through §AO). The registry below is non-exhaustive but covers the
P0/P1 surfaces active as of the v0.3 audit-resolution operation.

| Domain | Surface | Spec anchor | Example |
|--------|---------|-------------|---------|
| `ING` | Ingest edge (hosted) | §AI.1 | `RELAY-ING-031`, `RELAY-ING-041` |
| `GATE` | Gate engine + handoff | §C.5, §AD | `RELAY-GATE-021`, `RELAY-GATE-024` |
| `REPLAY` | Replay sandbox + workers | §E | `RELAY-REPLAY-014`, `RELAY-REPLAY-031` |
| `EVID` | Evidence bundle + verifier | §K, §AO | `RELAY-EVID-014`, `RELAY-EVID-024` |
| `CONTRACT` | Contract DSL + coverage | §D | `RELAY-CONTRACT-PARSE-001` (legacy 3-part; new domain codes prefer 3-segment) |
| `COVERAGE` | Contract coverage invariant | §D.5 | `RELAY-COVERAGE-NNN` |
| `IDEMPOTENCY` | Idempotency-Key handling | §B.6 | `RELAY-IDEMPOTENCY-014` |
| `CURSOR` | Pagination cursor signing | §B.3 | `RELAY-CURSOR-TAMPER`, `RELAY-PAGE-001` |
| `REDACT` | Redaction policy + budget | §G, §AI | `RELAY-REDACT-014` |
| `EVAL` | Eval runner + judge | §AJ | `RELAY-EVAL-EVALUATOR-DEFERRED` |
| `AUTH` | Authn + handoff identity | §C.5 | `RELAY-AUTH-001` |
| `SIDECAR` | Local sidecar runtime | §F, §H.5 | `RELAY-SIDECAR-STORAGE-001` |
| `HOSTED` | Hosted-only surfaces | §B | `RELAY-HOSTED-ONLY` |
| `CLI` | CLI binary itself | §P | `RELAY-CLI-070`, `RELAY-CLI-130` |

### Reservation rules

1. Three-letter domain tokens (`ING`, `GATE`) are reserved for spec-anchored
   surfaces. New domains added by feature work MUST be at least four
   characters.
2. Numeric ranges within a domain are allocated by the registry file
   `packages/schemas/raw/relay-error-codes.yaml`. Never hand-allocate a
   number; consult the registry and pick the next free triple.
3. Retired codes (a feature was removed) are kept in the registry with
   `status: retired` and SHOULD NOT be re-issued for unrelated semantics.

---

## Sub-classification: `details.subcode`

The three-digit ordinal is intentionally coarse. When a single wire code
covers multiple distinguishable failure causes that share remediation
context, the finer distinction is carried in the error envelope's
`details.subcode` field rather than by minting a new top-level code.

### Rationale

Minting a new top-level code per sub-cause has two costs:

1. CI gates, dashboards, and log forwarders that switch on the
   top-level code must learn every new variant. Adding 8 variants of
   "approval required failed" produces 8 new dispatch paths.
2. Operator-facing surfaces (runbooks, status pages) often only need
   the coarse class. Forcing the operator to memorize 8 codes when the
   remediation is the same wastes attention.

`details.subcode` lets the coarse code remain stable while the fine
distinction stays machine-readable for the consumers who care.

### Pattern

```
{
  "code": "RELAY-<DOMAIN>-<NNN>",
  "http_status": <int>,
  "message": "<human-readable, redaction-safe>",
  "details": {
    "subcode": "<snake_case_token>",
    ...
  }
}
```

The `subcode` grammar is `^[a-z][a-z0-9_]{0,63}$` -- lowercase snake_case,
1 to 64 characters, starts with a letter. Subcodes are scoped to their
top-level code; the same subcode token may appear under different codes
with unrelated meanings.

### Example: `RELAY-REPLAY-031` (approval-required override class)

The `approval_required` side-effect class has three distinct failure
shapes during replay:

| `details.subcode` | Condition | Remediation |
|---|---|---|
| `approval_required_missing` | Fixture declares `approval_required` but `--approval-token` was not provided. | Provide a fresh single-use approval token. |
| `approval_required_consumed` | Token previously used; replay tried to consume it again. | Mint a new token; the prior one is burned. |
| `approval_required_actor_mismatch` | Token issued for actor A; replay running as actor B. | Re-mint as the current actor. |

The wire envelope for the first variant:

```json
{
  "code": "RELAY-REPLAY-031",
  "http_status": 403,
  "message": "approval_required side-effect blocked: token missing",
  "blocked_surface": "rly replay run",
  "retry_advice": "after_fix",
  "details": {
    "subcode": "approval_required_missing",
    "case_id": "case-abcd1234",
    "side_effect_class": "approval_required"
  }
}
```

### Example: `RELAY-EVID-014` (signature/manifest failure class)

| `details.subcode` | Condition |
|---|---|
| `signature_invalid` | JWS signature fails verification against the trust anchor JWKS. |
| `signature_key_revoked` | Signing key matched, but `kid` is in the revocation registry. |
| `trust_anchor_mismatch` | Bundle's declared `trust_anchor` does not match the verifier's configured root. |
| `manifest_digest_mismatch` | Bundle manifest's recomputed digest does not match the stored value. |

### When to mint a new top-level code instead

Mint a new `RELAY-<DOMAIN>-<NNN>` rather than a subcode when ANY of:

1. The HTTP status differs (e.g., one variant is 400, another 403). HTTP
   status is part of the contract; subcodes cannot vary it.
2. The remediation path differs in kind (different runbook, different
   responsible team). Subcodes share a remediation umbrella.
3. The wire code participates in a CI-gate-blocking rule that switches
   on the code only. Pushing the distinction into `details.subcode`
   would silently break the gate.

---

## Lifecycle

1. **Proposal** -- a new feature lists the code(s) it intends to use in
   its `primaryFulfills` contract assertions or in its PR description.
2. **Reservation** -- the code lands in
   `packages/schemas/raw/relay-error-codes.yaml` with `status: reserved`
   and a one-line description. This MUST happen in the same PR that
   first emits the code.
3. **Active** -- once the feature lands and tests exercise the emission
   path, the code's `status` flips to `active`.
4. **Retired** -- if the feature is removed, the row stays with
   `status: retired`. The code MUST NOT be re-issued for unrelated
   semantics (see Reservation rules).

---

## Test coverage

- `packages/schemas/python/tests/` validates emitted envelopes against
  `^RELAY-[A-Z][A-Z0-9_]{1,31}-[0-9]{3}$`.
- `packages/cli/tests/test_audit_v3_json_injection.py` exercises the
  CLI's stdout JSON emit path under adversarial input so a control
  character in an operator-supplied field cannot inject a forged
  `code` token (VAL-V3M5-022).
- The contract registry generator under `packages/schemas/`
  cross-validates the registry YAML against this document's grammar on
  every commit.

---

## References

- Spec: `planning/epochly-replay-spec.md` §A.3 (envelope shape), §X.7
  (naming convention), §AI.1 (input safety).
- Audit contract: `relay-v0.3-audit-resolution/contract.md` VAL-V3M5-021,
  VAL-V3M5-022.
- Registry YAML: `packages/schemas/raw/relay-error-codes.yaml`.
