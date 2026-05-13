# W1.6 cross-language golden corpus (VAL-W1-038..045)

Cross-language Py <-> TS round-trip fixtures for the canonical envelope
serialization layer. Every fixture is the JCS-canonical byte form of an
input document; the corpus harness asserts that re-emitting it from BOTH
Py and TS produces the exact original bytes (modulo intentional rejection
paths like `unknown_enum_value.json`).

## Two-layer serialization architecture

The W1.5 codegen layer (`packages/sdk-python/relay/_generated/`,
`packages/sdk-typescript/src/_generated/`) carries the BaseModel / TS-type
output from datamodel-code-generator and openapi-typescript.

The W1.1-W1.4 hand-authored RICH layer
(`packages/schemas/python/relay_schemas/envelopes.py`,
`packages/schemas/typescript/src/envelopes.ts`) carries the cross-field
invariants AND the canonical-byte serializers used here:

- Py: `canonical_bytes(value)` -> UTF-8 bytes (sort_keys, compact separators).
  Pre-existing dedicated serializers `serialize_event_log_entry_canonical`
  and `serialize_replay_fixture_canonical` use the same primitive plus the
  raw-wire-form-string capture (VAL-W1-017 / VAL-W1-024) that preserves
  RFC 3339 offsets byte-for-byte.
- TS: `canonicalBytes(value)` -> UTF-8 Uint8Array (mirrors Py).

Both produce byte-identical output for the same input value.

## Cross-language workflow

The corpus uses a SHARED-SIDECAR pattern (no Python -> Node subprocess hop).
Each language tests independently against the SAME committed `.sha256`
sidecar file:

1. Pytest at `packages/schemas/python/tests/test_golden_corpus.py` loads
   each fixture JSON file, validates through the appropriate `parse*` /
   Pydantic `model_validate` call (asserts schema conformance), re-emits
   the loaded dict via `canonical_bytes`, and asserts SHA-256-hex of the
   output equals the committed `.sha256` sidecar.
2. Vitest at `packages/schemas/typescript/test/golden_corpus.test.ts`
   loads the SAME fixture JSON file, runs through the appropriate TS
   `parse*` function, re-emits via `canonicalBytes`, and asserts the
   same SHA-256-hex equality against the SAME sidecar.

Cross-language byte equality is established by the SHA-256 collision
resistance: if both languages independently compute a SHA-256 that equals
the same sidecar value, their canonical byte streams are byte-equal modulo
a collision (computationally infeasible at SHA-256 strength).

This pattern avoids a Python -> Node subprocess hop (which would burn
200-500ms of the VAL-W1-045 60s tier-1 budget per invocation) while
preserving the byte-equality contract. Pytest runs in <5s and vitest runs
in <1s for the full corpus; both well under budget.

The fixture files themselves (the `.json` files in this directory) are
ALREADY in JCS-canonical form (sorted keys, compact separators, UTF-8).
`canonical_bytes(json.loads(file_bytes)) == file_bytes` is the trivial
round-trip property, and the test asserts this with byte-for-byte SHA-256
equality.

## Locked policies referenced

- `packages/schemas/raw/enum-forward-compat.md` (VAL-W1-040, Option A
  strict reject with RELAY-SCHEMA-001).
- `packages/schemas/raw/timestamp-canonicalization.md` (VAL-W1-042, Option
  A preserve offset byte-for-byte).

## Fixture inventory

| Fixture | VAL ref | Envelope | Notes |
|---|---|---|---|
| `nullable_field.json` | VAL-W1-038 | RunResult | `primary_failure_class: null` |
| `missing_optional_field.json` | VAL-W1-039 | RunResult | `primary_failure_class` key absent |
| `unknown_enum_value.json` | VAL-W1-040 | RunResult | `status` outside closed set; rejection fixture (BOTH languages MUST raise `RelayUnknownEnumValueError`) |
| `decimal_precision.json` | VAL-W1-041 | synthetic | string-encoded decimals (`"0.30000000000000004"`, `"1234567890.123456789"`) per the contract guidance "TS uses string-encoded decimal (NOT number)" |
| `timestamp_z.json` | VAL-W1-042 | EventLogEntry | `occurred_at` ends with `Z` |
| `timestamp_offset.json` | VAL-W1-042 | EventLogEntry | `occurred_at` ends with `+05:30` |
| `union_scope_state_run.json` | VAL-W1-043 | ScopeState | `scope_kind="run"` variant |
| `union_scope_state_replay_case.json` | VAL-W1-043 | ScopeState | `scope_kind="replay_case"` variant |
| `union_scope_state_gate_round.json` | VAL-W1-043 | ScopeState | `scope_kind="gate_round"` variant |
| `union_scope_state_evidence_bundle.json` | VAL-W1-043 | ScopeState | `scope_kind="evidence_bundle"` variant |
| `union_redaction_matcher_regex.json` | VAL-W1-043 | RedactionPolicy | `matchers[0].kind="regex"` variant |
| `union_redaction_matcher_json_pointer.json` | VAL-W1-043 | RedactionPolicy | `matchers[0].kind="json_pointer"` variant |
| `error_envelope.json` | VAL-W1-044 | ErrorEnvelope | round-trips Py->TS->Py and TS->Py->TS |

`.sha256` sidecar carries the SHA-256-hex digest of the canonical bytes
(the file content) -- both Py and TS recompute and assert equality.

## Synthetic decimal fixture rationale

The W1 v0.1 envelope set does NOT yet land a decimal field (billing /
cost / confidence numerics live in section AC, post-v0.1). Per the worker
contract's explicit allowance ("If no real field exists, document the
choice in the corpus README and use a synthetic fixture"), the
`decimal_precision.json` fixture is a NON-envelope test document carrying
two string-encoded decimals. The harness validates byte-equal round-trip
through `canonical_bytes` / `canonicalBytes` only (no Pydantic / TS-type
model parse) because no envelope contains the field. When the v0.2
billing envelopes land, this fixture moves to the real envelope.
