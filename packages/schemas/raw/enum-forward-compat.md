# Locked policy: unknown enum value reader behavior

**Status:** LOCKED (W1.6 round-trip golden corpus)
**Date locked:** 2026-05-13
**Authority:** spec section B.7 (writer side), W1.6 contract VAL-W1-040
**Mirrors:** CLAUDE.md keystone invariant #10 (schema versioning + forward-compat
posture).

## Question

When a Relay reader (Py SDK / TS SDK / verifier / sidecar) deserializes a
canonical envelope that carries an **unknown enum value** in a closed-set
field (for example `RunResult.status = "future_status_v2"`, where the
canonical enum set is `{accepted, remediate_required, blocked, invalid}`),
what is the canonical reader behavior?

Spec section B.7 anchors WRITER behavior:

> Engines refuse to write objects whose `schema_version` is unknown.

The spec does **not** explicitly say what readers do for unknown enum
**values**. This document fills that gap.

## Policy options considered

### Option A -- Strict reject (LOCKED)

Reader raises a structured error (`RelayUnknownEnumValueError` in Py, the
mirroring class in TS) carrying:

- the field name where the unknown value appeared (e.g. `status`),
- the observed value (e.g. `"future_status_v2"`),
- the canonical enum set (the four allowed values),
- the canonical Relay error code `RELAY-SCHEMA-001`.

Py and TS readers MUST raise identically; the error class hierarchy makes
the error a `ValueError` subclass in Py (mirroring the existing
`RelayUnknownSchemaVersionError` precedent in W1.5) and an `Error` subclass
in TS.

### Option B -- Accept-with-warning (rejected)

Reader accepts the value as a free-form string (typing the field `str`
post-validation) and emits a warning log line. The Pydantic v2 path would
need a `Union[Literal["..."], str]` widening; the TS path would weaken
the discriminated-union types to `string`.

This option was REJECTED because:

1. **Symmetry with writer behavior.** section B.7 makes the writer side strict
   (refuse-to-write on unknown `schema_version`). Making the reader side
   lax for unknown enum *values* breaks the read-write symmetry that the
   evidence layer depends on. A canonical envelope that round-trips a
   value the reader silently accepted but the writer would refuse is an
   undetectable corruption surface.
2. **Forward-compat does not require lax readers.** section B.7's stance is that
   forward-compat is handled by `schema_version` bumps. A new enum value
   in `RunResult.status` is a breaking change to the wire format and
   requires `relay.run_result.v2` per CLAUDE.md keystone #10. Bumping
   the version is the supported forward-compat mechanism.
3. **Replay correctness.** Replay tolerates only deterministic readers.
   A lax reader's warning-log surface is a side-effect that diverges
   between cassette replay and live replay, making bundles produced by
   one path uncomparable with bundles produced by the other (section E.2).
4. **Evidence binding.** Per CLAUDE.md keystone #6, "Evidence binds.
   Narrative doesn't." Accepting an unknown value with a warning is
   narrative; structured rejection is evidence.
5. **CLI / verifier downstream.** An offline verifier that silently
   accepts unknown enum values cannot honor its contract (section AO.4); a
   bundle signed by a newer writer should fail strictly on an older
   verifier so the operator knows to upgrade.

## Locked behavior (Option A -- strict reject)

Both Py and TS reader paths raise `RelayUnknownEnumValueError` carrying:

```text
field            : str (dotted path within the envelope, e.g. "status")
observed_value   : str (the unknown value verbatim)
allowed_values   : tuple[str, ...] (sorted canonical enum set)
envelope_name    : str ("RunResult", "GateDecision", ...)
relay_error_code : Literal["RELAY-SCHEMA-001"]
```

The Py implementation lives in
`packages/schemas/python/relay_schemas/envelopes.py`. The TS implementation
lives in `packages/schemas/typescript/src/envelopes.ts`.

The error code `RELAY-SCHEMA-001` is registered in
`packages/schemas/raw/relay-error-codes.yaml` and surfaces in the
generated `RelayErrorCode` constants for both languages.

## Symmetry guarantee

Py and TS readers MUST raise structurally identical errors for identical
input. The W1.6 golden corpus encodes a fixture
(`unknown_enum_value.json`) where:

- Py raises `RelayUnknownEnumValueError(field="status", observed_value=
  "future_status_v2", allowed_values=("accepted","blocked","invalid",
  "remediate_required"), envelope_name="RunResult", relay_error_code=
  "RELAY-SCHEMA-001")`.
- TS raises the matching class with the same five attributes.
- The corpus asserts the cross-language behavior digest is byte-equal
  (sorted JSON of the five attributes).

A future enum widening (e.g. introducing `status = "deferred"`) is a
**v2 envelope** per CLAUDE.md keystone #10. The corresponding canonical
YAML is updated, the schema_version bumps to `relay.run_result.v2`,
both readers are regenerated, and the W1.6 corpus is updated to encode
the new enum set. Readers parsing v1 documents continue to reject
the new value with `RELAY-SCHEMA-001`; readers parsing v2 accept it.

## Test references

- `packages/schemas/python/tests/test_golden_corpus.py` -- VAL-W1-040
  test case `test_unknown_enum_value_strict_reject_cross_language`.
- `packages/schemas/typescript/test/golden_corpus.test.ts` -- mirror.
- `packages/schemas/python/tests/golden_corpus/unknown_enum_value.json`
  -- the fixture used by both.
