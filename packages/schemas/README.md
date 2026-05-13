# epochly-relay-schemas

Canonical control-plane schemas for the Relay agent reliability OS.

This package owns the canonical schema source-of-truth and the W1.5 codegen
pipeline.

## Source-of-truth file (W1.5)

`raw/openapi.yaml` is a single OpenAPI 3.1 document carrying every persisted
control-plane envelope under `components.schemas`. The W1.5 codegen pipeline
consumes this file via:

- `datamodel-code-generator` -> `packages/sdk-python/relay/_generated/`
  (Pydantic v2 `BaseModel` subclasses with `extra='forbid'`)
- `openapi-typescript` -> `packages/sdk-typescript/src/_generated/`
  (TypeScript type aliases + named re-exports)

Regenerate via:

```bash
uv run python packages/schemas/scripts/codegen.py
```

Drift check (VAL-W1-035):

```bash
uv run python scripts/check-codegen-drift.py
```

## Two-layer architecture

The W1.5 generated layer carries the BASE canonical models (one Pydantic
class per envelope; one TS type alias per envelope) with the `extra='forbid'`
discipline. The hand-authored W1.1-W1.4 modules under
`packages/schemas/python/relay_schemas/envelopes.py` and
`packages/schemas/typescript/src/envelopes.ts` add the RICH validation layer:

- Cross-field invariants (`accepted_requires_evidence`,
  `raw_capture_requires_dpa_and_approver`, `dry_run_never_resolves`).
- RFC 3339 timezone-offset enforcement (`VAL-W1-017`, `VAL-W1-024`).
- StrictBool rejection of string coercion (`VAL-W1-023`, `VAL-W1-026`).
- Canonical-byte serializers for cross-language round-trip evidence.
- The discriminated-union `ScopeState` metaclass adapter.

The generated layer and the hand-authored layer are independent: the generated
classes are NOT subclassed by the hand-authored classes. Future W1.6 +
cross-language fixtures consume both layers and verify them against the same
JSON canonical form.

## Layout

- `raw/openapi.yaml` - canonical OpenAPI 3.1 source-of-truth (W1.5).
- `raw/envelopes.yaml` - W1.1-W1.4 custom-format YAML; lock-in documentation
  companion only (not a codegen source).
- `raw/relay-error-codes.yaml` - canonical RELAY-* error code registry.
- `raw/owner-email-deny.yaml` - canonical group-email deny prefixes (W1.4).
- `python/relay_schemas/` - W1.1-W1.4 hand-authored rich-validation envelopes.
- `typescript/src/` - W1.1-W1.4 hand-authored TS runtime guards.
- `sql/` - W1.1-W1.4 SQL DDL migrations (FK targets and CHECK constraints).
- `scripts/codegen.py` - W1.5 codegen orchestrator (this file's home).
- `scripts/gen_error_codes.py` - W1.4 error-codes generator (called by W1.5).
- `python/tests/` - W1 contract assertion tests (pytest, tier-1 plumbing).

## Versioning

Per CLAUDE.md keystone invariant #10: every canonical envelope carries a
`schema_version` field pinned to a string literal. Engines refuse unknown
versions on write. The W1.5 codegen pipeline emits a
`RelayUnknownSchemaVersionError` helper (Python + TS) that callers use via
`parse_envelope(...)` / `parseEnvelope(...)` to surface forward-compat
failures with a stable error type (VAL-W1-036).

## License

Apache 2.0. See repository root `LICENSE`.
