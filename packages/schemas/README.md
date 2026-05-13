# epochly-relay-schemas

Canonical control-plane schemas for the Relay agent reliability OS.

This package defines every persisted control-plane envelope as a single source
of truth in YAML (under `raw/`), with Pydantic models (under `python/`) and
TypeScript types (under `typescript/`) generated from those YAML definitions
and kept in sync via the W1.5 codegen drift check.

## Layout

- `raw/` - canonical YAML schema definitions (single source of truth)
- `python/relay_schemas/` - generated Pydantic v2 models
- `typescript/src/` - generated TypeScript types and runtime guards
- `sql/` - generated SQL DDL migrations (FK targets and CHECK constraints)
- `python/tests/` - W1 contract assertion tests (pytest, tier-1 plumbing)

## Versioning

Per CLAUDE.md keystone invariant #10: every canonical envelope carries a
`schema_version` field pinned to a string literal. Engines refuse unknown
versions on write. Adding a new version is a breaking change handled per
spec section B.7.

## License

Apache 2.0. See repository root `LICENSE`.
