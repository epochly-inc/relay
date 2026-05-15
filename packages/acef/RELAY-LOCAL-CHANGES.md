# Relay-local changes on top of the ACEF v0.3 vendor pin

This document catalogues the changes Relay maintains OUTSIDE the
vendored `upstream/` tree. The vendored tree itself is immutable and
byte-equal to the pinned upstream commit (VAL-W11-004); every Relay
extension lives elsewhere in this package.

## Why list local changes here

The W11.1 vendor-drift guard (VAL-W11-004) rejects any mutation of
`upstream/` that is not part of the documented bump workflow. This
forces every Relay-specific addition to live in a bounded local
surface, which makes the upstream contribution boundary clear: a
behaviour change useful upstream is a PR against
`https://github.com/chandlercvaughn/ACEF`, not a patch against
`upstream/`.

## Local additions in this package

### `src/relay_acef/__init__.py`

Workspace-package surface. Exposes constants only; does NOT runtime-
import anything under `upstream/`. Constants:

- `VENDOR_COMMIT_SHA` -- the pinned commit; mirrored in
  `vendor_manifest.json` and read by the drift guard.
- `VENDOR_MATURITY` -- the upstream's stated maturity phrase, recorded
  verbatim per VAL-W11-003.

### `src/relay_acef/roundtrip.py` (W11.3)

W11.3 byte-level roundtrip helpers:

- `emit_bundle(bundle) -> bytes` -- W11.2 EmissionWriter validation
  followed by RFC 8785 (JCS) canonicalisation.
- `parse_bundle(bytes) -> dict` -- JSON parse with `parse_float=Decimal`,
  recursive NFC normalisation, and W11.2 re-validation on the parse path.
- `roundtrip(bundle) -> bytes` -- `emit(parse(emit(bundle)))`; the
  load-bearing equality `roundtrip(b) == emit_bundle(b)` is what the
  W11.3 corpus tests assert.
- `bundle_digest(bundle) -> str` -- `sha256(emit_bundle(bundle))` hex.
- `bundle_merkle_root(bundle) -> str` -- RFC 6962 Merkle root over
  `bundle["claims"]` in canonical claim order (lexicographic by
  `evidence_claim_id`); empty-bundle root is `sha256(b"")`.
- `JCSEncodeError` -- raised when a value type cannot be JCS-encoded
  (non-finite numbers, unsupported types).

The encoder NFC-normalises both dict keys and string values on emit so
NFD inputs and NFC inputs produce identical canonical bytes (VAL-W11-020).
Decimal numeric values are preserved with full textual precision; the
encoder collapses negative zero to `"0"` to match ECMA-262 NumberToString.

### `relay_extensions/` (W11.2)

The ten `x-relay/*` extension namespaces (spec lines 876-885) live
here. None of these symbols are present in the vendored upstream; they
are Relay-specific and ride on top of an unmodified ACEF Core bundle
under `bundle.namespaces["x-relay"]`. Surfaces:

- `EmissionWriter` -- W11.2 validator that audits root keys, namespace
  block structure, schema_version pins, namespace sub-fields against
  each namespace JSON Schema, and the seven required control-plane
  bindings. Returns the bundle unchanged on success or raises typed
  `SchemaVersionError(RELAY-SCHEMA-{011,014,023})`.
- `schemas/<namespace>.v1.json` -- JSON Schemas for the ten namespaces.
- `golden/<namespace>.json` -- golden fixtures used by tier-1 tests.
- `models/<namespace>.py` -- Python dataclass models per namespace.

The bundle these emit carries AI Act readiness evidence: per-run
control-plane bindings, replay verification outcomes, contract-gate
results, human-oversight events, incident-monitoring records. The
Merkle root binds the evidence coverage of a run into a single
content-addressed digest so an auditor can identify gaps and decide
whether the run is ready for auditor review.

### `tests/` (W11.1, W11.2, W11.3)

Tier-1 plumbing tests. Bound to `@pytest.mark.fulfills` for VAL-W11-001
through VAL-W11-026.

## Local additions NOT in this package

The hosted control-plane services that consume these surfaces (evidence
registry, replay workers, sandbox driver) live in `relay-platform/`.
Those services consume this package via pinned package versions; they
do not fork or mutate this code.

## Patches against `upstream/`

None. Per VAL-W11-004 the vendored tree is immutable outside the
documented bump workflow. A behaviour change required by Relay that is
not generally useful upstream lives under `relay_extensions/` or
`src/relay_acef/`; a behaviour change useful upstream goes through a
PR to the upstream project.
