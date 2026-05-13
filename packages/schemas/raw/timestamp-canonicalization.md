# Locked policy: RFC 3339 timestamp canonicalization in JCS form

**Status:** LOCKED (W1.6 round-trip golden corpus)
**Date locked:** 2026-05-13
**Authority:** spec section K (evidence binding), W1.6 contract VAL-W1-042,
RFC 3339 section 5.6, RFC 8785 JSON Canonicalization Scheme.

## Question

RFC 3339 section 5.6 permits BOTH `Z` and `+00:00` as the wire form for a UTC
timestamp. RFC 8785 (JCS) canonicalizes JSON values for numbers,
nested objects, key ordering, and strings, but it does NOT define a
normalization rule for RFC 3339 timestamps (timestamps are JSON strings
to RFC 8785; JCS leaves the string bytes alone).

When Relay canonical envelopes carry timestamps, does the canonical form
preserve the producer's offset byte-for-byte, or does it normalize to
some canonical representation?

Three options were considered.

## Policy options considered

### Option A -- Preserve offset byte-for-byte (LOCKED)

The canonical form is the original RFC 3339 string verbatim. A producer
that emits `2026-05-12T10:00:00+05:30` preserves `+05:30`. A producer
that emits `2026-05-12T10:00:00Z` preserves `Z`. A producer that emits
`2026-05-12T10:00:00+00:00` preserves `+00:00`.

The byte stream into the SHA-256 hash and into any signature is the
verbatim string the producer chose. Reader-side parsing converts that
string to a `datetime` for application logic, but the parser MUST also
capture and preserve the raw wire-form string so the canonical serializer
can re-emit it byte-for-byte. The Py `EventLogEntry` / `ReplayFixture`
models already do this via `_occurred_at_raw` / `_capture_clock_raw`
`PrivateAttr` sidecars; the W1.6 corpus extends the pattern.

### Option B -- Normalize all UTC-equivalent forms to `Z` (rejected)

`+00:00` would be rewritten to `Z` on canonicalization. Non-UTC offsets
(`+05:30`) would be preserved. This option was REJECTED because:

1. **Lossy normalization of a producer choice.** A producer that
   deliberately emits `+00:00` (because its internal wall clock is
   ambiguous about whether the offset was explicitly UTC or merely
   defaulted-to-UTC) has its provenance erased.
2. **Implementation complexity for marginal benefit.** Both Py and TS
   parsers would need a normalization pass post-parse-pre-canonicalize,
   adding a code path that itself becomes a forking surface (cel-python
   vs cel-js drift risk, etc.).
3. **Round-trip evidence weakens.** If `+00:00 -> Z` is silently
   rewritten, a verifier that receives a re-signed bundle cannot tell
   whether the original producer wrote `Z` or `+00:00`.

### Option C -- Normalize all timestamps to UTC `Z` (rejected)

Every timestamp converted to UTC and emitted as `...Z`. This option was
REJECTED hard. The producer's wall-clock offset carries provenance
information (the producer was in `Asia/Kolkata` at the time of emit,
which is auditable evidence in section K bundles). Erasing it is destroying
evidence. Spec section K explicitly says "evidence binds": a bundle that
silently converted `+05:30` to `Z` cannot bind to the wall-clock
provenance claim that produced it.

## Locked behavior (Option A -- preserve offset byte-for-byte)

For every RFC 3339 timestamp field in every canonical envelope:

1. The reader MUST capture the original wire-form string verbatim
   (preserved on a private attribute / property; not a serializable
   field in its own right).
2. The reader MUST parse the string into a timezone-aware datetime
   for application logic. Naive timestamps (no `Z`, no `+/-HH:MM`)
   MUST fail validation per VAL-W1-017 / VAL-W1-024 (already locked).
3. The canonical serializer MUST emit the original wire-form string
   byte-for-byte. Round-trip is `original_bytes -> parse -> serialize
   -> original_bytes` exactly.
4. JCS canonicalization (RFC 8785) handles the rest of the document
   (sorted keys, compact separators, UTF-8); the timestamp value is
   already a JSON string and is emitted verbatim.

## Test cases (W1.6 golden corpus)

The corpus encodes both representative cases:

- `timestamp_z.json` -- every timestamp uses the trailing `Z` form
  (`2026-05-12T10:00:00Z`).
- `timestamp_offset.json` -- every timestamp uses an explicit `+HH:MM`
  offset (`2026-05-12T10:00:00+05:30`).

Round-trip evidence requires the Py SHA-256-over-canonical-bytes and
the TS SHA-256-over-canonical-bytes to MATCH the committed
`.sha256` sidecar for each fixture. The two languages MUST agree on
the same canonical byte stream.

## Symmetry guarantee

Py and TS canonical serializers MUST emit identical byte streams for
identical input. The W1.6 corpus is the binding evidence; any future
change to either canonicalizer that breaks byte-equality fails the
corpus and blocks release.

## Test references

- `packages/schemas/python/tests/test_golden_corpus.py` -- VAL-W1-042
  cases `test_timestamp_z_roundtrip_byte_equal_cross_language` and
  `test_timestamp_offset_preserved_cross_language`.
- `packages/schemas/typescript/test/golden_corpus.test.ts` -- mirror.
- `packages/schemas/python/tests/golden_corpus/timestamp_z.json`,
  `packages/schemas/python/tests/golden_corpus/timestamp_offset.json`
  -- the fixtures used by both languages.
