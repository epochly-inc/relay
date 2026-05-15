# ACEF Architecture Guide

This document describes the internal architecture of the ACEF Reference SDK. It is intended for developers extending the SDK, implementers building ACEF-compatible tools in other languages, and architects evaluating ACEF for integration.

**Normative reference:** All design decisions trace back to the [ACEF Specification v0.3](../planning/ACEF-Spec-Outline-v0.1.md). Where this document describes behavior, the spec is authoritative.

---

## Table of Contents

1. [Module Architecture](#1-module-architecture)
2. [Data Model](#2-data-model)
3. [Bundle Layout](#3-bundle-layout)
4. [Integrity Model](#4-integrity-model)
5. [Validation Pipeline](#5-validation-pipeline)
6. [Rule DSL](#6-rule-dsl)
7. [Provision Rollup Algorithm](#7-provision-rollup-algorithm)
8. [Assessment Bundle](#8-assessment-bundle)
9. [Security Model](#9-security-model)
10. [Extension Points](#10-extension-points)

---

## 1. Module Architecture

The SDK uses a strictly layered architecture. Each layer depends only on layers below it. Circular imports are prevented by design.

```
Layer 9: render.py, cli/              Human-readable output, CLI commands
         |
Layer 8: redaction.py, merge.py       Privacy operations, multi-source merge
         |
Layer 7: assessment_builder.py        Top-level validate() and export_assessment()
         |
Layer 6: validation/                  4-phase validation pipeline
         |  engine.py                 Pipeline orchestrator
         |  operators.py              10 DSL operators
         |  rollup.py                 7-step provision rollup
         |  rule_engine.py            Per-subject rule evaluation
         |  schema_validator.py       JSON Schema checks
         |  integrity_checker.py      Hash/Merkle/signature checks
         |  reference_checker.py      Entity ref and path checks
         |
Layer 5: templates/                   Regulation mapping templates
         |  registry.py              Template discovery and loading
         |  models.py                Template, Provision, EvaluationRule
         |  *.json                   11 regulation template files
         |
Layer 4: signing.py                   JWS signing/verification (RS256, ES256)
         |
Layer 3: export.py, loader.py         Serialization and deserialization
         |
Layer 2: package.py                   Core package builder
         |
Layer 1: integrity.py                 RFC 8785, SHA-256, Merkle tree
         |
Layer 0: errors.py, models/           Error taxonomy, Pydantic data models
```

### Dependency Rules

- **No upward imports.** `integrity.py` (Layer 1) never imports from `package.py` (Layer 2).
- **Cross-layer access uses public APIs only.** Modules that need to reconstruct a `Package` from deserialized data use `Package._init_from_parts()` rather than reaching into private attributes.
- **Templates are data, not code.** The 11 regulation template JSON files are loaded by `registry.py` and parsed into `Template` model objects. Template files never contain executable code.
- **CLI commands are thin wrappers.** Each `*_cmd.py` file delegates to the SDK's Python API. No business logic lives in the CLI layer.

### Key Module Responsibilities

| Module | Responsibility |
|---|---|
| `errors.py` | Error taxonomy (ACEF-001 through ACEF-060) with severity and category. Base exception classes. `ValidationDiagnostic` for collecting errors within a phase. |
| `models/` | Pydantic v2 models for all data structures: subjects, entities, records, manifest, assessment, enums, URNs. |
| `integrity.py` | RFC 8785 canonicalization via the `rfc8785` library. SHA-256 hashing for JSON, JSONL, and binary files. Merkle tree construction with odd-leaf promotion. Content hash computation and verification. |
| `package.py` | The `Package` class -- the primary builder API. Methods for adding subjects, entities, records, profiles, attachments. Builds the manifest. Delegates export to `export.py`. |
| `export.py` | Writes directory bundles and deterministic `.acef.tar.gz` archives. Handles JSONL canonicalization, sharding, content hash generation, Merkle tree writing. |
| `loader.py` | Reads directory bundles and `.acef.tar.gz` archives. Includes tar bomb protection (10 GB total, 100k files, 1 GB per file). Path traversal rejection. |
| `signing.py` | JWS detached signatures per RFC 7515. RS256 and ES256 only. Auto-derives JWK from private key when x5c is not provided. Assessment Bundle signing. |
| `templates/` | Template discovery, loading (with LRU cache), and digest computation. `Template` model with provisions and evaluation rules. |
| `validation/` | 4-phase validation orchestrated by `engine.py`. 10 DSL operators in `operators.py`. 7-step rollup in `rollup.py`. |
| `assessment_builder.py` | Top-level `validate()` function that accepts a `Package` or path. `export_assessment()` for writing Assessment Bundle JSON files. |
| `redaction.py` | SHA-256 hash-commitment redaction. Replaces payloads with hash commitments while preserving the original hash for verification. |
| `merge.py` | Multi-source merge with conflict detection. Three strategies: `keep_latest`, `keep_all`, `fail`. |
| `render.py` | Generates Markdown and console-formatted compliance reports from `AssessmentBundle` objects. |

---

## 2. Data Model

### Envelope Structure (per spec Section 3.1)

The ACEF data model follows an envelope pattern inspired by OTLP's resource-scope-record model:

```
ACEFPackage
├── metadata                    PackageMetadata
│   ├── package_id              urn:acef:pkg:<uuid>
│   ├── timestamp               ISO 8601
│   ├── producer                ProducerInfo (name, version)
│   ├── prior_package_ref       SHA-256 bundle digest (for chaining)
│   └── retention_policy        RetentionPolicy (min_retention_days)
│
├── versioning                  Versioning
│   ├── core_version            "1.0.0"
│   └── profiles_version        "1.0.0"
│
├── subjects[]                  Subject
│   ├── subject_id              urn:acef:sub:<uuid>
│   ├── subject_type            ai_system | ai_model
│   ├── name, version, provider
│   ├── risk_classification     high-risk | gpai | gpai-systemic | limited-risk | minimal-risk
│   ├── modalities[]            text, image, audio, video, multimodal
│   ├── lifecycle_phase         design | development | testing | deployment | monitoring | decommission
│   └── lifecycle_timeline[]    LifecycleEntry (phase, start_date, end_date)
│
├── entities                    EntitiesBlock
│   ├── components[]            Component (component_id, name, type, version, subject_refs)
│   ├── datasets[]              Dataset (dataset_id, name, source_type, modality, size)
│   ├── actors[]                Actor (actor_id, role, name, organization)
│   └── relationships[]         Relationship (source_ref, target_ref, type, description)
│
├── profiles[]                  ProfileEntry
│   ├── profile_id              e.g., "eu-ai-act-2024"
│   ├── template_version        "1.0.0"
│   └── applicable_provisions[] e.g., ["article-9", "article-10"]
│
├── evidence_records[]          RecordEnvelope (stored in records/*.jsonl, not in manifest)
│   ├── record_id               urn:acef:rec:<uuid>
│   ├── record_type             One of 16 v1 types or x-prefixed extension
│   ├── provisions_addressed[]  e.g., ["article-9.1"]
│   ├── timestamp               ISO 8601
│   ├── obligation_role         provider | deployer | ... | platform
│   ├── confidentiality         public | redacted | hash-committed | regulator-only | under-nda
│   ├── trust_level             self-attested | peer-reviewed | independently-verified | notified-body-certified
│   ├── entity_refs             EntityRefs (subject_refs, component_refs, dataset_refs, actor_refs)
│   ├── payload                 Type-specific evidence data (validated per record_type schema)
│   ├── attachments[]           AttachmentRef (path, hash, media_type, attachment_type)
│   ├── attestation             Attestation (method, signer, signed_fields, signature)
│   └── retention               RecordRetention (min_retention_days, retention_start_event, legal_basis)
│
└── audit_trail[]               AuditTrailEntry
    ├── event_type              created | updated | reviewed | submitted | certified
    ├── timestamp               ISO 8601
    ├── actor_ref               urn:acef:act:<uuid>
    └── description             What changed
```

### Entity Graph

Entities form a W3C PROV-compatible directed graph:

- **Nodes**: Subjects, Components, Datasets, Actors (each with a unique URN)
- **Edges**: Relationships with typed connections

Supported relationship types (per spec):

| Type | Meaning | Example |
|---|---|---|
| `wraps` | System wraps a model | RAG system wraps LLM |
| `calls` | System calls component | System calls retriever |
| `fine_tunes` | Model fine-tunes base | Custom model fine-tunes GPT-4 |
| `deploys` | Actor deploys system | Provider deploys to production |
| `trains_on` | Model trains on dataset | LLM trains on CommonCrawl |
| `evaluates_with` | System evaluated with dataset | System evaluated with benchmark |
| `oversees` | Actor oversees system | Auditor oversees deployment |

### URN Format

All identifiers use the URN scheme `urn:acef:{type}:{uuid}`:

| Type Code | Entity |
|---|---|
| `pkg` | Package |
| `sub` | Subject |
| `cmp` | Component |
| `dat` | Dataset |
| `act` | Actor |
| `rec` | Record |
| `asx` | Assessment |

URNs are generated using `uuid4()` and are guaranteed unique within a package.

---

## 3. Bundle Layout

### Directory Structure (per spec Section 3.1.1)

```
my-system-evidence.acef/
├── acef-manifest.json              # Envelope (metadata, subjects, entities, profiles, audit_trail)
├── records/                        # Evidence records in JSONL format
│   ├── risk_register.jsonl         # One file per record type (single shard)
│   ├── event_log/                  # Sharded directory for large record sets
│   │   ├── event_log.0001.jsonl
│   │   └── event_log.0002.jsonl
│   └── ...
├── artifacts/                      # Binary attachments (PDFs, CSVs, images)
│   ├── eval-report-v3.pdf
│   └── model-card.md
├── hashes/                         # Integrity files (OUTSIDE hash domain)
│   ├── content-hashes.json         # SHA-256 hash of every file in the hash domain
│   └── merkle-tree.json            # Merkle tree with root hash
└── signatures/                     # Detached JWS signatures (OUTSIDE hash domain)
    └── provider-key.jws
```

### JSONL Format

All record files use JSON Lines format (`.jsonl`). Each line is one record, RFC 8785-canonicalized, followed by `\n` (0x0A). Records within each file are sorted by `timestamp` ascending, then by `record_id` ascending for deterministic output.

### Sharding Algorithm (per spec Section 3.1.1)

Record files are split into shards when they exceed thresholds:

1. Split at the **earlier** of 100,000 records or 256 MB.
2. If 100,000 records fit within 256 MB, split at exactly 100,000.
3. Shard numbers are zero-padded to 4 digits (e.g., `event_log.0001.jsonl`).
4. Sharded files go into a subdirectory named after the record type.

This algorithm is deterministic: two exporters given the same logical record set produce identical shard boundaries.

### Archive Format

When packed as `.acef.tar.gz`, the archive follows strict canonicalization rules for byte-identical output:

| Property | Required Value |
|---|---|
| File order | Lexicographic by path |
| File timestamps | `metadata.timestamp` (Unix epoch seconds, UTC) |
| Owner/Group | 0/0 |
| File permissions | 0644 |
| Directory permissions | 0755 |
| Gzip compression level | 6 |
| Gzip mtime | 0 |
| Gzip OS byte | 0xFF (unknown) |
| Symlinks/hardlinks | Forbidden |

### Path Normalization

All paths in the manifest and hash files must:

- Use forward slashes (`/`)
- Be relative to the bundle root
- Use UTF-8 NFC normalization
- Not contain `.` or `..` segments
- Not contain backslash separators

---

## 4. Integrity Model

The integrity model avoids circular dependencies by defining a strict, non-overlapping hash domain (per spec Section 3.1.3).

### Hash Domain

**Files that ARE hashed** (the hash domain):
- `acef-manifest.json`
- Everything in `records/`
- Everything in `artifacts/`

**Files that are NOT hashed** (outside the hash domain):
- `hashes/content-hashes.json`
- `hashes/merkle-tree.json`
- `signatures/*.jws`

This separation is critical: the manifest contains no hash of itself or any reference to the hashes/ directory, eliminating all circular dependencies.

### Canonicalization (RFC 8785)

All JSON files in the hash domain are canonicalized using RFC 8785 (JCS) before hashing:

- JSON files (`.json`): Parse, canonicalize, hash the canonical bytes.
- JSONL files (`.jsonl`): Each line is independently canonicalized. The hash covers the concatenation of `canonical_line + \n` for all lines.
- Binary files: Hashed as raw bytes using 64 KB chunked streaming.

### Content Hashes

`content-hashes.json` is an RFC 8785-canonicalized JSON object mapping relative paths (lexicographically sorted) to lowercase hex-encoded SHA-256 hashes:

```json
{
  "acef-manifest.json": "a1b2c3d4...",
  "artifacts/eval-report.pdf": "e5f6a7b8...",
  "records/risk_register.jsonl": "c9d0e1f2..."
}
```

### Merkle Tree

`merkle-tree.json` is built from the sorted entries of `content-hashes.json`:

- **Leaf nodes**: `SHA-256(path_utf8_bytes || 0x00 || hash_hex_utf8_bytes)`
- **Inner nodes**: `SHA-256(left_raw_32_bytes || right_raw_32_bytes)`
- **Odd leaf**: Promoted unchanged (NOT duplicated)
- **Root**: The single remaining hash

```json
{
  "leaves": [
    {"path": "acef-manifest.json", "hash": "a1b2c3d4..."},
    {"path": "records/risk_register.jsonl", "hash": "c9d0e1f2..."}
  ],
  "root": "f3e4d5c6..."
}
```

### Bundle Digest

The canonical identity of an ACEF Evidence Bundle is:

```
sha256:<SHA-256 of RFC 8785-canonicalized content-hashes.json>
```

This single value is used for `prior_package_ref` (version chaining), `evidence_bundle_ref.content_hash` in Assessment Bundles, and any future registry APIs.

### JWS Signatures

Signatures are detached JWS (RFC 7515) over the raw bytes of canonicalized `content-hashes.json`:

- **Algorithms**: RS256 and ES256 only. All other algorithms are rejected (ACEF-013).
- **Header requirements**: Must include `alg` and either `x5c` (certificate chain) or `jwk` (public key).
- **Unsigned bundles are valid.** Signatures are optional. Profiles may require them via DSL rules.
- **Trust model**: `x5c` proves organizational identity; `jwk` alone proves data integrity but not identity.

---

## 5. Validation Pipeline

The validation engine (`validation/engine.py`) runs four sequential phases. Per spec Section 3.6, validators report ALL errors within each phase before moving to the next.

### Phase 1: Schema Validation

1. Validate `acef-manifest.json` against `acef-conventions/v1/manifest.schema.json`.
2. For each record in `records/`, validate the common envelope against `record-envelope.schema.json`.
3. For each record, validate the `payload` against the record-type-specific schema (e.g., `risk_register.schema.json`).
4. Check module version compatibility (ACEF-001).

### Phase 2: Integrity Verification

1. Canonicalize (RFC 8785) and hash (SHA-256) every file in the hash domain.
2. Compare against entries in `content-hashes.json`. Mismatches produce ACEF-010 (fatal).
3. Files in the domain missing from `content-hashes.json`, or entries with no corresponding file, produce ACEF-014 (fatal).
4. Recompute the Merkle tree. Root mismatch produces ACEF-011 (fatal).
5. Verify each signature in `signatures/`. Invalid signatures produce ACEF-012 (fatal).

### Phase 3: Reference Checking

1. Verify all `entity_refs` URNs resolve to entities declared in the manifest.
2. Check `record_files` paths exist on disk.
3. Detect duplicate URNs within the package (ACEF-021).
4. Detect duplicate `record_id` values (ACEF-026).
5. Verify record counts match between manifest and actual JSONL files (ACEF-025).
6. Verify attachment paths reference files in `artifacts/` (ACEF-023).

### Phase 4: Rule Evaluation

This phase runs only when profiles are specified. For each profile:

1. Load the regulation mapping template by `profile_id`.
2. Check for duplicate `rule_id` values within the template (ACEF-044).
3. Record the template digest in the Assessment Bundle.
4. Filter provisions to those declared applicable in the manifest's `profiles[]`.
5. Split provisions into **package-scoped** (`evaluation_scope: "package"`) and **per-subject** (default).
6. Evaluate package-scoped provisions once against all records.
7. Evaluate per-subject provisions once per subject, filtering records by entity refs.
8. For each provision, compute the outcome using the 7-step rollup algorithm.

---

## 6. Rule DSL

The ACEF DSL defines 10 built-in operators for regulation mapping templates (per spec Section 3.5). Each operator takes parameters and a list of records, returning a `(passed: bool, evidence_refs: list[str])` tuple.

### Operator Reference

| Operator | Type | Empty-Set Behavior | Description |
|---|---|---|---|
| `has_record_type` | Existential | FAIL on zero records | At least `min_count` records of given type exist |
| `field_present` | Universal | PASS (vacuous truth) | Every record of given type has non-null value at JSON Pointer path |
| `field_value` | Universal | PASS (vacuous truth) | Field value satisfies comparison for every record of given type |
| `evidence_freshness` | Universal | PASS (vacuous truth) | All records within scope have timestamp within `max_days` of reference date |
| `attachment_exists` | Existential | FAIL on zero records | At least one record of given type has an attachment (optional `media_type` filter) |
| `entity_linked` | Universal | PASS (vacuous truth) | Every record of given type has at least one entity ref of given type |
| `exists_where` | Existential | FAIL on zero records | At least `min_count` records exist where field satisfies comparison |
| `attachment_kind_exists` | Existential | FAIL on zero records | Records of given type have attachments with matching `attachment_type` |
| `bundle_signed` | Existential | FAIL on zero sigs | Bundle has at least `min_signatures` valid signatures |
| `record_attested` | Existential | FAIL on zero records | At least `min_count` records have valid attestation blocks |

### Empty-Set Semantics

Per spec Section 3.5:

- **Existential operators** (has_record_type, exists_where, attachment_exists, attachment_kind_exists, bundle_signed, record_attested): FAIL when zero records match. These require something to exist.
- **Universal operators** (field_present, field_value, evidence_freshness, entity_linked): PASS vacuously when zero records match. "For all X in empty set, P(X)" is vacuously true.

### Missing-Path Behavior

When a JSON Pointer (RFC 6901) path does not resolve in a record:

- `field_present`: Returns `None`, meaning the field is not present (FAIL for that record).
- `field_value`: `None` fails all comparisons except `ne`. Missing path means the condition is not met.
- `exists_where`: `None` fails the comparison (record does not match the filter).

### Comparison Operators

The `field_value` and `exists_where` operators support these comparison operators:

| Op | Meaning |
|---|---|
| `eq` | Equal |
| `ne` | Not equal |
| `gt` | Greater than |
| `gte` | Greater than or equal |
| `lt` | Less than |
| `lte` | Less than or equal |
| `in` | Value is in list |
| `regex` | ECMA-262 regex search (with ReDoS protection) |

### Scope Filters and Conditions

Each rule can have optional scope filters and conditions:

```json
{
  "rule_id": "art9-risk-register-exists",
  "rule": "has_record_type",
  "params": {"type": "risk_register", "min_count": 1},
  "severity": "fail",
  "scope": {
    "risk_classifications": ["high-risk"],
    "obligation_roles": ["provider"],
    "lifecycle_phases": ["deployment", "monitoring"]
  },
  "condition": {
    "if_provision_effective": true
  }
}
```

- **`scope.risk_classifications`**: Rule applies only to subjects with matching risk classification.
- **`scope.obligation_roles`**: Rule applies only to records with matching obligation role.
- **`scope.lifecycle_phases`**: Rule applies only during these lifecycle phases.
- **`scope.modalities`**: Rule applies only to subjects with matching modalities.
- **`condition.if_provision_effective`**: Rule is skipped if the provision's effective date has not yet passed relative to `evaluation_instant`.

### ReDoS Mitigation

The `regex` comparison operator includes multiple protections against regular expression denial-of-service:

1. **Pattern length limit**: 1,024 characters maximum.
2. **Input length limit**: 1,000,000 characters maximum.
3. **Timeout**: 5-second SIGALRM-based timeout on Unix systems (main thread only).

---

## 7. Provision Rollup Algorithm

The 7-step deterministic precedence algorithm computes a single `ProvisionOutcome` from a set of `RuleResult` values for a given provision (per spec Section 3.7). Steps are evaluated in order; the first matching step determines the outcome.

| Step | Condition | Outcome |
|---|---|---|
| 1 | Any rule with `severity: fail` has `outcome: failed` | `not-satisfied` |
| 2 | Any rule has `outcome: error` | `not-assessed` |
| 3 | All rules have `outcome: skipped` | `skipped` |
| 4 | An `evidence_gap` record exists addressing this provision (and no fail-severity failures) | `gap-acknowledged` |
| 5 | All fail-severity rules passed, but some warning-severity rules failed | `partially-satisfied` |
| 6 | All evaluated rules passed (skipped rules are treated as not-applicable) | `satisfied` |
| 7 | No rules exist for this provision | `not-assessed` |

### Outcome Values

| Outcome | Meaning |
|---|---|
| `satisfied` | All mandatory rules passed |
| `not-satisfied` | At least one mandatory rule failed |
| `partially-satisfied` | All mandatory rules passed, some advisory rules failed |
| `gap-acknowledged` | Missing evidence explicitly declared via `evidence_gap` record |
| `skipped` | All rules were skipped (provision not applicable) |
| `not-assessed` | No rules evaluated, or a rule errored |

---

## 8. Assessment Bundle

The Assessment Bundle is a separate JSON artifact (`.acef-assessment.json`) that contains validation results for an Evidence Bundle.

### Structure

```json
{
  "versioning": {
    "core_version": "1.0.0",
    "assessment_version": "1.0.0"
  },
  "assessment_id": "urn:acef:asx:<uuid>",
  "timestamp": "2026-03-17T00:00:00Z",
  "evaluation_instant": "2026-03-17T00:00:00Z",
  "assessor": {
    "name": "acef-validator",
    "version": "1.0.0",
    "organization": "AI Commons"
  },
  "evidence_bundle_ref": {
    "package_id": "urn:acef:pkg:<uuid>",
    "content_hash": "sha256:<digest>"
  },
  "profiles_evaluated": ["eu-ai-act-2024:1.0.0"],
  "template_digests": {
    "eu-ai-act-2024:1.0.0": "sha256:<digest>"
  },
  "results": [
    {
      "rule_id": "art9-risk-register-exists",
      "provision_id": "article-9",
      "profile_id": "eu-ai-act-2024",
      "rule_severity": "fail",
      "outcome": "passed",
      "message": null,
      "evidence_refs": ["urn:acef:rec:<uuid>"],
      "subject_scope": ["urn:acef:sub:<uuid>"]
    }
  ],
  "provision_summary": [
    {
      "provision_id": "article-9",
      "profile_id": "eu-ai-act-2024",
      "provision_outcome": "satisfied",
      "subject_scope": ["urn:acef:sub:<uuid>"],
      "fail_count": 0,
      "warning_count": 0,
      "skipped_count": 0,
      "evidence_refs": ["urn:acef:rec:<uuid>"]
    }
  ],
  "structural_errors": [],
  "integrity": null
}
```

### Key Design Decisions

- **`evaluation_instant`**: All date-sensitive rule logic uses this single reference timestamp. Wall-clock time is never used during evaluation (per spec Section 3.7).
- **`template_digests`**: SHA-256 of the RFC 8785-canonicalized template, enabling reproducible assessments.
- **`evidence_bundle_ref.content_hash`**: The bundle digest, enabling cryptographic binding between assessment and evidence.
- **Versioning**: Assessment Bundles declare `core_version` and `assessment_version` (NOT `profiles_version`, which belongs to Evidence Bundles).

### Signing Procedure

1. Set `integrity` to `null`.
2. Canonicalize the entire Assessment Bundle via RFC 8785.
3. Sign the canonical bytes with a detached JWS.
4. Populate the `integrity` block with the JWS value.

---

## 9. Security Model

### Path Traversal Prevention

Three defense layers:

1. **`Package.add_attachment()`**: Rejects paths with `..`, `.`, backslashes, and absolute paths before storing.
2. **`export.py`**: Re-validates all attachment paths during export (defense-in-depth).
3. **`loader.py`**: Validates all paths from the manifest before reading from disk. Rejects `..`, `.`, backslashes, and absolute paths.

### Tar Bomb Protection

The loader enforces these limits when extracting `.acef.tar.gz` archives:

| Limit | Value |
|---|---|
| Maximum total extracted size | 10 GB |
| Maximum file count | 100,000 |
| Maximum single file size | 1 GB |
| Symlinks/hardlinks | Rejected |

On Python 3.12+, the loader uses `tar.extractall(filter="data")` for additional safety.

### Algorithm Whitelist

The signing module enforces a strict algorithm whitelist:

- **Allowed**: RS256, ES256
- **All other algorithms**: Rejected with ACEF-013

For ES256, only the P-256 curve (NIST secp256r1) is accepted.

### ReDoS Mitigation

The `regex` comparison operator in the DSL includes:

- Pattern length capped at 1,024 characters
- Input string length capped at 1,000,000 characters
- 5-second SIGALRM timeout on Unix/main thread

### JWS Validation

- Maximum x5c certificate size: 65,536 bytes
- JWK key type whitelist: RSA and EC (P-256 only)
- Signature format validation: ES256 signatures must be exactly 64 bytes (32-byte r + 32-byte s)

### Memory Protection

- Binary files are hashed using 64 KB chunked streaming (never loaded entirely into memory).
- Archive files are streamed through gzip compression in 64 KB chunks.
- Artifact loading enforces cumulative size limits (10 GB total across all artifacts).

---

## 10. Extension Points

### Custom Record Types

Record types prefixed with `x-` are treated as vendor extensions:

```python
pkg.record(
    "x-myorg/custom-audit",
    payload={"custom_field": "value"},
    provisions=["custom-provision"],
)
```

Extension record types bypass the built-in record type validation. Per spec Section 3.3, custom schemas should be placed in `acef-conventions/extensions/`.

### Vendor Operators

Per spec Section 3.5, vendor-specific DSL operators use namespaced prefixes and must be safely ignorable by standard validators. Unknown operators produce a skipped rule outcome rather than an error.

### Template Extensions

Templates can include `x-` prefixed fields at any level:

```json
{
  "template_id": "x-myorg-custom-framework",
  "provisions": [
    {
      "provision_id": "custom-1",
      "x-myorg-internal-id": "INT-001"
    }
  ]
}
```

Standard validators ignore `x-` prefixed fields. Per spec Section 3.1, vendor extension fields must not affect conformance outcomes (ACEF-053).
