# ACEF API Reference

Complete Python API documentation for the ACEF Reference SDK.

**Module**: `acef`
**Version**: 0.1.0
**Python**: >= 3.11

---

## Table of Contents

1. [Top-Level Functions](#1-top-level-functions)
2. [acef.Package](#2-acefpackage)
3. [Validation and Assessment](#3-validation-and-assessment)
4. [Signing and Verification](#4-signing-and-verification)
5. [Redaction](#5-redaction)
6. [Merging](#6-merging)
7. [Rendering](#7-rendering)
8. [Models Reference](#8-models-reference)
9. [Enums Reference](#9-enums-reference)
10. [Error Types](#10-error-types)

---

## 1. Top-Level Functions

The `acef` module exposes these top-level functions and classes:

```python
import acef

# Core
acef.Package             # Evidence package builder
acef.load(path)          # Load bundle from directory or archive
acef.chain(path, **kw)   # Create a chained package from a prior bundle
acef.validate(pkg, ...)  # Validate and produce an Assessment Bundle

# Signing
acef.sign(bundle_dir, key_path, *, kid)  # Sign an exported bundle
acef.verify(jws, payload, ...)           # Verify a detached JWS

# Assessment
acef.export_assessment(assessment, path, *, key_path)  # Export Assessment Bundle

# Privacy
acef.redact(pkg, *, record_filter, method, access_policy)  # Redact a package
acef.redact_record(record, *, method, access_policy)        # Redact a single record

# Multi-source
acef.merge(packages, *, producer, conflict_strategy)  # Merge packages

# Reports
acef.render(assessment)                    # Render Markdown report
acef.render_console(assessment)            # Render console summary
acef.render_markdown(assessment)           # Render Markdown report (explicit)
```

### `acef.load(path: str) -> Package`

Load an ACEF Evidence Bundle from a directory or `.acef.tar.gz` archive.

**Parameters:**

| Name | Type | Description |
|---|---|---|
| `path` | `str` | Path to a bundle directory or `.acef.tar.gz` archive |

**Returns:** `Package` -- a fully reconstructed package.

**Raises:**
- `ACEFFormatError` -- if the bundle is malformed, corrupt, or not a valid format.
- `ACEFSchemaError` -- if the manifest is invalid.

```python
pkg = acef.load("my-evidence.acef/")
pkg = acef.load("my-evidence.acef.tar.gz")
```

### `acef.chain(prior_bundle_path: str, **kwargs) -> Package`

Create a new package chained to a prior Evidence Bundle. Computes the bundle digest of the prior bundle and sets it as `prior_package_ref` on the new package.

**Parameters:**

| Name | Type | Description |
|---|---|---|
| `prior_bundle_path` | `str` | Path to the prior bundle directory or archive |
| `**kwargs` | | Additional arguments passed to `Package()` constructor |

**Returns:** `Package` -- a new package with `prior_package_ref` set.

```python
pkg_v2 = acef.chain(
    "v1-evidence.acef/",
    producer={"name": "my-tool", "version": "2.0"},
)
print(pkg_v2.metadata.prior_package_ref)  # "sha256:a1b2c3d4..."
```

### `acef.validate(package_or_path, *, profiles, evaluation_instant) -> AssessmentBundle`

Validate a package or bundle and produce an Assessment Bundle.

**Parameters:**

| Name | Type | Default | Description |
|---|---|---|---|
| `package_or_path` | `Package \| str \| Path` | | A Package object, directory path, or archive path |
| `profiles` | `list[str] \| None` | `None` | Profile IDs to evaluate (e.g., `["eu-ai-act-2024"]`) |
| `evaluation_instant` | `str \| None` | `None` | Override evaluation timestamp (ISO 8601). Defaults to current UTC time. |

**Returns:** `AssessmentBundle` -- assessment results including rule outcomes, provision summaries, and structural errors.

```python
# Validate a Package object
assessment = acef.validate(pkg, profiles=["eu-ai-act-2024"])

# Validate a directory
assessment = acef.validate("bundle.acef/", profiles=["nist-ai-rmf-1.0"])

# Validate an archive
assessment = acef.validate("bundle.acef.tar.gz")

# With fixed evaluation time (for reproducible assessments)
assessment = acef.validate(pkg, profiles=["eu-ai-act-2024"],
                           evaluation_instant="2026-08-02T00:00:00Z")
```

### `acef.export_assessment(assessment, output_path, *, key_path) -> Path`

Export an Assessment Bundle to a JSON file.

**Parameters:**

| Name | Type | Default | Description |
|---|---|---|---|
| `assessment` | `AssessmentBundle` | | The assessment to export |
| `output_path` | `str` | | Output file path |
| `key_path` | `str \| None` | `None` | Path to PEM private key for signing |

**Returns:** `Path` -- path to the created file.

```python
acef.export_assessment(assessment, "assessment.acef-assessment.json")

# With signing
acef.export_assessment(assessment, "signed-assessment.json", key_path="private.pem")
```

---

## 2. acef.Package

The primary API for building ACEF Evidence Bundles.

### Constructor

```python
Package(
    producer: dict[str, str] | ProducerInfo | None = None,
    *,
    retention_policy: dict[str, Any] | RetentionPolicy | None = None,
    prior_package_ref: str | None = None,
)
```

**Parameters:**

| Name | Type | Default | Description |
|---|---|---|---|
| `producer` | `dict \| ProducerInfo \| None` | `ProducerInfo("acef-sdk", "0.1.0")` | Tool/organization that created this package. Dict with `name` and `version` keys. |
| `retention_policy` | `dict \| RetentionPolicy \| None` | `None` | Package-level retention. Dict with `min_retention_days` (int). |
| `prior_package_ref` | `str \| None` | `None` | Bundle digest of a prior package (for version chaining). |

```python
pkg = acef.Package(
    producer={"name": "my-tool", "version": "1.0"},
    retention_policy={"min_retention_days": 3650},
)
```

### Properties

| Property | Type | Description |
|---|---|---|
| `metadata` | `PackageMetadata` | Package-level metadata (package_id, timestamp, producer) |
| `versioning` | `Versioning` | Module versions (core_version, profiles_version) |
| `subjects` | `list[Subject]` | Declared subjects (read-only copy) |
| `entities` | `EntitiesBlock` | Entity graph (components, datasets, actors, relationships) |
| `records` | `list[RecordEnvelope]` | Evidence records (read-only copy) |
| `profiles` | `list[ProfileEntry]` | Declared profiles (read-only copy) |
| `audit_trail` | `list[AuditTrailEntry]` | Audit trail entries (read-only copy) |
| `attachments` | `dict[str, bytes]` | Attachment path-to-content mapping (read-only copy) |
| `is_signed` | `bool` | Whether the package is marked for signing |
| `signing_key` | `str \| None` | Path to signing key, if set |

### `add_subject(...) -> Subject`

Add a subject (AI system or model) to the package.

```python
add_subject(
    subject_type: str | SubjectType,
    name: str,
    *,
    version: str = "1.0.0",
    provider: str = "",
    risk_classification: str | RiskClassification = "minimal-risk",
    modalities: list[str] | None = None,
    lifecycle_phase: str | LifecyclePhase = "development",
    lifecycle_timeline: list[dict[str, str]] | None = None,
) -> Subject
```

**Returns:** `Subject` with a generated URN (`urn:acef:sub:<uuid>`).

```python
system = pkg.add_subject(
    "ai_system",
    name="My System",
    version="2.0.0",
    provider="Acme Corp",
    risk_classification="high-risk",
    modalities=["text", "image"],
    lifecycle_phase="deployment",
    lifecycle_timeline=[
        {"phase": "development", "start_date": "2025-01-01", "end_date": "2025-12-31"},
        {"phase": "deployment", "start_date": "2026-01-01"},
    ],
)
print(system.id)  # "urn:acef:sub:550e8400-..."
```

### `add_component(...) -> Component`

Add a component entity to the package.

```python
add_component(
    name: str,
    type: str | ComponentType,
    *,
    version: str = "1.0.0",
    subject_refs: list[str] | None = None,
    provider: str = "",
) -> Component
```

### `add_dataset(...) -> Dataset`

Add a dataset entity to the package.

```python
add_dataset(
    name: str,
    *,
    version: str = "1.0.0",
    source_type: str | DatasetSourceType = "licensed",
    modality: str | DatasetModality = "text",
    size: dict[str, Any] | None = None,
    subject_refs: list[str] | None = None,
) -> Dataset
```

### `add_actor(...) -> Actor`

Add an actor entity to the package.

```python
add_actor(
    name: str = "",
    *,
    role: str | ActorRole = "provider",
    organization: str = "",
) -> Actor
```

### `add_relationship(...) -> Relationship`

Add a relationship between entities.

```python
add_relationship(
    source_ref: str,
    target_ref: str,
    relationship_type: str | RelationshipType,
    *,
    description: str = "",
) -> Relationship
```

### `add_profile(...) -> ProfileEntry`

Declare a regulation profile for this package.

```python
add_profile(
    profile_id: str,
    *,
    provisions: list[str] | None = None,
    template_version: str = "1.0.0",
) -> ProfileEntry
```

### `record(...) -> RecordEnvelope`

Record an evidence record. This is the primary method for adding evidence.

```python
record(
    record_type: str,
    *,
    provisions: list[str] | None = None,
    payload: dict[str, Any] | None = None,
    obligation_role: str | ObligationRole | None = None,
    entity_refs: dict[str, list[str]] | EntityRefs | None = None,
    confidentiality: str | Confidentiality = "public",
    redaction_method: str | None = None,
    access_policy: dict[str, Any] | None = None,
    trust_level: str | TrustLevel = "self-attested",
    lifecycle_phase: str | LifecyclePhase | None = None,
    collector: dict[str, str] | CollectorInfo | None = None,
    attachments: list[dict[str, Any] | AttachmentRef] | None = None,
    attestation: dict[str, Any] | Attestation | None = None,
    retention: dict[str, Any] | RecordRetention | None = None,
    timestamp: str | None = None,
) -> RecordEnvelope
```

**Parameters:**

| Name | Type | Default | Description |
|---|---|---|---|
| `record_type` | `str` | | One of 16 ACEF v1 record types, or `x-` prefixed extension type |
| `provisions` | `list[str] \| None` | `None` | Regulatory provisions this evidence supports |
| `payload` | `dict \| None` | `None` | Type-specific evidence payload |
| `obligation_role` | `str \| ObligationRole \| None` | `None` | Who produced this evidence |
| `entity_refs` | `dict \| EntityRefs \| None` | `None` | Links to subjects, components, datasets, actors |
| `confidentiality` | `str \| Confidentiality` | `"public"` | Evidence confidentiality level |
| `trust_level` | `str \| TrustLevel` | `"self-attested"` | Evidence provenance level |
| `lifecycle_phase` | `str \| LifecyclePhase \| None` | `None` | Related lifecycle phase |
| `collector` | `dict \| CollectorInfo \| None` | `None` | Tool/person that collected this evidence |
| `attachments` | `list \| None` | `None` | File references in artifacts/ |
| `attestation` | `dict \| Attestation \| None` | `None` | Cryptographic attestation |
| `retention` | `dict \| RecordRetention \| None` | `None` | Per-record retention requirements |
| `timestamp` | `str \| None` | `None` | Override timestamp (ISO 8601) |

**Raises:**
- `ACEFSchemaError` (ACEF-003) -- if `record_type` is not recognized and does not start with `x-`.
- `ACEFError` (ACEF-050) -- if `timestamp` is not valid ISO 8601.

### `add_attachment(path: str, content: bytes) -> None`

Add an attachment file to be included in `artifacts/`.

**Parameters:**

| Name | Type | Description |
|---|---|---|
| `path` | `str` | Relative path within artifacts/ (e.g., `"eval-report.pdf"`) |
| `content` | `bytes` | Raw file content |

**Raises:** `ACEFError` (ACEF-052) -- if the path contains traversal sequences, backslashes, or is absolute.

### `sign(key: str, *, method: str = "jws") -> None`

Mark this package for signing during export.

### `export(path: str) -> None`

Export the package to a directory or archive. If `path` ends with `.tar.gz`, exports as an archive; otherwise, exports as a directory bundle.

### `build_manifest() -> Manifest`

Build the Manifest object from current package state. Used internally by `export()`.

---

## 3. Validation and Assessment

### AssessmentBundle

The result of validating an Evidence Bundle.

```python
from acef.models.assessment import AssessmentBundle
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `assessment_id` | `str` | URN identifier (`urn:acef:asx:<uuid>`) |
| `timestamp` | `str` | ISO 8601 creation time |
| `evaluation_instant` | `str` | ISO 8601 reference time for date-sensitive rules |
| `assessor` | `Assessor` | Tool that performed the assessment |
| `evidence_bundle_ref` | `EvidenceBundleRef` | Reference to the evaluated Evidence Bundle |
| `profiles_evaluated` | `list[str]` | Profile IDs that were evaluated |
| `template_digests` | `dict[str, str]` | SHA-256 digests of templates used |
| `results` | `list[RuleResult]` | Individual rule evaluation results |
| `provision_summary` | `list[ProvisionSummary]` | Per-provision outcome summaries |
| `structural_errors` | `list[dict]` | Schema, integrity, and reference errors |
| `integrity` | `AssessmentIntegrity \| None` | Signature block (if signed) |

**Methods:**

| Method | Returns | Description |
|---|---|---|
| `summary()` | `str` | Human-readable summary (e.g., `"eu-ai-act-2024: 3/5 provisions passed"`) |
| `errors()` | `list[dict]` | All structural errors plus failed rule results |
| `to_dict()` | `dict` | Serialize to dict for JSON output |

### RuleResult

Result of evaluating a single DSL rule.

| Field | Type | Description |
|---|---|---|
| `rule_id` | `str` | Rule identifier from the template |
| `provision_id` | `str` | Provision this rule belongs to |
| `profile_id` | `str` | Profile/template ID |
| `rule_severity` | `RuleSeverity` | `fail`, `warning`, or `info` |
| `outcome` | `RuleOutcome` | `passed`, `failed`, `skipped`, or `error` |
| `message` | `str \| None` | Human-readable result message |
| `evidence_refs` | `list[str]` | Record IDs that contributed to the result |
| `subject_scope` | `list[str]` | Subject URNs this result applies to |

### ProvisionSummary

Roll-up summary for a single provision.

| Field | Type | Description |
|---|---|---|
| `provision_id` | `str` | Provision identifier |
| `profile_id` | `str` | Profile/template ID |
| `provision_outcome` | `ProvisionOutcome` | Outcome from 7-step rollup |
| `subject_scope` | `list[str]` | Subject URNs |
| `fail_count` | `int` | Number of fail-severity rule failures |
| `warning_count` | `int` | Number of warning-severity rule failures |
| `skipped_count` | `int` | Number of skipped rules |
| `evidence_refs` | `list[str]` | All evidence record IDs |

---

## 4. Signing and Verification

### `acef.sign(bundle_dir, key_path, *, kid) -> str`

Sign an exported bundle's `content-hashes.json`.

**Parameters:**

| Name | Type | Default | Description |
|---|---|---|---|
| `bundle_dir` | `Path` | | Path to the bundle directory |
| `key_path` | `str` | | Path to PEM private key file |
| `kid` | `str` | `"provider-key"` | Key identifier |

**Returns:** `str` -- path to the created signature file.

### `acef.verify(jws_str, payload, public_key, *, key_data) -> dict`

Verify a detached JWS signature.

**Parameters:**

| Name | Type | Default | Description |
|---|---|---|---|
| `jws_str` | `str` | | JWS compact serialization (`header..signature`) |
| `payload` | `bytes` | | Original signed data |
| `public_key` | `PublicKeyTypes \| None` | `None` | Verification key (optional if key in JWS header) |
| `key_data` | `bytes \| None` | `None` | PEM-encoded public key or certificate |

**Returns:** `dict` -- the decoded JWS header.

**Raises:** `ACEFSigningError` -- if verification fails.

### `acef.create_detached_jws(payload, private_key, *, kid, x5c) -> str`

Create a detached JWS signature.

**Parameters:**

| Name | Type | Default | Description |
|---|---|---|---|
| `payload` | `bytes` | | Data to sign |
| `private_key` | `PrivateKeyTypes` | | The signing key |
| `kid` | `str` | `""` | Key identifier |
| `x5c` | `list[str] \| None` | `None` | Certificate chain (base64 DER). If omitted, JWK is auto-derived. |

**Returns:** `str` -- JWS compact serialization with empty payload (`header..signature`).

### `acef.sign_assessment(assessment_data, key_path) -> dict`

Sign an Assessment Bundle dict.

---

## 5. Redaction

### `acef.redact(package, *, record_filter, method, access_policy) -> Package`

Create a redacted copy of a package. Alias for `redact_package()`.

**Parameters:**

| Name | Type | Default | Description |
|---|---|---|---|
| `package` | `Package` | | The package to redact |
| `record_filter` | `dict \| None` | `None` | Filter criteria. Keys: `record_types` (list), `confidentiality_levels` (list). |
| `method` | `str` | `"sha256-hash-commitment"` | Redaction method |
| `access_policy` | `dict \| None` | `None` | Who can see the full payload. Keys: `roles` (list), `organizations` (list). |

**Returns:** `Package` -- a new package with selected records redacted.

### `acef.redact_record(record, *, method, access_policy) -> RecordEnvelope`

Create a redacted copy of a single record.

**Returns:** `RecordEnvelope` with:
- `confidentiality` set to `hash-committed`
- `payload` replaced with `{"_redacted": True, "_commitment": "sha256:<hash>"}`
- `redaction_method` set to `"sha256-hash-commitment:<hash>"`

### `acef.redaction.verify_redaction(redacted_record, original_payload) -> bool`

Verify that a redacted record's hash commitment matches an original payload.

---

## 6. Merging

### `acef.merge(packages, *, producer, conflict_strategy) -> MergeResult`

Merge multiple ACEF packages into one. Alias for `merge_packages()`.

**Parameters:**

| Name | Type | Default | Description |
|---|---|---|---|
| `packages` | `list[Package]` | | Packages to merge |
| `producer` | `dict[str, str] \| None` | `{"name": "acef-merger", "version": "0.1.0"}` | Producer for merged package |
| `conflict_strategy` | `str` | `"keep_latest"` | `"keep_latest"`, `"keep_all"`, or `"fail"` |

**Returns:** `MergeResult` with `.package` (merged Package) and `.conflicts` (list of `ValidationDiagnostic`).

**Raises:** `ACEFMergeError` -- if no packages provided, unknown strategy, or `"fail"` strategy with conflicts.

### MergeResult

| Property | Type | Description |
|---|---|---|
| `package` | `Package` | The merged package |
| `conflicts` | `list[ValidationDiagnostic]` | Detected conflicts |
| `has_conflicts` | `bool` | Whether any conflicts were found |

---

## 7. Rendering

### `acef.render(assessment) -> str`

Render an Assessment Bundle as a Markdown compliance report. Alias for `render_markdown()`.

### `acef.render_markdown(assessment) -> str`

Render an Assessment Bundle as a Markdown compliance report.

**Returns:** Markdown string including:
- Assessment metadata
- Executive summary
- Provision results table
- Rule details
- Structural errors

### `acef.render_console(assessment) -> str`

Render a concise console-formatted summary.

**Returns:** Plain text string with outcome symbols (`[PASS]`, `[FAIL]`, `[PARTIAL]`, `[GAP]`, `[SKIP]`, `[N/A]`).

---

## 8. Models Reference

All models are Pydantic v2 `BaseModel` subclasses. Import from `acef.models`:

```python
from acef.models import (
    Subject, Component, Dataset, Actor, Relationship, EntitiesBlock,
    RecordEnvelope, EntityRefs, AttachmentRef, Attestation, CollectorInfo, RecordRetention,
    PackageMetadata, ProducerInfo, RetentionPolicy, Versioning,
    Manifest, ProfileEntry, AuditTrailEntry, RecordFileEntry,
    AssessmentBundle, RuleResult, ProvisionSummary, Assessor, EvidenceBundleRef,
    LifecycleEntry,
)
```

### Subject

| Field | Type | Default | Description |
|---|---|---|---|
| `subject_id` | `str` | Auto-generated URN | Unique identifier |
| `subject_type` | `SubjectType` | | `ai_system` or `ai_model` |
| `name` | `str` | | Human-readable name |
| `version` | `str` | `"1.0.0"` | System/model version |
| `provider` | `str` | `""` | Organization responsible |
| `risk_classification` | `RiskClassification` | `minimal-risk` | EU AI Act risk level |
| `modalities` | `list[str]` | `[]` | Input/output modalities |
| `lifecycle_phase` | `LifecyclePhase` | `development` | Current phase |
| `lifecycle_timeline` | `list[LifecycleEntry]` | `[]` | Phase transition history |

### RecordEnvelope

| Field | Type | Default | Description |
|---|---|---|---|
| `record_id` | `str` | Auto-generated URN | Unique identifier |
| `record_type` | `str` | | One of 16 v1 types |
| `provisions_addressed` | `list[str]` | `[]` | Regulatory provisions |
| `timestamp` | `str` | Current UTC | ISO 8601 |
| `lifecycle_phase` | `LifecyclePhase \| None` | `None` | Related phase |
| `collector` | `CollectorInfo \| None` | `None` | Collection tool/person |
| `obligation_role` | `ObligationRole \| None` | `None` | Who is responsible |
| `confidentiality` | `Confidentiality` | `public` | Confidentiality level |
| `redaction_method` | `str \| None` | `None` | Redaction method if redacted |
| `access_policy` | `dict \| None` | `None` | Access control |
| `trust_level` | `TrustLevel` | `self-attested` | Evidence provenance |
| `entity_refs` | `EntityRefs` | Empty | Entity references |
| `payload` | `dict` | `{}` | Type-specific evidence data |
| `attachments` | `list[AttachmentRef]` | `[]` | Artifact references |
| `attestation` | `Attestation \| None` | `None` | Cryptographic attestation |
| `retention` | `RecordRetention \| None` | `None` | Retention requirements |

### Component

| Field | Type | Default | Description |
|---|---|---|---|
| `component_id` | `str` | Auto-generated URN | Unique identifier |
| `name` | `str` | | Component name |
| `type` | `ComponentType` | | `model`, `retriever`, `guardrail`, etc. |
| `version` | `str` | `"1.0.0"` | Component version |
| `subject_refs` | `list[str]` | `[]` | Associated subject URNs |
| `provider` | `str` | `""` | Component provider |

### Dataset

| Field | Type | Default | Description |
|---|---|---|---|
| `dataset_id` | `str` | Auto-generated URN | Unique identifier |
| `name` | `str` | | Dataset name |
| `version` | `str` | `"1.0.0"` | Dataset version |
| `source_type` | `DatasetSourceType` | `licensed` | Acquisition source |
| `modality` | `DatasetModality` | `text` | Data modality |
| `size` | `DatasetSize \| dict` | `{records: 0, size_gb: 0}` | Size information |
| `subject_refs` | `list[str]` | `[]` | Associated subject URNs |

### Actor

| Field | Type | Default | Description |
|---|---|---|---|
| `actor_id` | `str` | Auto-generated URN | Unique identifier |
| `role` | `ActorRole` | `provider` | Role in AI lifecycle |
| `name` | `str` | `""` | Name or pseudonym |
| `organization` | `str` | `""` | Organization |

### EntityRefs

| Field | Type | Default |
|---|---|---|
| `subject_refs` | `list[str]` | `[]` |
| `component_refs` | `list[str]` | `[]` |
| `dataset_refs` | `list[str]` | `[]` |
| `actor_refs` | `list[str]` | `[]` |

### AttachmentRef

| Field | Type | Default | Description |
|---|---|---|---|
| `path` | `str` | | Relative path in artifacts/ |
| `hash` | `str \| None` | `None` | Advisory SHA-256 hash |
| `media_type` | `str` | `"application/octet-stream"` | MIME type |
| `attachment_type` | `str \| None` | `None` | Logical kind (used by `attachment_kind_exists`) |
| `description` | `str` | `""` | Human-readable description |

---

## 9. Enums Reference

All enums are `str` enums (can be used as strings).

### SubjectType

| Value | Description |
|---|---|
| `ai_system` | Deployed AI system |
| `ai_model` | Standalone AI model |

### RiskClassification

| Value | Description |
|---|---|
| `high-risk` | High-risk AI system (EU AI Act Art. 6) |
| `gpai` | General-purpose AI model (Art. 53) |
| `gpai-systemic` | GPAI with systemic risk (Art. 55) |
| `limited-risk` | Limited-risk system (Art. 50) |
| `minimal-risk` | Minimal-risk system |

### LifecyclePhase

`design`, `development`, `testing`, `deployment`, `monitoring`, `decommission`

### ComponentType

`model`, `retriever`, `guardrail`, `orchestrator`, `tool`, `database`, `api`

### DatasetSourceType

`licensed`, `scraped`, `public_domain`, `synthetic`, `user_generated`

### DatasetModality

`text`, `image`, `audio`, `video`, `tabular`, `multimodal`

### ActorRole

`provider`, `deployer`, `importer`, `distributor`, `auditor`, `regulator`, `data_subject`

### RelationshipType

`wraps`, `calls`, `fine_tunes`, `deploys`, `trains_on`, `evaluates_with`, `oversees`

### ObligationRole

`provider`, `deployer`, `importer`, `distributor`, `authorised_representative`, `notified_body`, `platform`

### Confidentiality

`public`, `redacted`, `hash-committed`, `regulator-only`, `under-nda`

### TrustLevel

`self-attested`, `peer-reviewed`, `independently-verified`, `notified-body-certified`

### RuleSeverity

`fail`, `warning`, `info`

### RuleOutcome

`passed`, `failed`, `skipped`, `error`

### ProvisionOutcome

`satisfied`, `not-satisfied`, `partially-satisfied`, `gap-acknowledged`, `skipped`, `not-assessed`

### AuditEventType

`created`, `updated`, `reviewed`, `submitted`, `certified`

### RECORD_TYPES

Frozen set of 16 valid v1 record types:

```python
from acef.models.enums import RECORD_TYPES
print(RECORD_TYPES)
# frozenset({'risk_register', 'risk_treatment', 'dataset_card', 'data_provenance',
#            'evaluation_report', 'event_log', 'human_oversight_action',
#            'transparency_disclosure', 'transparency_marking', 'disclosure_labeling',
#            'copyright_rights_reservation', 'license_record', 'incident_report',
#            'governance_policy', 'conformity_declaration', 'evidence_gap'})
```

---

## 10. Error Types

All ACEF exceptions inherit from `ACEFError`:

```python
from acef.errors import (
    ACEFError,           # Base exception
    ACEFSchemaError,     # Schema validation (ACEF-001 to ACEF-004)
    ACEFIntegrityError,  # Integrity verification (ACEF-010 to ACEF-014)
    ACEFReferenceError,  # Reference integrity (ACEF-020 to ACEF-027)
    ACEFProfileError,    # Profile/template (ACEF-030 to ACEF-033)
    ACEFEvaluationError, # Rule evaluation (ACEF-040 to ACEF-045)
    ACEFFormatError,     # Format (ACEF-050 to ACEF-053)
    ACEFMergeError,      # Merge conflicts (ACEF-060)
    ACEFExportError,     # Export/serialization
    ACEFSigningError,    # Signing/verification
)
```

### ACEFError Properties

| Property | Type | Description |
|---|---|---|
| `code` | `str` | ACEF error code (e.g., `"ACEF-003"`) |
| `message` | `str` | Error message (without code prefix) |
| `severity` | `Severity` | `fatal`, `error`, `warning`, or `info` |
| `category` | `ErrorCategory` | `schema`, `integrity`, `reference`, `profile`, `evaluation`, `format`, `merge` |
| `details` | `dict` | Additional error context |

```python
try:
    pkg.record("invalid_type", payload={})
except ACEFSchemaError as e:
    print(e.code)      # "ACEF-003"
    print(e.message)   # "Unknown record_type: 'invalid_type'"
    print(e.severity)  # Severity.ERROR
```

### ValidationDiagnostic

Used internally by the validation engine to collect errors within a phase:

```python
from acef.errors import ValidationDiagnostic

diag = ValidationDiagnostic(
    "ACEF-020",
    "Dangling entity ref: urn:acef:sub:missing",
    path="/records/risk_register.jsonl",
)
print(diag.severity)   # Severity.ERROR
print(diag.category)   # ErrorCategory.REFERENCE
print(diag.to_dict())  # Serializable dict for Assessment Bundle structural_errors
```
