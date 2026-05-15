# ACEF User Guide

This guide walks compliance teams, developers, and auditors through using the ACEF Reference SDK to build, validate, and manage AI compliance evidence packages.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Building Evidence Packages](#2-building-evidence-packages)
3. [Validating Against Regulations](#3-validating-against-regulations)
4. [Working with the CLI](#4-working-with-the-cli)
5. [Advanced Features](#5-advanced-features)
6. [Error Codes Reference](#6-error-codes-reference)

---

## 1. Getting Started

### Installation

```bash
pip install acef
```

For development (includes test and lint dependencies):

```bash
pip install acef[dev]
```

### Your First Bundle

```python
import acef

# Create a package with producer information
pkg = acef.Package(producer={"name": "my-compliance-tool", "version": "1.0"})

# Declare the AI system
system = pkg.add_subject(
    "ai_system",
    name="Loan Approval Model",
    risk_classification="high-risk",
    modalities=["tabular"],
    lifecycle_phase="deployment",
)

# Record a risk assessment
pkg.record(
    "risk_register",
    provisions=["article-9"],
    payload={
        "description": "Model bias against protected demographics",
        "likelihood": "medium",
        "severity": "high",
        "category": "fairness",
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
)

# Export
pkg.export("loan-model-evidence.acef/")
print(f"Bundle created: {pkg.metadata.package_id}")
```

---

## 2. Building Evidence Packages

### Defining Subjects

Every ACEF package documents one or more **subjects** -- the AI systems or models under scrutiny. Use `ai_system` for deployed applications and `ai_model` for standalone models.

```python
import acef

pkg = acef.Package(producer={"name": "acme-tool", "version": "2.0"})

# A deployed AI system (EU AI Act Art. 6 scope)
system = pkg.add_subject(
    "ai_system",
    name="Acme RAG Assistant",
    version="2.1.0",
    provider="Acme AI Corp",
    risk_classification="high-risk",
    modalities=["text"],
    lifecycle_phase="deployment",
    lifecycle_timeline=[
        {"phase": "development", "start_date": "2025-01-15", "end_date": "2025-11-01"},
        {"phase": "testing", "start_date": "2025-11-01", "end_date": "2026-01-15"},
        {"phase": "deployment", "start_date": "2026-01-15"},
    ],
)

# A standalone GPAI model (EU AI Act Art. 53 scope)
model = pkg.add_subject(
    "ai_model",
    name="Acme LLM v3",
    version="3.0.0",
    provider="Acme AI Corp",
    risk_classification="gpai",
    modalities=["text"],
)
```

**Risk classifications** (per EU AI Act):

| Value | Meaning |
|---|---|
| `high-risk` | High-risk AI system (Art. 6) |
| `gpai` | General-purpose AI model (Art. 53) |
| `gpai-systemic` | GPAI with systemic risk (Art. 55) |
| `limited-risk` | Limited-risk system (Art. 50) |
| `minimal-risk` | Minimal-risk system |

### Building the Entity Graph

Entities provide the structural context for evidence records. Define them once, reference them by URN from records.

```python
# Components -- subsystems of the AI system
retriever = pkg.add_component(
    "Vector Retriever",
    type="retriever",
    version="3.1.0",
    subject_refs=[system.id],
)

guardrail = pkg.add_component(
    "Safety Filter",
    type="guardrail",
    version="1.4.0",
    subject_refs=[system.id],
)

# Datasets -- training, validation, and test data
training_data = pkg.add_dataset(
    "Training Conversations",
    source_type="licensed",
    modality="text",
    size={"records": 1000000, "size_gb": 100},
    subject_refs=[model.id],
)

# Actors -- people and organizations involved
lead_engineer = pkg.add_actor(
    name="Jane Smith",
    role="provider",
    organization="Acme AI Corp",
)

auditor = pkg.add_actor(
    name="External Auditor",
    role="auditor",
    organization="TrustCert GmbH",
)

# Relationships -- entity graph edges
pkg.add_relationship(system.id, model.id, "wraps")
pkg.add_relationship(system.id, retriever.id, "calls")
pkg.add_relationship(model.id, training_data.id, "trains_on")
pkg.add_relationship(auditor.id, system.id, "oversees")
```

**Component types**: `model`, `retriever`, `guardrail`, `orchestrator`, `tool`, `database`, `api`

**Dataset source types**: `licensed`, `scraped`, `public_domain`, `synthetic`, `user_generated`

**Relationship types**: `wraps`, `calls`, `fine_tunes`, `deploys`, `trains_on`, `evaluates_with`, `oversees`

### Recording Evidence

Each evidence record has a common envelope plus a type-specific payload. The `record()` method accepts all envelope fields:

```python
# Risk identification (EU AI Act Art. 9)
pkg.record(
    "risk_register",
    provisions=["article-9"],
    payload={
        "description": "Hallucination risk in customer-facing responses",
        "likelihood": "medium",
        "severity": "high",
        "category": "safety",
        "assessment_method": "Expert panel review",
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
    trust_level="peer-reviewed",
    lifecycle_phase="deployment",
    collector={"name": "risk-assessment-tool", "version": "1.2"},
)

# Risk treatment (EU AI Act Art. 9)
pkg.record(
    "risk_treatment",
    provisions=["article-9"],
    payload={
        "treatment_type": "mitigate",
        "description": "Safety filter blocks high-risk outputs",
        "implementation_status": "deployed",
        "effectiveness_score": 0.94,
    },
    obligation_role="provider",
    entity_refs={
        "subject_refs": [system.id],
        "component_refs": [guardrail.id],
    },
)

# Dataset documentation (EU AI Act Art. 10)
pkg.record(
    "dataset_card",
    provisions=["article-10"],
    payload={
        "name": "Training Conversations",
        "description": "Licensed customer support transcripts",
        "representativeness_assessment": "Covers 12 languages, 45 product categories",
        "known_limitations": "Under-represents languages with <1% market share",
    },
    obligation_role="provider",
    entity_refs={"dataset_refs": [training_data.id]},
)

# Data provenance (EU AI Act Art. 10, GPAI, US Copyright)
pkg.record(
    "data_provenance",
    provisions=["article-10"],
    payload={
        "acquisition_method": "licensed",
        "acquisition_date": "2025-09-01",
        "source_uri": "https://data-vendor.example.com/conversations-v3",
        "license_type": "commercial",
    },
    obligation_role="provider",
    entity_refs={"dataset_refs": [training_data.id]},
)

# Evaluation results (EU AI Act Art. 15)
pkg.record(
    "evaluation_report",
    provisions=["article-15"],
    payload={
        "methodology": "Automated benchmark suite",
        "results": {
            "accuracy": 0.95,
            "f1_score": 0.92,
            "hallucination_rate": 0.03,
        },
        "test_conditions": "Production-equivalent environment, 10k test cases",
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
)

# Transparency marking (EU AI Act Art. 50)
pkg.record(
    "transparency_marking",
    provisions=["article-50.2"],
    payload={
        "modality": "text",
        "marking_scheme_id": "c2pa-content-credentials",
        "scheme_version": "2.3",
        "metadata_container": "xmp/c2pa-manifest-store",
        "watermark_applied": True,
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
)

# Event log (EU AI Act Art. 12)
pkg.record(
    "event_log",
    provisions=["article-12"],
    payload={
        "event_type": "inference",
        "correlation_id": "req-12345",
        "inputs_commitment": {"hash_alg": "sha-256", "hash": "a1b2c3d4..."},
        "outputs_commitment": {"hash_alg": "sha-256", "hash": "e5f6a7b8..."},
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
    retention={"min_retention_days": 180, "legal_basis": "eu-ai-act-2024:article-12"},
)

# Evidence gap (when evidence is not yet available)
pkg.record(
    "evidence_gap",
    provisions=["article-15"],
    payload={
        "missing_record_type": "evaluation_report",
        "reason": "testing_scheduled",
        "expected_completion_date": "2026-06-30",
        "remediation_plan": "Comprehensive robustness testing planned for Q2 2026",
    },
    entity_refs={"subject_refs": [system.id]},
)
```

### Declaring Regulatory Profiles

Profiles tell validators which regulation templates to evaluate:

```python
# EU AI Act -- specify applicable provisions
pkg.add_profile(
    "eu-ai-act-2024",
    provisions=["article-9", "article-10", "article-12", "article-15", "article-50.2"],
)

# NIST AI RMF -- all provisions
pkg.add_profile("nist-ai-rmf-1.0")

# China CAC labeling
pkg.add_profile(
    "china-cac-labeling-2025",
    provisions=["cac-explicit-label", "cac-implicit-metadata"],
)
```

If `provisions` is omitted, all provisions in the template are evaluated.

### Adding Attachments

Binary files (PDFs, images, CSVs) are stored in the `artifacts/` directory:

```python
# Read a PDF report
with open("eval-report-v3.pdf", "rb") as f:
    report_content = f.read()

# Add it to the package
pkg.add_attachment("eval-report-v3.pdf", report_content)

# Reference it from a record
pkg.record(
    "evaluation_report",
    provisions=["article-15"],
    payload={"methodology": "Third-party audit"},
    attachments=[{
        "path": "artifacts/eval-report-v3.pdf",
        "media_type": "application/pdf",
        "description": "Independent evaluation report by TrustCert GmbH",
    }],
)
```

### Setting Confidentiality and Access Policies

Different evidence may have different confidentiality levels:

```python
# Public evidence
pkg.record(
    "transparency_disclosure",
    confidentiality="public",
    payload={"description": "Published model card"},
)

# Regulator-only evidence (trade secrets)
pkg.record(
    "copyright_rights_reservation",
    confidentiality="regulator-only",
    access_policy={"roles": ["regulator", "auditor"], "organizations": ["EU AI Office"]},
    payload={
        "opt_out_method": "robots_txt",
        "removal_count": 42,
    },
)

# Hash-committed evidence (provably exists without disclosure)
pkg.record(
    "data_provenance",
    confidentiality="hash-committed",
    payload={"source": "Confidential data source"},
)
```

**Confidentiality levels**:

| Level | Meaning |
|---|---|
| `public` | Visible to all |
| `redacted` | Content replaced with summary |
| `hash-committed` | Payload replaced with SHA-256 hash commitment |
| `regulator-only` | Visible only to regulators and auditors |
| `under-nda` | Restricted by NDA terms |

### Package Chaining (Version History)

Create a chain of evidence packages for audit trails:

```python
import acef

# Create v2 chained to v1
pkg_v2 = acef.chain(
    "v1-evidence.acef/",
    producer={"name": "my-tool", "version": "1.0"},
)

# The prior_package_ref is automatically set to the v1 bundle digest
print(pkg_v2.metadata.prior_package_ref)
# => "sha256:a1b2c3d4..."

# Add updated evidence to v2
pkg_v2.add_subject("ai_system", name="My System", version="2.0.0")
pkg_v2.record("risk_register", payload={"description": "Updated risk assessment"})
pkg_v2.export("v2-evidence.acef/")
```

### Exporting

```python
# Export as a directory bundle
pkg.export("my-evidence.acef/")

# Export as a portable archive
pkg.export("my-evidence.acef.tar.gz")
```

---

## 3. Validating Against Regulations

### Basic Validation

```python
import acef

# Validate an exported bundle (structural checks only)
assessment = acef.validate("my-evidence.acef/")

# Validate against a specific regulation
assessment = acef.validate(
    "my-evidence.acef/",
    profiles=["eu-ai-act-2024"],
)

# Validate a Package object directly (without exporting first)
assessment = acef.validate(pkg, profiles=["eu-ai-act-2024"])

# Validate an archive
assessment = acef.validate("my-evidence.acef.tar.gz", profiles=["eu-ai-act-2024"])
```

### EU AI Act Validation Example

```python
import acef

pkg = acef.Package(producer={"name": "my-tool", "version": "1.0"})

system = pkg.add_subject(
    "ai_system",
    name="Credit Scoring Model",
    risk_classification="high-risk",
    modalities=["tabular"],
    lifecycle_phase="deployment",
)

pkg.add_profile("eu-ai-act-2024", provisions=["article-9", "article-10", "article-15"])

# Add evidence for Article 9
pkg.record("risk_register", provisions=["article-9"],
           payload={"description": "Bias risk", "likelihood": "high", "severity": "high"},
           obligation_role="provider", entity_refs={"subject_refs": [system.id]})
pkg.record("risk_treatment", provisions=["article-9"],
           payload={"treatment_type": "mitigate", "description": "Bias mitigation applied"},
           obligation_role="provider", entity_refs={"subject_refs": [system.id]})

# Add evidence for Article 10
ds = pkg.add_dataset("Training Data", source_type="licensed", modality="tabular",
                     subject_refs=[system.id])
pkg.record("dataset_card", provisions=["article-10"],
           payload={"name": "Training Data", "description": "Licensed financial records"},
           obligation_role="provider", entity_refs={"dataset_refs": [ds.id]})
pkg.record("data_provenance", provisions=["article-10"],
           payload={"acquisition_method": "licensed", "acquisition_date": "2025-06-01"},
           obligation_role="provider", entity_refs={"dataset_refs": [ds.id]})

# Add evidence for Article 15
pkg.record("evaluation_report", provisions=["article-15"],
           payload={"methodology": "benchmark", "results": {"accuracy": 0.97}},
           obligation_role="provider", entity_refs={"subject_refs": [system.id]})

# Validate
assessment = acef.validate(pkg, profiles=["eu-ai-act-2024"])
print(assessment.summary())

# Render a Markdown report
report = acef.render(assessment)
print(report)
```

### NIST AI RMF Validation Example

```python
import acef

pkg = acef.Package(producer={"name": "gov-tool", "version": "1.0"})
system = pkg.add_subject("ai_system", name="Document Classifier",
                         risk_classification="minimal-risk", modalities=["text"])

pkg.add_profile("nist-ai-rmf-1.0")

# GOVERN function evidence
pkg.record("governance_policy", provisions=["govern-1.1"],
           payload={"policy_type": "ai_governance", "title": "AI Governance Framework",
                    "approval_date": "2025-01-15"},
           entity_refs={"subject_refs": [system.id]})

# MAP function evidence
pkg.record("risk_register", provisions=["map-1.1"],
           payload={"description": "Operational risk assessment", "likelihood": "low", "severity": "low"},
           entity_refs={"subject_refs": [system.id]})

# MEASURE function evidence
pkg.record("evaluation_report", provisions=["measure-1.1"],
           payload={"methodology": "NIST TEVV framework", "results": {"accuracy": 0.99}},
           entity_refs={"subject_refs": [system.id]})

# MANAGE function evidence
pkg.record("risk_treatment", provisions=["manage-1.1"],
           payload={"treatment_type": "mitigate", "description": "Monitoring and alerting"},
           entity_refs={"subject_refs": [system.id]})

assessment = acef.validate(pkg, profiles=["nist-ai-rmf-1.0"])
print(assessment.summary())
```

### China CAC Validation Example

```python
import acef

pkg = acef.Package(producer={"name": "cn-tool", "version": "1.0"})
system = pkg.add_subject("ai_system", name="Content Generator",
                         risk_classification="limited-risk", modalities=["text", "image"])

pkg.add_profile("china-cac-labeling-2025")

# Explicit label evidence
pkg.record("transparency_marking", provisions=["cac-explicit-label"],
           payload={
               "modality": "text",
               "marking_scheme_id": "cn-cac-explicit-label-2025",
               "scheme_version": "1.0",
               "metadata_container": "text-superscript",
               "watermark_applied": False,
               "jurisdiction": "CN",
           },
           obligation_role="provider", entity_refs={"subject_refs": [system.id]})

# Implicit metadata evidence
pkg.record("transparency_marking", provisions=["cac-implicit-metadata"],
           payload={
               "modality": "text",
               "marking_scheme_id": "cn-cac-implicit-label-2025",
               "scheme_version": "1.0",
               "metadata_container": "file-header",
               "watermark_applied": False,
               "jurisdiction": "CN",
           },
           obligation_role="provider", entity_refs={"subject_refs": [system.id]})

assessment = acef.validate(pkg, profiles=["china-cac-labeling-2025"])
print(assessment.summary())
```

### Understanding Assessment Results

The `AssessmentBundle` object provides structured access to results:

```python
# Overall summary
print(assessment.summary())

# Provision-level results
for ps in assessment.provision_summary:
    print(f"{ps.provision_id}: {ps.provision_outcome.value} "
          f"(fails={ps.fail_count}, warnings={ps.warning_count})")

# Individual rule results
for result in assessment.results:
    if result.outcome.value == "failed":
        print(f"FAILED: {result.rule_id} [{result.rule_severity.value}] {result.message}")

# Structural errors (schema, integrity, reference issues)
for error in assessment.structural_errors:
    print(f"[{error['code']}] {error['severity']}: {error['message']}")

# Export assessment to file
acef.export_assessment(assessment, "assessment.acef-assessment.json")
```

### The 7-Step Provision Outcome Algorithm

Each provision gets a single outcome computed from its rule results:

1. If any **fail-severity** rule failed: `not-satisfied`
2. If any rule errored: `not-assessed`
3. If all rules were skipped: `skipped`
4. If an evidence gap exists (and no fail-severity failures): `gap-acknowledged`
5. If all fail-severity rules passed but some warnings failed: `partially-satisfied`
6. If all evaluated rules passed: `satisfied`
7. If no rules exist for the provision: `not-assessed`

---

## 4. Working with the CLI

The `acef` CLI is installed automatically with the package. Run `acef --help` for a full command list.

### `acef init` -- Scaffold a New Bundle

Creates a minimal valid bundle directory structure:

```bash
acef init my-system.acef/ \
  --producer-name "my-tool" \
  --producer-version "1.0.0" \
  --subject-name "My AI System" \
  --subject-type ai_system \
  --risk-classification high-risk
```

Output:
```
Created ACEF bundle at: my-system.acef/
Package ID: urn:acef:pkg:550e8400-e29b-41d4-a716-446655440000
```

### `acef validate` -- Run Validation

```bash
# Structural validation only
acef validate my-system.acef/

# Validate against a regulation
acef validate my-system.acef/ -p eu-ai-act-2024

# Multiple profiles
acef validate my-system.acef/ -p eu-ai-act-2024 -p nist-ai-rmf-1.0

# JSON output for CI/CD integration
acef validate my-system.acef/ -p eu-ai-act-2024 --format json

# Markdown report
acef validate my-system.acef/ -p eu-ai-act-2024 --format markdown

# Save assessment to file
acef validate my-system.acef/ -p eu-ai-act-2024 -o assessment.json
```

**Exit codes:**
- `0`: All provisions satisfied (or no profiles evaluated)
- `1`: At least one provision is `not-satisfied`
- `2`: Fatal structural error (invalid bundle)

### `acef inspect` -- Examine Bundle Contents

```bash
# Pretty-printed summary
acef inspect my-system.acef/

# JSON manifest dump
acef inspect my-system.acef/ --format json

# Works with archives too
acef inspect my-system.acef.tar.gz
```

### `acef doctor` -- Diagnose Issues

Runs a comprehensive health check on a bundle:

```bash
acef doctor my-system.acef/
```

Checks performed:
- Directory structure verification
- Manifest JSON validity
- Required metadata fields
- Content hash verification
- Merkle tree presence
- Record file parsing
- Signature discovery

### `acef export` -- Convert Between Formats

```bash
# Directory to archive
acef export my-system.acef/ output.acef.tar.gz

# Archive to directory
acef export input.acef.tar.gz output.acef/

# Export with signing
acef export my-system.acef/ signed.acef.tar.gz --sign private-key.pem
```

### `acef record` -- Add Records from Command Line

```bash
# Inline JSON payload
acef record my-system.acef/ \
  --type risk_register \
  --provision article-9 \
  --payload '{"description": "New risk", "likelihood": "high", "severity": "medium"}' \
  --role provider

# Payload from file
acef record my-system.acef/ \
  --type evaluation_report \
  --provision article-15 \
  --payload @eval-results.json \
  --role provider
```

### `acef scaffold` -- Generate Template Stubs

Shows what evidence a regulation requires:

```bash
acef scaffold eu-ai-act-2024
acef scaffold nist-ai-rmf-1.0
acef scaffold china-cac-labeling-2025
```

---

## 5. Advanced Features

### Signing Bundles

ACEF supports JWS detached signatures with RSA (RS256) and ECDSA (ES256) keys.

#### Generate Keys

```bash
# RSA 2048-bit key
openssl genrsa -out private-key.pem 2048
openssl rsa -in private-key.pem -pubout -out public-key.pem

# ECDSA P-256 key
openssl ecparam -genkey -name prime256v1 -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem
```

#### Sign via Python API

```python
import acef

# Mark for signing during export
pkg.sign("private-key.pem")
pkg.export("signed-bundle.acef/")

# Or sign an already-exported bundle
acef.sign("bundle.acef/", "private-key.pem", kid="provider-key")
```

#### Sign via CLI

```bash
acef export my-system.acef/ signed.acef.tar.gz --sign private-key.pem
```

#### Verify Signatures

```python
from pathlib import Path
from acef.signing import verify_detached_jws

# Read the signature and content-hashes.json
sig_path = Path("bundle.acef/signatures/provider-key.jws")
hashes_path = Path("bundle.acef/hashes/content-hashes.json")

jws = sig_path.read_text()
payload = hashes_path.read_bytes()

# Verify (public key auto-extracted from JWS header)
header = verify_detached_jws(jws, payload)
print(f"Algorithm: {header['alg']}")
```

### Redacting Sensitive Evidence

Replace payloads with SHA-256 hash commitments while preserving verifiability:

```python
import acef

# Create a package with sensitive evidence
pkg = acef.Package(producer={"name": "my-tool", "version": "1.0"})
pkg.add_subject("ai_system", name="My System")
rec = pkg.record(
    "copyright_rights_reservation",
    confidentiality="regulator-only",
    payload={"opt_out_method": "robots_txt", "removal_count": 42},
)

# Save the original payload for later verification
original_payload = rec.payload.copy()

# Create a redacted copy of the package
redacted = acef.redact(
    pkg,
    record_filter={"confidentiality_levels": ["regulator-only"]},
    access_policy={"roles": ["regulator"], "organizations": ["EU AI Office"]},
)

# The redacted record has a hash commitment instead of the payload
redacted_rec = redacted.records[0]
print(redacted_rec.confidentiality.value)  # "hash-committed"
print(redacted_rec.payload)          # {"_redacted": True, "_commitment": "sha256:..."}

# Later, verify the original payload matches the commitment
from acef.redaction import verify_redaction
assert verify_redaction(redacted_rec, original_payload)  # True
```

### Merging Evidence from Multiple Sources

Combine evidence from different teams or tools:

```python
import acef

# Package from the ML team
ml_pkg = acef.Package(producer={"name": "ml-pipeline", "version": "2.0"})
ml_pkg.add_subject("ai_model", name="Core LLM")
ml_pkg.record("evaluation_report", payload={"methodology": "benchmark"})

# Package from the governance team
gov_pkg = acef.Package(producer={"name": "grc-tool", "version": "1.0"})
gov_pkg.add_subject("ai_system", name="Deployed System")
gov_pkg.record("governance_policy", payload={"policy_type": "ai_governance"})

# Merge
result = acef.merge([ml_pkg, gov_pkg], producer={"name": "acme-merger", "version": "1.0"})

if result.has_conflicts:
    for conflict in result.conflicts:
        print(f"Conflict: {conflict.message}")

merged_pkg = result.package
print(f"Merged: {len(merged_pkg.subjects)} subjects, {len(merged_pkg.records)} records")
```

**Conflict strategies:**

| Strategy | Behavior |
|---|---|
| `keep_latest` | When duplicate records are found, keep the one with the latest timestamp (default) |
| `keep_all` | Keep all records, even if duplicated |
| `fail` | Raise `ACEFMergeError` on any conflict |

### Rendering Compliance Reports

```python
import acef

assessment = acef.validate("bundle.acef/", profiles=["eu-ai-act-2024"])

# Markdown report (suitable for documents and wikis)
markdown = acef.render(assessment)
with open("compliance-report.md", "w") as f:
    f.write(markdown)

# Console summary (suitable for terminal output)
from acef.render import render_console
console_output = render_console(assessment)
print(console_output)
```

---

## 6. Error Codes Reference

ACEF defines a structured error taxonomy with unique codes, severities, and categories. Errors are collected within each validation phase before reporting.

### Schema Errors (ACEF-001 to ACEF-004)

| Code | Severity | Description |
|---|---|---|
| ACEF-001 | Fatal | Incompatible module versions in versioning block |
| ACEF-002 | Fatal | Manifest fails JSON Schema validation |
| ACEF-003 | Error | Unknown record_type -- no schema in registry |
| ACEF-004 | Fatal | Record payload fails record-type JSON Schema validation |

### Integrity Errors (ACEF-010 to ACEF-014)

| Code | Severity | Description |
|---|---|---|
| ACEF-010 | Fatal | File hash mismatch |
| ACEF-011 | Fatal | Merkle root mismatch |
| ACEF-012 | Fatal | Invalid or expired signature |
| ACEF-013 | Fatal | Unsupported JWS algorithm (only RS256 and ES256 allowed) |
| ACEF-014 | Fatal | Hash index completeness failure (file missing from or extra in content-hashes.json) |

### Reference Errors (ACEF-020 to ACEF-027)

| Code | Severity | Description |
|---|---|---|
| ACEF-020 | Error | Dangling entity_refs -- URN references nonexistent entity |
| ACEF-021 | Error | Duplicate URNs within the package |
| ACEF-022 | Error | record_files entry references nonexistent file |
| ACEF-023 | Error | Attachment path references file not in artifacts/ |
| ACEF-025 | Error | Record count mismatch between manifest and actual JSONL |
| ACEF-026 | Error | Duplicate record_id within the package |
| ACEF-027 | Warning | Attachment hash does not match content-hashes.json entry |

### Profile Errors (ACEF-030 to ACEF-033)

| Code | Severity | Description |
|---|---|---|
| ACEF-030 | Error | Unknown profile_id -- no matching template |
| ACEF-031 | Error | Unknown template_version |
| ACEF-032 | Info | Provision not yet effective -- rules produce skipped outcome |
| ACEF-033 | Error | Incompatible module versions between bundle and template |

### Evaluation Errors (ACEF-040 to ACEF-045)

| Code | Severity | Description |
|---|---|---|
| ACEF-040 | Error | Required evidence type missing |
| ACEF-041 | Warning | Evidence freshness exceeded |
| ACEF-042 | Info | evidence_gap acknowledged for provision |
| ACEF-043 | Error | Invalid JSON Pointer in rule field parameter |
| ACEF-044 | Error | Duplicate rule_id in template |
| ACEF-045 | Error | Invalid ECMA-262 regex pattern in rule value |

### Format Errors (ACEF-050 to ACEF-053)

| Code | Severity | Description |
|---|---|---|
| ACEF-050 | Fatal | Malformed JSONL line |
| ACEF-051 | Fatal | JSON not canonicalized per RFC 8785 |
| ACEF-052 | Error | Path contains .. segments or non-UTF-8-NFC characters |
| ACEF-053 | Error | Vendor extension field affects conformance outcome |

### Merge Errors (ACEF-060)

| Code | Severity | Description |
|---|---|---|
| ACEF-060 | Warning | Conflicting records from multiple packages |

### Error Severity Levels

| Severity | Meaning |
|---|---|
| `fatal` | Package is structurally invalid; cannot proceed with validation |
| `error` | Evidence fails binding regulatory requirements |
| `warning` | Evidence fails voluntary or advisory requirements |
| `info` | Informational observation (not a failure) |
