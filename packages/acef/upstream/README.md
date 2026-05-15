# ACEF -- AI Compliance Evidence Format

**The SBOM for AI governance.** An open, vendor-neutral standard for packaging machine-readable proof that an AI system complies with applicable regulations, standards, and governance commitments.

ACEF is maintained by [AI Commons](https://aicommons.org) (non-profit, open standard) and licensed under Apache 2.0.

| | |
|---|---|
| **Version** | 0.1.0 (Spec v0.3 -- Working Draft) |
| **Python** | >= 3.11 |
| **License** | Apache-2.0 |
| **Status** | Alpha -- API may change before 1.0 |

---

## Why ACEF?

AI regulation is accelerating worldwide. The EU AI Act's high-risk system requirements take effect **August 2, 2026**. Organizations building, deploying, or auditing AI systems need a portable, machine-readable format for compliance evidence -- not PDFs in a shared drive.

ACEF provides:

- **One format, many regulations.** A single evidence bundle serves EU AI Act, NIST AI RMF, GPAI Code of Practice, China CAC labeling measures, US Copyright Office guidance, and more -- via pluggable regulation mapping templates.
- **Evidence, not assertions.** Every compliance claim links to verifiable evidence artifacts (logs, test results, documents, hashes). No self-reported pass/fail.
- **Immutable, signable, chainable.** Every evidence package is content-addressable, cryptographically signable (JWS with RS256/ES256), and can reference prior versions for audit trails.
- **Privacy-aware.** Confidential evidence (trade secrets, PII in training data) can be attested without disclosure, using SHA-256 hash commitments.
- **Open validation.** Regulation mapping templates and the rule engine are open-source. Compliance logic is not locked inside proprietary tools.

---

## Quick Start

### Installation

```bash
pip install acef
```

Or from source:

```bash
git clone https://github.com/ai-commons/acef.git
cd acef
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Create an Evidence Bundle

```python
import acef

# 1. Create a package
pkg = acef.Package(producer={"name": "my-tool", "version": "1.0"})

# 2. Declare the AI system being documented
system = pkg.add_subject(
    "ai_system",
    name="Customer Support Bot",
    version="2.1.0",
    provider="Acme Corp",
    risk_classification="high-risk",
    modalities=["text"],
    lifecycle_phase="deployment",
)

# 3. Add entities (datasets, components, actors)
training_data = pkg.add_dataset(
    "Training Conversations",
    source_type="licensed",
    modality="text",
    size={"records": 500000, "size_gb": 12.5},
    subject_refs=[system.id],
)

guardrail = pkg.add_component(
    "Safety Filter",
    type="guardrail",
    version="1.4.0",
    subject_refs=[system.id],
)

# 4. Record evidence
pkg.record(
    "risk_register",
    provisions=["article-9"],
    payload={
        "description": "Hallucination risk in customer-facing responses",
        "likelihood": "medium",
        "severity": "high",
        "category": "safety",
    },
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
)

pkg.record(
    "dataset_card",
    provisions=["article-10"],
    payload={
        "name": "Training Conversations",
        "description": "Licensed customer support transcripts",
        "representativeness_assessment": "Covers 12 languages, 45 product categories",
    },
    obligation_role="provider",
    entity_refs={"dataset_refs": [training_data.id]},
)

# 5. Declare which regulations this evidence addresses
pkg.add_profile("eu-ai-act-2024", provisions=["article-9", "article-10"])

# 6. Export as a directory bundle
pkg.export("my-system-evidence.acef/")

# 7. Or export as a portable archive
pkg.export("my-system-evidence.acef.tar.gz")
```

### Validate Against a Regulation

```python
import acef

# Validate an exported bundle against the EU AI Act
assessment = acef.validate(
    "my-system-evidence.acef/",
    profiles=["eu-ai-act-2024"],
)

# Check results
print(assessment.summary())
# => "eu-ai-act-2024: 2/5 provisions passed"

# Render a full compliance report
report = acef.render(assessment)
print(report)

# Export the assessment as a signed JSON file
acef.export_assessment(assessment, "assessment.acef-assessment.json")
```

### Load and Inspect a Bundle

```python
import acef

# Load from directory or archive
pkg = acef.load("my-system-evidence.acef/")

print(f"Package ID: {pkg.metadata.package_id}")
print(f"Subjects: {len(pkg.subjects)}")
print(f"Records: {len(pkg.records)}")
print(f"Profiles: {[p.profile_id for p in pkg.profiles]}")
```

---

## Key Concepts

### Evidence Bundle vs. Assessment Bundle

ACEF defines two distinct artifact types:

| Artifact | Contains | Produced By | File Format |
|---|---|---|---|
| **Evidence Bundle** | Raw evidence records, entity graph, integrity metadata, attachments | System provider or deployer | Directory (`.acef/`) or archive (`.acef.tar.gz`) |
| **Assessment Bundle** | Rule evaluation results, provision status, signed conclusions | Validators, auditors, notified bodies | JSON file (`.acef-assessment.json`) |

This separation ensures evidence is neutral -- it contains no self-reported pass/fail judgments. Assessment results are produced independently by validators using the open rule engine.

### Subjects and Entities

An ACEF package documents one or more **subjects** (AI systems or models) along with their **entity graph**:

- **Subjects** -- The AI systems (`ai_system`) or models (`ai_model`) being documented. Supports composed systems with multiple subjects.
- **Components** -- Subsystems like models, retrievers, guardrails, orchestrators, tools.
- **Datasets** -- Training, validation, and test datasets with provenance metadata.
- **Actors** -- People and organizations involved (providers, deployers, auditors).
- **Relationships** -- Entity graph edges (`wraps`, `calls`, `fine_tunes`, `trains_on`, `evaluates_with`, `deploys`, `oversees`).

### Record Types

ACEF v1 defines 16 core record types. Each record has a common envelope (ID, timestamp, provisions, entity refs, confidentiality) plus a type-specific payload:

| Record Type | Description | Primary Regulations |
|---|---|---|
| `risk_register` | Risk identification and assessment | EU AI Act Art. 9, NIST MAP/MEASURE |
| `risk_treatment` | Mitigation and control measures | EU AI Act Art. 9, NIST MANAGE |
| `dataset_card` | Dataset documentation | EU AI Act Art. 10, NIST MAP |
| `data_provenance` | Dataset lineage and acquisition | EU AI Act Art. 10, GPAI, US Copyright |
| `evaluation_report` | Test results and benchmarks | EU AI Act Art. 15, NIST MEASURE |
| `event_log` | Automatic system event records | EU AI Act Art. 12, China CAC |
| `human_oversight_action` | Override, stop, verification events | EU AI Act Art. 14 |
| `transparency_disclosure` | Public-facing documentation | EU AI Act Art. 13, GPAI |
| `transparency_marking` | Provider-side content marking | EU AI Act Art. 50, EU Labelling CoP |
| `disclosure_labeling` | Deployer-side disclosure events | EU AI Act Art. 50, China CAC |
| `copyright_rights_reservation` | TDM opt-out compliance | GPAI Art. 53, US Copyright |
| `license_record` | Content licensing agreements | GPAI Copyright, US Copyright |
| `incident_report` | Safety/security incidents | GPAI Systemic Risk, NIST MANAGE |
| `governance_policy` | Organizational governance | NIST GOVERN, ISO 42001, OMB M-24-10 |
| `conformity_declaration` | Formal compliance declarations | EU AI Act Art. 47-48 |
| `evidence_gap` | Acknowledgment of missing evidence | All regulations |

### Profiles and Regulation Templates

A **profile** declares which regulation mapping template an evidence bundle addresses. Templates are community-maintained JSON files that define:

- Which provisions apply (e.g., `article-9`, `govern-1.1`)
- What evidence is required per provision
- Machine-executable evaluation rules (DSL)
- Effective dates and applicability filters

---

## Architecture Overview

ACEF uses a layered architecture with strict dependency rules:

```
Layer 0: errors.py, models/         -- Error taxonomy, Pydantic data models
Layer 1: integrity.py               -- RFC 8785, SHA-256, Merkle tree
Layer 2: package.py                 -- Core package builder
Layer 3: export.py, loader.py       -- Bundle serialization/deserialization
Layer 4: signing.py                 -- JWS detached signatures (RS256, ES256)
Layer 5: templates/                 -- Regulation mapping templates and registry
Layer 6: validation/                -- 4-phase validation pipeline
Layer 7: assessment_builder.py      -- Assessment Bundle construction
Layer 8: redaction.py, merge.py     -- Privacy and multi-source operations
Layer 9: render.py, cli/            -- Human-readable output and CLI
```

The validation pipeline runs four phases:

1. **Schema Validation** -- Manifest JSON Schema, record envelope schema, payload schema per record type.
2. **Integrity Verification** -- SHA-256 content hashes, Merkle tree root, JWS signature verification.
3. **Reference Checking** -- Entity ref resolution, file path existence, duplicate URN detection.
4. **Rule Evaluation** -- DSL operator execution per provision, 7-step provision rollup algorithm.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full technical architecture.

---

## CLI Usage

The `acef` CLI provides 7 commands for working with Evidence Bundles:

### Initialize a Bundle

```bash
acef init my-system.acef/ \
  --producer-name "my-tool" \
  --producer-version "1.0.0" \
  --subject-name "My AI System" \
  --subject-type ai_system \
  --risk-classification high-risk
```

### Validate a Bundle

```bash
# Structural validation only
acef validate my-system.acef/

# Validate against a regulation profile
acef validate my-system.acef/ -p eu-ai-act-2024

# Output assessment as JSON
acef validate my-system.acef/ -p eu-ai-act-2024 --format json

# Save assessment to file
acef validate my-system.acef/ -p eu-ai-act-2024 -o assessment.json
```

### Inspect Bundle Contents

```bash
acef inspect my-system.acef/
acef inspect my-system.acef/ --format json
```

### Diagnose Bundle Issues

```bash
acef doctor my-system.acef/
```

### Add Records from the Command Line

```bash
acef record my-system.acef/ \
  --type risk_register \
  --provision article-9 \
  --payload '{"description": "New risk identified", "likelihood": "high", "severity": "medium"}' \
  --role provider
```

### Export / Convert Formats

```bash
# Directory to archive
acef export my-system.acef/ output.acef.tar.gz --format archive

# Archive to directory
acef export input.acef.tar.gz output.acef/

# Export with signing
acef export my-system.acef/ signed.acef.tar.gz --sign private-key.pem
```

### Generate Template Scaffolds

```bash
# See what evidence a regulation requires
acef scaffold eu-ai-act-2024
acef scaffold nist-ai-rmf-1.0
acef scaffold china-cac-labeling-2025
```

---

## Regulation Templates

The SDK ships with 11 regulation mapping templates:

| Template ID | Regulation | Jurisdiction | Legal Force |
|---|---|---|---|
| `eu-ai-act-2024` | EU Artificial Intelligence Act | EU | Binding |
| `eu-gpai-code-of-practice-2025` | GPAI Code of Practice | EU | Binding |
| `eu-labelling-code-of-practice-2026` | AI-Generated Content Labelling CoP | EU | Binding |
| `nist-ai-rmf-1.0` | NIST AI Risk Management Framework 1.0 | US | Voluntary |
| `nist-ai-600-1-gai-profile` | NIST AI 600-1 GAI Profile | US | Voluntary |
| `us-copyright-office-part3-2025` | Copyright Office Part 3 Guidance | US | Advisory |
| `us-omb-m-24-10` | OMB Memorandum M-24-10 | US | Binding (federal) |
| `china-cac-labeling-2025` | CAC AI Content Labeling Measures | China | Binding |
| `iso-iec-42001-2023` | ISO/IEC 42001:2023 AI Management | International | Voluntary |
| `iso-iec-23894-2023` | ISO/IEC 23894:2023 AI Risk Management | International | Voluntary |
| `uk-ai-copyright-guidance-2026` | UK House of Lords AI & Copyright | UK | Advisory |

Templates are JSON files in `src/acef/templates/`. See [docs/TEMPLATE_AUTHORING.md](docs/TEMPLATE_AUTHORING.md) for how to create custom templates.

---

## Development Setup

### Prerequisites

- Python >= 3.11
- A virtual environment tool (venv, virtualenv, or conda)

### Setup

```bash
git clone https://github.com/ai-commons/acef.git
cd acef
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=src/acef --cov-report=term-missing

# Specific test suites
pytest tests/unit/                  # Unit tests
pytest tests/integration/           # Integration tests
pytest tests/conformance/           # Conformance test suite
```

### Lint and Type Check

```bash
ruff check src/ tests/
mypy src/acef/
```

---

## Project Structure

```
ACEF/
├── planning/                           # Specification documents
│   └── ACEF-Spec-Outline-v0.1.md      # Normative specification (v0.3)
├── src/acef/                           # Python SDK source
│   ├── __init__.py                     # Public API surface
│   ├── package.py                      # Core evidence package builder
│   ├── export.py                       # Bundle serialization (directory + archive)
│   ├── loader.py                       # Bundle deserialization
│   ├── integrity.py                    # SHA-256 hashing, Merkle tree, RFC 8785
│   ├── signing.py                      # JWS signing/verification (RS256, ES256)
│   ├── assessment_builder.py           # Assessment Bundle construction
│   ├── redaction.py                    # Privacy-preserving redaction
│   ├── merge.py                        # Multi-source evidence merging
│   ├── render.py                       # Compliance report generation
│   ├── errors.py                       # Error taxonomy (ACEF-001 to ACEF-060)
│   ├── models/                         # Pydantic v2 data models
│   │   ├── assessment.py               # Assessment Bundle models
│   │   ├── entities.py                 # Component, Dataset, Actor, Relationship
│   │   ├── enums.py                    # All enumeration types
│   │   ├── manifest.py                 # Manifest structure
│   │   ├── metadata.py                 # Package metadata, producer info
│   │   ├── records.py                  # Record envelope and supporting types
│   │   ├── subjects.py                 # Subject (AI system/model)
│   │   └── urns.py                     # URN generation and parsing
│   ├── validation/                     # 4-phase validation pipeline
│   │   ├── engine.py                   # Pipeline orchestrator
│   │   ├── operators.py                # 10 DSL operators
│   │   ├── rollup.py                   # 7-step provision rollup
│   │   ├── rule_engine.py              # Rule evaluation engine
│   │   ├── schema_validator.py         # JSON Schema validation
│   │   ├── integrity_checker.py        # Hash/Merkle/signature verification
│   │   └── reference_checker.py        # Entity ref and path validation
│   ├── templates/                      # Regulation mapping templates
│   │   ├── registry.py                 # Template discovery and loading
│   │   ├── models.py                   # Template data models
│   │   └── *.json                      # 11 regulation templates
│   └── cli/                            # Click-based CLI
│       ├── main.py                     # CLI entry point
│       └── *_cmd.py                    # Subcommands
├── acef-conventions/v1/                # Versioned JSON Schema registry
│   ├── manifest.schema.json            # Manifest schema
│   ├── record-envelope.schema.json     # Common record envelope schema
│   ├── assessment-bundle.schema.json   # Assessment Bundle schema
│   ├── variant-registry.json           # Payload variant discriminators
│   └── *.schema.json                   # Per-record-type payload schemas
├── test-vectors/                       # Per-template test vectors
│   ├── eu-ai-act/                      # 10 EU AI Act test bundles
│   ├── nist-rmf/                       # 2 NIST RMF test bundles
│   ├── china-cac/                      # 3 China CAC test bundles
│   ├── eu-gpai-cop/                    # 2 GPAI CoP test bundles
│   └── omb-m24-10/                     # 2 OMB M-24-10 test bundles
├── tests/                              # Test suite
│   ├── unit/                           # Unit tests per module
│   ├── integration/                    # End-to-end lifecycle tests
│   └── conformance/                    # Conformance test suite with golden bundles
├── docs/                               # Documentation
│   ├── ARCHITECTURE.md                 # Technical architecture
│   ├── USER_GUIDE.md                   # Practitioner guide
│   ├── API_REFERENCE.md                # Complete API documentation
│   ├── TEMPLATE_AUTHORING.md           # Template creation guide
│   └── CONFORMANCE.md                  # Conformance testing guide
└── pyproject.toml                      # Build configuration
```

---

## Standards Compliance

ACEF implements or references these standards:

| Standard | Usage |
|---|---|
| [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785) | JSON Canonicalization Scheme -- all JSON in the hash domain |
| [RFC 7515 (JWS)](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature -- RS256 and ES256 only |
| [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) | JSON Pointer -- field references in DSL rules |
| ISO 8601 | All timestamps |
| BCP 47 | Language tags in disclosure_labeling |
| UTF-8 NFC | All text normalization |
| ECMA-262 | Regular expression dialect for the `regex` operator |

---

## Detailed Documentation

- [Architecture Guide](docs/ARCHITECTURE.md) -- Layered design, integrity model, validation pipeline, security model
- [User Guide](docs/USER_GUIDE.md) -- Step-by-step guide for compliance teams
- [API Reference](docs/API_REFERENCE.md) -- Complete Python SDK documentation
- [Template Authoring](docs/TEMPLATE_AUTHORING.md) -- Creating regulation mapping templates
- [Conformance Guide](docs/CONFORMANCE.md) -- Running the conformance test suite

---

## License

Copyright 2024-2026 AI Commons.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

Code is licensed under Apache 2.0. Templates and schemas are licensed under CC-BY 4.0.
