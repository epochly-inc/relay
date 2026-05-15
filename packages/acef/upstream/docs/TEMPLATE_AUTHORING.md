# ACEF Template Authoring Guide

This guide explains how to create, test, and maintain regulation mapping templates for the ACEF framework.

Templates are the bridge between regulatory text and machine-executable validation rules. They define what evidence is required for each provision of a regulation, and how to verify that evidence is present and well-formed.

---

## Table of Contents

1. [Template Structure](#1-template-structure)
2. [Writing Provisions](#2-writing-provisions)
3. [The 10 DSL Operators](#3-the-10-dsl-operators)
4. [Empty-Set Semantics and Missing-Path Behavior](#4-empty-set-semantics-and-missing-path-behavior)
5. [Scope Filters and Conditions](#5-scope-filters-and-conditions)
6. [Payload Variants](#6-payload-variants)
7. [Testing Templates](#7-testing-templates)
8. [Best Practices](#8-best-practices)

---

## 1. Template Structure

A regulation mapping template is a JSON file with this structure:

```json
{
  "template_id": "my-regulation-2026",
  "template_name": "My Regulation Framework",
  "version": "1.0.0",
  "jurisdiction": "EU",
  "source_legislation": "Regulation (EU) 2026/XXXX",
  "instrument_type": "law",
  "legal_force": "binding",
  "instrument_status": "final",
  "default_effective_date": "2026-08-02",
  "superseded_by": null,
  "applicable_system_types": ["high-risk", "gpai"],
  "provisions": [
    ...
  ],
  "test_vectors": [
    "test-vectors/my-regulation/pass-case.acef",
    "test-vectors/my-regulation/fail-case.acef"
  ]
}
```

### Top-Level Fields

| Field | Required | Type | Description |
|---|---|---|---|
| `template_id` | Yes | `string` | Unique identifier. Convention: `{framework}-{year}` (e.g., `eu-ai-act-2024`) |
| `template_name` | Yes | `string` | Human-readable name |
| `version` | Yes | `string` | Semver version |
| `jurisdiction` | Yes | `string` | Geographic scope (e.g., `EU`, `US`, `CN`, `International`) |
| `source_legislation` | No | `string` | Legal citation |
| `instrument_type` | No | `string` | `law`, `standard`, `code_of_practice`, `guidance`, `parliamentary_report` |
| `legal_force` | No | `string` | `binding`, `voluntary`, `advisory` |
| `instrument_status` | No | `string` | `final` or `draft` |
| `default_effective_date` | No | `string` | ISO 8601 date when the regulation takes effect |
| `superseded_by` | No | `string\|null` | Template ID of the replacement (when deprecated) |
| `applicable_system_types` | No | `list[string]` | Risk classifications this template applies to |
| `provisions` | Yes | `list[Provision]` | The regulatory provisions and evaluation rules |
| `test_vectors` | No | `list[string]` | Paths to test bundles |

### Template File Naming

Templates are stored as JSON files named `{template_id}.json` in the `src/acef/templates/` directory. The template ID must exactly match the filename (without `.json`).

---

## 2. Writing Provisions

Each provision represents a regulatory requirement with machine-executable evaluation rules:

```json
{
  "provision_id": "article-9",
  "provision_name": "Risk Management System",
  "normative_text_ref": "EU AI Act Art. 9(1)-(9)",
  "description": "Continuous, iterative risk management across lifecycle",
  "effective_date": "2026-08-02",
  "applicable_to": ["high-risk"],
  "sub_provisions": [
    {
      "provision_id": "article-9.1",
      "normative_text_ref": "EU AI Act Art. 9(1)",
      "description": "Establish, implement, document, and maintain a risk management system"
    }
  ],
  "required_evidence_types": ["risk_register", "risk_treatment"],
  "minimum_evidence_count": {
    "risk_register": 1,
    "risk_treatment": 1
  },
  "evidence_freshness_max_days": 365,
  "retention_years": 10,
  "evaluation_scope": null,
  "evaluation": [
    {
      "rule_id": "art9-risk-register-exists",
      "rule": "has_record_type",
      "params": {"type": "risk_register", "min_count": 1},
      "severity": "fail",
      "message": "At least one risk_register record is required for Art. 9"
    },
    {
      "rule_id": "art9-risk-treatment-exists",
      "rule": "has_record_type",
      "params": {"type": "risk_treatment", "min_count": 1},
      "severity": "fail",
      "message": "At least one risk_treatment record is required for Art. 9"
    },
    {
      "rule_id": "art9-risk-linked-to-subject",
      "rule": "entity_linked",
      "params": {"record_type": "risk_register", "entity_type": "subject"},
      "severity": "warning",
      "message": "risk_register records should be linked to a subject"
    }
  ]
}
```

### Provision Fields

| Field | Required | Type | Description |
|---|---|---|---|
| `provision_id` | Yes | `string` | Unique within template (e.g., `article-9`, `govern-1.1`) |
| `provision_name` | No | `string` | Human-readable name |
| `normative_text_ref` | No | `string` | Citation to source text |
| `description` | No | `string` | What this provision requires |
| `effective_date` | No | `string` | ISO 8601 date. Rules are skipped before this date. |
| `applicable_to` | No | `list[string]` | Risk classifications (e.g., `["high-risk"]`) |
| `sub_provisions` | No | `list[SubProvision]` | Nested sub-provisions for documentation |
| `required_evidence_types` | No | `list[string]` | Record types needed (informational) |
| `minimum_evidence_count` | No | `dict[string, int]` | Minimum record counts per type (informational) |
| `evidence_freshness_max_days` | No | `int` | Maximum age in days (informational) |
| `retention_years` | No | `int` | Required retention period in years |
| `evaluation_scope` | No | `string\|null` | `"package"` for package-scoped, `null` for per-subject (default) |
| `evaluation` | Yes | `list[EvaluationRule]` | Machine-executable DSL rules |
| `tiered_requirements` | No | `dict` | Tiered requirements by risk level |

### Evaluation Scope

- **Per-subject (default)**: Rules are evaluated separately for each subject declared in the manifest. Records are filtered by `entity_refs.subject_refs`. This is appropriate when the same regulation applies differently to different subjects.
- **Package-scoped** (`"evaluation_scope": "package"`): Rules are evaluated once against all records regardless of subject. Use this for provisions that apply to the organization rather than individual AI systems.

---

## 3. The 10 DSL Operators

Each evaluation rule specifies an operator name in the `rule` field and operator-specific parameters in `params`.

### `has_record_type`

Check that at least `min_count` records of a given type exist.

**Type:** Existential (FAIL on zero matching records if `min_count > 0`)

```json
{
  "rule_id": "art9-risk-register-exists",
  "rule": "has_record_type",
  "params": {
    "type": "risk_register",
    "min_count": 1
  },
  "severity": "fail"
}
```

| Param | Type | Default | Description |
|---|---|---|---|
| `type` | `string` | (required) | Record type to check |
| `min_count` | `int` | `1` | Minimum number of records |

### `field_present`

Check that every record of a given type has a non-null value at a JSON Pointer path.

**Type:** Universal (PASS vacuously on zero records)

```json
{
  "rule_id": "art10-dataset-name-present",
  "rule": "field_present",
  "params": {
    "record_type": "dataset_card",
    "field": "/payload/name"
  },
  "severity": "fail"
}
```

| Param | Type | Description |
|---|---|---|
| `record_type` | `string` | Record type to check |
| `field` | `string` | JSON Pointer (RFC 6901) path |

### `field_value`

Check that a field value satisfies a comparison for every record of a given type.

**Type:** Universal (PASS vacuously on zero records)

```json
{
  "rule_id": "art50-marking-watermark",
  "rule": "field_value",
  "params": {
    "record_type": "transparency_marking",
    "field": "/payload/watermark_applied",
    "op": "eq",
    "value": true
  },
  "severity": "warning"
}
```

| Param | Type | Description |
|---|---|---|
| `record_type` | `string` | Record type to check |
| `field` | `string` | JSON Pointer path |
| `op` | `string` | Comparison operator: `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `regex` |
| `value` | `any` | Expected value (list for `in`, regex string for `regex`) |

### `evidence_freshness`

Check that all records within scope have timestamps within `max_days` of a reference date.

**Type:** Universal (PASS vacuously on zero records)

```json
{
  "rule_id": "art15-eval-freshness",
  "rule": "evidence_freshness",
  "params": {
    "max_days": 365,
    "reference_date": "validation_time"
  },
  "severity": "warning"
}
```

| Param | Type | Default | Description |
|---|---|---|---|
| `max_days` | `int` | (required) | Maximum age in days |
| `reference_date` | `string` | `"validation_time"` | `"validation_time"` (evaluation_instant), `"package_time"` (metadata.timestamp), or `"obligation_effective_date"` (provision effective_date) |

### `attachment_exists`

Check that at least one record of a given type has an attachment.

**Type:** Existential (FAIL on zero matching records)

```json
{
  "rule_id": "art11-tech-doc-attachment",
  "rule": "attachment_exists",
  "params": {
    "record_type": "evaluation_report",
    "media_type": "application/pdf"
  },
  "severity": "warning"
}
```

| Param | Type | Default | Description |
|---|---|---|---|
| `record_type` | `string` | (required) | Record type to check |
| `media_type` | `string\|null` | `null` | Filter by MIME type (optional) |

### `entity_linked`

Check that every record of a given type has at least one entity ref of a specified type.

**Type:** Universal (PASS vacuously on zero records)

```json
{
  "rule_id": "art10-data-linked-to-dataset",
  "rule": "entity_linked",
  "params": {
    "record_type": "data_provenance",
    "entity_type": "dataset"
  },
  "severity": "warning"
}
```

| Param | Type | Description |
|---|---|---|
| `record_type` | `string` | Record type to check |
| `entity_type` | `string` | Entity type: `subject`, `component`, `dataset`, or `actor` |

### `exists_where`

Check that at least `min_count` records exist where a field satisfies a comparison.

**Type:** Existential (FAIL on zero matching records if `min_count > 0`)

```json
{
  "rule_id": "art50-marking-has-scheme",
  "rule": "exists_where",
  "params": {
    "record_type": "transparency_marking",
    "field": "/payload/marking_scheme_id",
    "op": "ne",
    "value": null,
    "min_count": 1
  },
  "severity": "fail"
}
```

| Param | Type | Default | Description |
|---|---|---|---|
| `record_type` | `string` | (required) | Record type to filter |
| `field` | `string` | (required) | JSON Pointer path |
| `op` | `string` | (required) | Comparison operator |
| `value` | `any` | (required) | Expected value |
| `min_count` | `int` | `1` | Minimum matching records |

### `attachment_kind_exists`

Check that records of a given type have attachments with a matching `attachment_type`.

**Type:** Existential (FAIL on zero matching records)

```json
{
  "rule_id": "art17-qms-policy-doc",
  "rule": "attachment_kind_exists",
  "params": {
    "record_type": "governance_policy",
    "attachment_type": "qms_policy",
    "min_count": 1
  },
  "severity": "warning"
}
```

| Param | Type | Default | Description |
|---|---|---|---|
| `record_type` | `string` | (required) | Record type to check |
| `attachment_type` | `string` | (required) | The `attachment_type` value to match |
| `min_count` | `int` | `1` | Minimum matching records |

### `bundle_signed`

Check that the bundle has at least `min_signatures` valid signatures.

**Type:** Existential (on signatures, not records)

```json
{
  "rule_id": "art9-bundle-signed",
  "rule": "bundle_signed",
  "params": {
    "min_signatures": 1,
    "required_alg": ["RS256", "ES256"]
  },
  "severity": "warning"
}
```

| Param | Type | Default | Description |
|---|---|---|---|
| `min_signatures` | `int` | `1` | Minimum number of signatures |
| `required_alg` | `list[string]\|null` | `null` | Required algorithm(s) |

### `record_attested`

Check that at least `min_count` records of a given type have valid attestation blocks.

**Type:** Existential (FAIL on zero matching records)

```json
{
  "rule_id": "art9-management-review-attested",
  "rule": "record_attested",
  "params": {
    "record_type": "risk_register",
    "min_count": 1
  },
  "severity": "warning"
}
```

| Param | Type | Default | Description |
|---|---|---|---|
| `record_type` | `string` | (required) | Record type to check |
| `min_count` | `int` | `1` | Minimum attested records |

---

## 4. Empty-Set Semantics and Missing-Path Behavior

### Empty-Set Semantics

The behavior when zero records match the operator's filter is a critical design choice (per spec Section 3.5):

- **Existential operators** (`has_record_type`, `exists_where`, `attachment_exists`, `attachment_kind_exists`, `bundle_signed`, `record_attested`): FAIL when zero records match. These operators assert that something must exist.

- **Universal operators** (`field_present`, `field_value`, `evidence_freshness`, `entity_linked`): PASS vacuously when zero records match. The statement "all records of type X satisfy Y" is vacuously true when there are no records of type X.

**Why this matters for template authors:** If you need both "records exist" AND "records have correct fields", you need two rules:

```json
[
  {
    "rule_id": "risk-register-exists",
    "rule": "has_record_type",
    "params": {"type": "risk_register", "min_count": 1},
    "severity": "fail",
    "message": "At least one risk_register record is required"
  },
  {
    "rule_id": "risk-register-has-description",
    "rule": "field_present",
    "params": {"record_type": "risk_register", "field": "/payload/description"},
    "severity": "fail",
    "message": "All risk_register records must have a description"
  }
]
```

The first rule (existential) fails if no risk_register records exist. The second rule (universal) passes vacuously if no records exist, but fails if any record lacks the field. Together, they ensure records exist AND have the right fields.

### Missing-Path Behavior

When a JSON Pointer path does not resolve in a record:

- **`field_present`**: Returns `None` -- the field is not present (FAIL for that record).
- **`field_value`**: Missing value fails all comparisons except `ne`. The `ne` operator returns `True` for `None != expected_value`.
- **`exists_where`**: Missing value fails the comparison -- the record does not match the filter.

---

## 5. Scope Filters and Conditions

### Rule Scope

Each rule can specify scope filters that restrict when it applies:

```json
{
  "rule_id": "high-risk-eval-required",
  "rule": "has_record_type",
  "params": {"type": "evaluation_report", "min_count": 1},
  "severity": "fail",
  "scope": {
    "risk_classifications": ["high-risk"],
    "obligation_roles": ["provider"],
    "lifecycle_phases": ["deployment", "monitoring"],
    "modalities": ["text", "image"]
  }
}
```

| Scope Field | Effect |
|---|---|
| `risk_classifications` | Rule applies only to subjects with matching risk classification |
| `obligation_roles` | Rule applies only to records with matching obligation role |
| `lifecycle_phases` | Rule applies only during these lifecycle phases |
| `modalities` | Rule applies only to subjects with matching modalities |

When a scope field is empty or omitted, no filtering is applied for that dimension. When multiple scope fields are present, they are ANDed together.

### Rule Conditions

Conditions control whether a rule is evaluated at all:

```json
{
  "rule_id": "art9-risk-register-if-effective",
  "rule": "has_record_type",
  "params": {"type": "risk_register"},
  "severity": "fail",
  "condition": {
    "if_provision_effective": true,
    "if_system_type": ["high-risk", "gpai-systemic"]
  }
}
```

| Condition | Effect |
|---|---|
| `if_provision_effective` | If `true`, rule is skipped when `evaluation_instant` is before the provision's `effective_date` |
| `if_system_type` | Rule applies only to subjects matching these types |

---

## 6. Payload Variants

Some record types use payload variants to represent different kinds of evidence within the same record type. The variant registry (`acef-conventions/v1/variant-registry.json`) maps variant names to record types and discriminator fields.

### Using Variants in Rules

To check for a specific variant, use `exists_where` with the discriminator field:

```json
{
  "rule_id": "art9-management-review-exists",
  "rule": "exists_where",
  "params": {
    "record_type": "risk_register",
    "field": "/payload/review_type",
    "op": "eq",
    "value": "management_review",
    "min_count": 1
  },
  "severity": "warning",
  "message": "A management review record is recommended for Art. 9"
}
```

### Standard Variants

| Variant Name | Record Type | Discriminator Field | Value |
|---|---|---|---|
| `management_review` | `risk_register` | `/payload/review_type` | `"management_review"` |
| `post_market_monitoring_plan` | `risk_register` | `/payload/review_type` | `"post_market_monitoring_plan"` |
| `risk_testing_log` | `risk_treatment` | `/payload/treatment_subtype` | `"testing_log"` |
| `marking_standards_compliance` | `transparency_marking` | `/payload/marking_subtype` | `"standards_compliance"` |
| `interaction_disclosure` | `disclosure_labeling` | `/payload/disclosure_subtype` | `"interaction"` |
| `biometric_disclosure` | `disclosure_labeling` | `/payload/disclosure_subtype` | `"biometric"` |
| `logging_spec` | `event_log` | `/payload/event_type` | `"logging_spec"` |
| `gpai_annex_xi_model_doc` | `evaluation_report` | `/payload/variant` | `"gpai_annex_xi_model_doc"` |
| `ai_use_case_inventory_entry` | `governance_policy` | `/payload/variant` | `"ai_use_case_inventory_entry"` |
| `mark_detectability_test` | `evaluation_report` | `/payload/variant` | `"mark_detectability_test"` |
| `training_competency_record` | `governance_policy` | `/payload/variant` | `"training_competency_record"` |
| `publication_evidence` | `transparency_disclosure` | `/payload/variant` | `"publication_evidence"` |

---

## 7. Testing Templates

### Creating Test Vectors

Every template should have test vectors: bundles that are expected to pass or fail validation. Test vectors live in `test-vectors/{template-category}/`:

```
test-vectors/
├── eu-ai-act/
│   ├── article-9-minimal-pass.acef/          # Should pass article-9 provisions
│   ├── article-9-minimal-fail.acef/          # Should fail article-9 provisions
│   ├── article-9-minimal-pass.acef.acef-assessment.json    # Expected assessment
│   └── article-9-minimal-fail.acef.acef-assessment.json
├── nist-rmf/
│   ├── govern-map-measure-manage-pass.acef/
│   └── govern-missing-policy-fail.acef/
```

### Test Vector Structure

Each test vector is a complete ACEF bundle directory paired with an expected Assessment Bundle JSON:

```bash
# Create a passing test vector
python -c "
import acef
pkg = acef.Package(producer={'name': 'test', 'version': '1.0'})
system = pkg.add_subject('ai_system', name='Test', risk_classification='high-risk')
pkg.add_profile('eu-ai-act-2024', provisions=['article-9'])
pkg.record('risk_register', provisions=['article-9'],
           payload={'description': 'Test risk', 'likelihood': 'high', 'severity': 'high'},
           obligation_role='provider', entity_refs={'subject_refs': [system.id]})
pkg.record('risk_treatment', provisions=['article-9'],
           payload={'treatment_type': 'mitigate', 'description': 'Mitigation applied'},
           obligation_role='provider', entity_refs={'subject_refs': [system.id]})
pkg.export('test-vectors/eu-ai-act/my-test-pass.acef/')
"
```

### Running Template Tests

```bash
# Run the full conformance test suite
pytest tests/conformance/

# Run tests for a specific template
pytest tests/conformance/test_golden_bundles.py -k "eu_high_risk"

# Run test vector validation
pytest tests/conformance/test_dsl_operators.py
```

### Registering Test Vectors

Add test vector paths to the template's `test_vectors` field:

```json
{
  "template_id": "my-regulation-2026",
  "test_vectors": [
    "test-vectors/my-regulation/basic-pass.acef",
    "test-vectors/my-regulation/missing-evidence-fail.acef"
  ]
}
```

---

## 8. Best Practices

### Rule Design

1. **Use existential rules for required evidence.** `has_record_type` with `severity: fail` for mandatory record types.

2. **Use universal rules for data quality.** `field_present` and `field_value` with `severity: fail` for mandatory fields, `severity: warning` for recommended fields.

3. **Pair existential and universal rules.** A universal rule alone cannot detect missing records (it passes vacuously). Always pair with a `has_record_type` check.

4. **Use meaningful rule IDs.** Convention: `{provision}-{what}-{check}` (e.g., `art9-risk-register-exists`, `art10-dataset-linked`).

5. **Provide clear messages.** The `message` field appears in Assessment Bundle reports. Make it actionable.

6. **Use `info` severity for recommendations.** Non-binding guidance should use `severity: info` so it does not affect provision outcomes.

### Provision Design

1. **Map provisions 1:1 to regulatory articles.** Each provision should correspond to a single regulatory requirement.

2. **Use sub-provisions for granularity.** Document sub-articles as `sub_provisions` but keep evaluation rules at the provision level.

3. **Set effective dates.** Rules for provisions with future effective dates are automatically skipped, producing `ACEF-032` info diagnostics.

4. **Specify `applicable_to`.** Not all provisions apply to all risk classifications. Use this field to prevent false positives.

5. **Use `evaluation_scope: "package"` sparingly.** Most provisions should be per-subject. Use package scope only for organizational requirements (e.g., governance policies, QMS documentation).

### Template Maintenance

1. **Version templates with semver.** Breaking changes (new fail-severity rules) increment the major version.

2. **Document normative references.** Fill in `normative_text_ref` for every provision so auditors can trace rules to regulatory text.

3. **Create test vectors for every provision.** At minimum, one passing and one failing bundle per provision.

4. **Review with legal counsel.** Template rules encode legal interpretations. Ensure they are reviewed by someone who understands the regulation.

5. **Use the `superseded_by` field.** When a regulation is updated, create a new template and set `superseded_by` on the old one.
