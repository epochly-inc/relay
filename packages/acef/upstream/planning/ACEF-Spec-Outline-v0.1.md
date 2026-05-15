# AI Compliance Evidence Format (ACEF) — Specification Outline v0.3

**Status:** Working Draft
**Date:** 2026-03-17
**Owner:** AI Commons (non-profit, open standard)
**Analogies:** OTLP for compliance, CycloneDX/SPDX for AI governance, C2PA for provenance, W3C PROV for entity relationships

---

## 1. Purpose & Positioning

ACEF is an **open, vendor-neutral specification** for how to package machine-readable proof that an AI system complies with applicable regulations, standards, and governance commitments. It is **not** a compliance engine — it is the **wire format** that compliance tools, audit platforms, and regulators consume.

**What AI Commons owns (non-profit, open standard):**

- **The ACEF Specification** — JSON Schema, versioned, community-governed. The "OTLP of compliance."
- **A Reference Capture SDK** — minimum viable library that records traces, guardrails, and oversight events to the open format. Python first; community contributes TypeScript/Go/Java.
- **Regulation Mapping Templates** — the JSON config files that define what each regulation requires. Community-maintained, peer-reviewed, freely available. Compliance knowledge should not be proprietary.
- **A Reference Validator** — open-source evaluator that executes regulation mapping template rules against ACEF packages and produces machine-readable validation results. This prevents compliance logic from being locked inside proprietary tools.
- **Conformance Test Suite** — golden files and cross-language round-trip tests that define what "ACEF-compatible" means.

**What commercial providers build (on top of the open layer):**

Commercial tools differentiate on workflow, dashboards, integrations, managed services, analytics, and advisory — NOT on the format, schemas, mapping templates, or rule semantics. Any product claiming "ACEF-compatible" MUST pass the public conformance suite and export lossless ACEF Evidence Bundles.

### 1.0.1 ACEF v1 Scope

ACEF v1 is defined as **three separate, independently versioned modules:**

| Module | Contents | v1 Scope |
|---|---|---|
| **ACEF Core** | Envelope schema, entity model, bundle layout, integrity model, canonical serialization, error taxonomy | Normative — the at-rest bundle format |
| **ACEF Profiles** | Regulation mapping templates, record type schemas, rule DSL, validation result schema | Normative — what evidence is required per regulation |
| **ACEF Assessment** | Assessment result bundles, provision status, auditor findings, signed conclusions | Normative — separated from evidence to preserve the open boundary |

**v1 explicitly excludes:** transport protocol (companion spec if needed), real-time streaming, conformity assessment certification procedures.

### 1.0.2 Two Artifact Types

ACEF defines two distinct artifact types to cleanly separate evidence from assessment:

1. **ACEF Evidence Bundle** — raw evidence records, entity graph, integrity metadata, and attachments. Produced by the system provider or deployer. Contains NO pass/fail judgments.
2. **ACEF Assessment Bundle** — rule-evaluation results, provision status, auditor findings, attestations, and signed conclusions. Produced by validators, auditors, or notified bodies. References an Evidence Bundle by hash.

This separation ensures AI Commons owns the open evidence substrate and open rule definitions, while commercial vendors differentiate on workflow, dashboards, and managed services — not on the compliance knowledge itself.

### 1.1 Design Principles

| Principle | Rationale |
|---|---|
| **Regulation-agnostic envelope, regulation-specific payloads** | One format serves EU AI Act, NIST AI RMF, US Copyright Office guidance, China CAC, UK requirements — via pluggable mapping templates |
| **Evidence, not assertions** | Every compliance claim must link to verifiable evidence artifacts (logs, test results, documents, hashes) |
| **Machine-readable first, human-readable second** | JSON Schema primary; renderers produce human-readable views for auditors |
| **Immutable, signable, chainable** | Borrow from C2PA manifests and SBOM signing — every evidence package is hashable, signable, and can reference prior versions |
| **Extensible via semantic conventions** | Borrow from OTLP — core schema is stable; regulation-specific fields live in semantic conventions that evolve independently |
| **Privacy-aware** | Confidential evidence (trade secrets, PII in training data) can be attested without disclosure, using hash commitments or zero-knowledge proofs |
| **Dual-track: model-level + system-level** | GPAI model evidence (training, evaluation, copyright) and deployed system evidence (logs, oversight, incidents) are distinct but linkable tracks — reflecting the EU AI Act's provider/deployer split |
| **Content-addressable bundle** | Package is a directory (or archive) with manifest + records + artifacts + hashes + signatures, not a single monolithic JSON — enabling selective disclosure, large log handling, and partial verification |
| **W3C PROV-compatible entity model** | Core entities (Subject, Component, Dataset, Actor, Control) form a relationship graph compatible with W3C PROV's Agent/Entity/Activity model, enabling interoperability with provenance ecosystems |
| **Evidence and assessment are separate artifacts** | Evidence Bundles contain raw proof; Assessment Bundles contain evaluation results. This prevents compliance knowledge from being hidden inside proprietary evaluators. |
| **Open boundary enforcement** | AI Commons-managed schemas, templates, and rule semantics are publicly versioned, signed, and licensed under permissive terms (Apache 2.0 for code, CC-BY 4.0 for templates and schemas). Vendor extensions MUST use namespaced prefixes and be safely ignorable by standard validators. |

---

## 2. Regulatory Landscape — What ACEF Must Capture

### 2.1 EU AI Act (High-Risk Systems: Articles 9–17, 50, Annexes IV/XI/XII)

The EU AI Act is the most implementation-specific regulatory framework globally. ACEF must capture evidence for every article requirement.

#### Article 9 — Risk Management System

| Requirement | ACEF Evidence Artifact |
|---|---|
| Continuous, iterative, documented risk management across full lifecycle | `risk_management_plan` with version history, lifecycle phase tags |
| Risk identification, estimation, evaluation for health/safety/fundamental rights | `risk_register` entries: risk ID, description, likelihood, severity, category (health/safety/rights), assessment method |
| Risk elimination/reduction/mitigation measures | `risk_treatment` entries: treatment type (eliminate/reduce/mitigate/accept), control description, implementation status |
| Residual risk acceptance with justification | `residual_risk_assessment`: residual risk level, acceptability justification, approver, date |
| Testing to find most appropriate risk management measures | `risk_testing_log`: test method, results, date, link to risk ID |
| Post-market monitoring integration | `post_market_monitoring_plan` with trigger conditions, data sources |
| Management review with signed minutes | `management_review` records: date, attendees, decisions, linked risk IDs, signatories |

#### Article 10 — Data Governance & Training Data

| Requirement | ACEF Evidence Artifact |
|---|---|
| Training/validation/test datasets are relevant, representative, error-free, complete | `dataset_card`: name, version, source, size, modality, representativeness assessment, known limitations |
| Data governance processes | `data_governance_log`: curation steps, bias mitigation methods, quality checks performed |
| Dataset provenance and lineage | `data_provenance`: source URIs, acquisition method (licensed/scraped/public domain/synthetic), acquisition dates, chain of custody |
| Bias detection and mitigation | `bias_assessment`: protected attributes tested, metrics used, results, mitigation actions taken |

#### Article 11 — Technical Documentation (Annex IV)

| Requirement | ACEF Evidence Artifact |
|---|---|
| System description, intended purpose, development process | `system_description`: model architecture, intended purpose, development methodology, version |
| Monitoring, functioning, control details | `operational_design`: monitoring mechanisms, control interfaces, human override capabilities |
| Performance metrics and appropriateness | `performance_metrics`: metric name, value, threshold, test conditions, assessment of appropriateness |
| Risk management system description | Cross-reference to `risk_management_plan` |
| Lifecycle changes by provider | `changelog`: version, date, change description, impact assessment |
| Applied technical standards | `standards_applied`: standard ID (ISO/CEN/etc.), version, scope of application |
| Declaration of conformity | `conformity_declaration`: date, scope, notified body (if applicable), certificate reference |
| System performance evaluation methods and results | `evaluation_report`: methodology, test datasets, results, confidence intervals |

**Retention:** 10 years (ACEF metadata must include retention policy).

#### Article 12 — Record-Keeping / Automatic Logging

| Requirement | ACEF Evidence Artifact |
|---|---|
| Automatic event logging throughout lifecycle | `event_log` entries: timestamp, event type, system state, input summary hash, output summary hash |
| Traceability to intended purpose | `traceability_record`: session ID, user/deployer ID, purpose classification |
| Tamper-resistant logs | `log_integrity`: hash chain, signing certificate, tamper-detection method |
| People involved in verifying results | `verification_record`: verifier ID, role, timestamp, decision |
| Usage period and input/output data references | `usage_log`: time period, data volume, input/output reference hashes |

**Retention:** minimum 6 months for deployers (ACEF must support configurable retention policies).

#### Article 13 — Transparency & Instructions for Use

| Requirement | ACEF Evidence Artifact |
|---|---|
| Instructions for use enabling deployer compliance | `instructions_for_use`: capabilities, limitations, intended use, risk warnings, interpretation guidance |
| System characteristics, capabilities, limitations | `capability_card`: modality, performance envelope, known failure modes, out-of-scope uses |
| Output interpretation mechanisms | `interpretability_spec`: explanation methods available, confidence indicators, uncertainty quantification |

#### Article 14 — Human Oversight

| Requirement | ACEF Evidence Artifact |
|---|---|
| Designed for human oversight during use | `oversight_design`: oversight mechanisms, intervention points, override capabilities |
| Users can understand capacities/limitations | Cross-reference to `capability_card` and `instructions_for_use` |
| Users can correctly interpret outputs | Cross-reference to `interpretability_spec` |
| Users can intervene/override | `intervention_log`: override events, human decision records, escalation paths |

#### Article 15 — Accuracy, Robustness, Cybersecurity

| Requirement | ACEF Evidence Artifact |
|---|---|
| Appropriate accuracy levels | `accuracy_assessment`: metrics, thresholds (set pre-development), test results, conditions |
| Robustness testing | `robustness_assessment`: adversarial testing methods, perturbation types, results |
| Cybersecurity measures | `security_assessment`: threat model, controls implemented, penetration test results, vulnerability scan results |
| Continuous learning bias prevention | `drift_monitoring`: monitoring method, detection thresholds, corrective actions log |

#### Article 17 — Quality Management System

Article 17 is documentary by construction — it requires written policies, procedures, and instructions that span the full compliance lifecycle. This is the "meta-evidence" layer: evidence that the *process* for producing evidence exists and is maintained.

| Requirement | ACEF Evidence Artifact |
|---|---|
| Written QMS policies, procedures, and instructions | `qms_document`: document type (policy/procedure/instruction), title, version, approval date, review cycle |
| Design and development controls | `design_control`: design inputs, design outputs, design review records, design verification/validation |
| Testing and validation procedures | `test_validation_procedure`: procedure ID, scope, method, acceptance criteria, version |
| Technical specifications and standards applied | Cross-reference to `standards_applied` |
| Data management systems and procedures | `data_management_procedure`: data lifecycle, retention rules, access controls, backup/recovery |
| Risk management procedures | Cross-reference to `risk_management_plan` |
| Post-market monitoring system | Cross-reference to `post_market_monitoring_plan` |
| Serious incident and malfunction reporting procedures | `incident_procedure`: reporting triggers, timelines, notification channels, escalation paths |
| Communication with competent authorities | `authority_communication_log`: date, authority, subject, response, reference number |
| Record-keeping procedures | `recordkeeping_procedure`: retention periods per document type, storage mechanisms, retrieval process, destruction policy |
| Resource management and accountability | `resource_allocation`: team structure, competency requirements, training records |
| Accountability framework | `accountability_framework`: governance structure, reporting lines, delegation of authority |

**Retention:** QMS documentation must be maintained for the lifetime of the system + applicable retention periods (up to 10 years after market placement).

#### Article 50 — Transparency for Synthetic Content and Limited-Risk Systems

Article 50 applies broadly — not only to high-risk systems — and establishes transparency obligations for AI systems that interact with persons, generate synthetic content, or perform emotion recognition/biometric categorization. These obligations are distinct from Article 13 (high-risk transparency) and from the Labelling Code of Practice (which operationalizes Article 50's marking requirements).

| Requirement | ACEF Evidence Artifact |
|---|---|
| Providers of systems generating synthetic audio/image/video/text MUST ensure outputs are marked in a machine-readable format and detectable as artificially generated, using effective, interoperable, robust, and reliable solutions | `transparency_marking`: marking technique (secure metadata/watermark/digital signature), robustness parameters, interoperability standard, detection method |
| Marking solutions MUST be informed by generally acknowledged state of the art, including relevant harmonised standards | `marking_standards_compliance`: standards applied, conformity evidence, state-of-the-art assessment |
| Deployers of deepfake systems MUST disclose artificial generation/manipulation | `disclosure_labeling`: disclosure type (deepfake/synthetic text/emotion recognition), placement, accessibility, timing, audience |
| Deployers of AI-generated/manipulated public-interest text MUST disclose this fact | `disclosure_labeling`: content category (public-interest text), disclosure method, first-exposure visibility |
| Providers of AI systems interacting with natural persons MUST ensure the system informs users they are interacting with AI (unless obvious from context) | `interaction_disclosure`: disclosure mechanism, trigger conditions, exemption justification (if applicable) |
| Providers of emotion recognition / biometric categorization systems MUST inform exposed natural persons | `biometric_disclosure`: system type, affected persons notification mechanism, data processing transparency |

**Note:** Article 50 obligations apply to providers AND deployers with distinct responsibilities. The `obligation_role` field on evidence records (see Section 3.1) tracks which party is responsible for each piece of evidence.

#### Annex XI — Technical Documentation for GPAI Models

Annex XI defines minimum structured data requirements for GPAI model documentation. These fields map naturally to ACEF record payloads.

| Required Field | ACEF Evidence Artifact |
|---|---|
| Acceptable use policy | `acceptable_use_policy`: policy document, version, restrictions, enforcement mechanisms |
| Model architecture, parameter count, modality, I/O formats | `model_architecture`: architecture type, parameter count, input modalities, output modalities, context length, format specifications |
| Data types, provenance, curation, bias detection | Cross-reference to `dataset_card`, `data_provenance`, `bias_assessment` |
| Compute used for training | `compute_record`: hardware type, total GPU/TPU hours, cloud provider, training duration |
| Known/estimated energy consumption | `energy_consumption`: total kWh, carbon intensity (gCO2eq/kWh), methodology (measured vs. estimated), reporting standard |
| License terms | `model_license`: license type, restrictions, distribution terms |
| Evaluation strategies, metrics, and results | Cross-reference to `evaluation_report` |
| Adversarial testing / red teaming (systemic risk) | `adversarial_testing`: methodology, attack types, results, independent evaluator, date |
| System architecture description (systemic risk) | `system_architecture`: component diagram, data flow, integration points, scaling characteristics |

#### Annex XII — Documentation for Downstream Integrators

| Required Field | ACEF Evidence Artifact |
|---|---|
| Capabilities and limitations documentation | Cross-reference to `capability_card` and `instructions_for_use` |
| Integration guidance | `integration_guidance`: API documentation, rate limits, supported use cases, prohibited uses |
| Risk information for downstream deployers | `downstream_risk_advisory`: known risks, recommended mitigations, deployment constraints |

---

### 2.2 EU AI Act — GPAI Model Obligations (Articles 53, 55)

#### General-Purpose AI Code of Practice

| Requirement | ACEF Evidence Artifact |
|---|---|
| **Transparency: Sufficiently detailed training data summary** (mandatory template) | `training_data_summary`: model/provider ID, version, modalities, data size, language/demographic coverage, intended purpose |
| List of data sources | `data_sources[]`: dataset name, source type (licensed/scraped/public domain/synthetic/user-generated), for web scraping: top 10% domains, crawler identifiers, crawl timing windows |
| Data processing aspects | `data_processing`: pre-training steps, copyright opt-out respect method, content moderation for illegal material |
| Confidential Model Documentation Form (MDF) for regulators | `model_documentation_form`: detailed dataset provenance/composition (confidential, hash-attested) |
| **Copyright: TDM opt-out compliance** | `copyright_rights_reservation`: opt-out detection method (robots.txt, TDMRep, HTTP headers), removal/exclusion process, compliance verification date |
| Licensed content agreements | `licensing_records[]`: licensor, scope, date, content type, agreement reference |
| Output infringement prevention | `output_guardrails`: methods for preventing infringing outputs, testing results |
| Complaint handling | `complaint_mechanism`: process description, contact, response SLA |
| **Safety/Security (systemic risk GPAI only):** | |
| Safety and Security Framework document | `safety_framework`: responsibilities, evaluation triggers, risk forecasting methodology, mitigations |
| Systemic risk assessments (CBRN, loss of control, cyber offense, manipulation) | `systemic_risk_assessment[]`: risk category, assessment method, adversarial/red-team results, independent evaluator ID |
| Model Report | `model_report`: pre-market submission date, risk summary, mitigations, update history |
| Incident reporting (2–15 day notification) | `incident_report[]`: incident type, severity, notification date, AI Office reference |
| Cybersecurity protections | `security_controls`: encryption, access controls, insider threat mitigations |

---

### 2.3 EU Marking & Labelling Code of Practice (AI-Generated Content)

Based on the second draft (March 2026), applicable August 2, 2026.

| Requirement | ACEF Evidence Artifact |
|---|---|
| **Layer 1: Secured metadata** — machine-readable provenance in outputs | `content_provenance_metadata`: AI system identifier, generation timestamp, synthetic origin indicator, format (C2PA manifest encouraged) |
| **Layer 2: Digital watermarking** — imperceptible, robust to compression/cropping/tampering | `watermark_spec`: method, robustness parameters, detection API endpoint |
| **Optional: Fingerprinting** — content hashes / perceptual hashes | `content_fingerprint`: hash algorithm, hash value, robustness to modifications |
| **Optional: Logging** — server-side generation event records | `generation_log`: event ID, timestamp, model version, content type, access API |
| **Detection/Verification APIs** — free, with confidence scores | `verification_api`: endpoint, authentication, response schema (confidence score, provenance data, synthetic indicator) |
| **Uniform EU icon** — "AI" / "IA" / "KI" acronym, positioned consistently | `label_compliance`: icon variant used, placement description, first-exposure visibility |
| **Provider vs. Deployer split** | `obligation_role`: provider (technical marking) vs. deployer (user-facing labels/disclosures) |

---

### 2.4 NIST AI Risk Management Framework (AI RMF 1.0)

NIST does not mandate specific formats but requires "objective evidence" for trustworthiness. ACEF regulation mapping templates translate NIST subcategories into evidence requirements.

#### GOVERN Function

| Subcategory | ACEF Evidence Artifact |
|---|---|
| AI governance policies | `governance_policy`: policy document reference, version, approval date, scope |
| Roles and responsibilities | `accountability_matrix`: RACI matrix, AI oversight committee charter, named roles |
| Risk appetite statements | `risk_appetite`: acceptable risk thresholds per domain, approval authority |
| Organizational AI principles | `ai_principles`: principles document, mapping to trustworthiness characteristics |

#### MAP Function

| Subcategory | ACEF Evidence Artifact |
|---|---|
| System context documentation | `system_context`: legal environment, deployment context, operational constraints |
| Stakeholder analysis | `stakeholder_analysis`: affected parties, impact types, engagement records |
| Risk identification | `risk_identification`: risk register entries, categorization (validity/reliability/safety/security/accountability/transparency/explainability/privacy/fairness) |
| Capability and limitation mapping | `capability_limitations`: intended capabilities, known limitations, failure modes |

#### MEASURE Function

| Subcategory | ACEF Evidence Artifact |
|---|---|
| Evaluation metrics and thresholds | `evaluation_metrics[]`: metric name, value, threshold, test conditions |
| Test, Evaluation, Verification, Validation (TEVV) reports | `tevv_report`: methodology, datasets, results, reviewer |
| Bias and fairness assessments | `fairness_assessment`: protected attributes, disparate impact analysis, mitigation actions |
| Performance benchmarks | `benchmark_results`: benchmark name, score, comparison baseline, date |

#### MANAGE Function

| Subcategory | ACEF Evidence Artifact |
|---|---|
| Risk treatment plans | `risk_treatment_plan`: risk ID, treatment strategy, implementation timeline, responsible party |
| Monitoring logs | `monitoring_log`: drift detection results, performance tracking, alerting events |
| Incident response records | `incident_record`: incident ID, root cause analysis, corrective actions, resolution date |
| Decommissioning records | `decommission_record`: reason, data disposition, notification to stakeholders |

#### NIST AI 600-1 — Generative AI Profile Additions

| Requirement | ACEF Evidence Artifact |
|---|---|
| GAI-specific risk identification (12 categories: hate speech, data privacy, bias amplification, CBRN, cyber, environmental, etc.) | `gai_risk_assessment[]`: risk category (from NIST 600-1 taxonomy), assessment method, current vs. target state |
| Dual-use risk evaluation | `dual_use_assessment`: capability analysis, access controls, monitoring |
| Foundation model-specific documentation | `foundation_model_card`: parameter count, training compute (FLOPs), architecture, training methodology |

---

### 2.5 US Copyright Office — Part 3 Generative AI Training Guidance

The Copyright Office does not impose binding rules but establishes the policy baseline for lawful acquisition, licensing, and risk management. ACEF should capture evidence that aligns with these expectations.

| Guidance Area | ACEF Evidence Artifact |
|---|---|
| Lawful vs. unlawful acquisition of training data | `acquisition_record[]`: source, acquisition method, legal basis (license/fair use/public domain), date |
| Licensing pathway documentation | `license_record[]`: licensor, scope, restrictions, expiration, content type |
| Curation and filtering processes | `curation_log`: filtering criteria, deduplication methods, content removal decisions |
| Memorization/regurgitation risk mitigation | `memorization_mitigation`: detection methods, test results, guardrails implemented |
| Technical guardrails against infringing output | `output_guardrails`: blocking methods (prompt filtering, internal instructions), effectiveness testing |
| Recordkeeping for legal defensibility | `legal_defensibility_record`: fair use analysis, transformative purpose documentation, guardrail effectiveness evidence |

---

### 2.6 China CAC — Measures for Labeling AI-Generated Content

Effective September 1, 2025. Mandatory for internet information service providers in China.

| Requirement | ACEF Evidence Artifact |
|---|---|
| Explicit visible labels (text superscript, audio cues, graphic watermarks) | `visible_label`: label type (text/audio/graphic), placement, persistence across sharing/download |
| Implicit metadata labels (provider name/code, content ID/type, reference number) | `implicit_metadata`: provider_id, content_id, content_type, reference_number |
| Digital watermarks (encouraged for robustness) | `digital_watermark`: method, robustness spec, detection capability |
| Platform verification duties (confirmed/possible/suspected categorization) | `platform_verification`: detection method, categorization (confirmed/possible/suspected), platform-specific metadata |
| User declarations when publishing | `user_declaration`: declaration timestamp, platform, content type |
| Log retention (6 months for unlabeled content) | `audit_log`: retention period, content reference, labeling status |
| CAC registration filings | `regulatory_filing`: filing date, registration number, filing authority |

---

### 2.7 UK — House of Lords Recommendations (March 2026)

Not yet binding, but establishes the direction for UK legislation on AI and copyright.

| Recommendation Area | ACEF Evidence Artifact |
|---|---|
| Mandatory training data disclosure | `training_data_disclosure`: disclosure scope (public vs. regulator-confidential), content summary, publication date |
| Rights reservation / opt-out compliance | `rights_reservation`: opt-out mechanisms respected, removal processes, verification |
| Provenance standards compliance | `provenance_certification`: standards applied, certification body, certification date |
| Licensing agreements with rights-holders | Cross-reference to `license_record[]` |
| Transparency reporting | `transparency_report`: public disclosure document, reporting period, scope |

---

## 3. ACEF Schema Architecture

### 3.1 Envelope Structure

Borrowing from OTLP's resource-scope-record pattern, CycloneDX's BOM envelope, and W3C PROV's entity-activity-agent model:

```
ACEFPackage
├── metadata                    # Package-level metadata
│   ├── package_id              # URN identifier (urn:acef:pkg:<uuid>)
│   ├── timestamp               # Package creation time (ISO 8601)
│   ├── producer                # Organization/tool that created this package
│   │   ├── name                # Producer name
│   │   └── version             # Producer tool version
│   ├── prior_package_ref       # Hash reference to prior version (for chaining)
│   └── retention_policy        # Package-level retention requirements
│       ├── min_retention_days  # Minimum retention period (e.g., 3650 for 10 years)
│       └── personal_data_interplay # How retention interacts with data protection (GDPR Art. 17 etc.)
│
├── subjects[]                  # The AI systems/models being documented (PLURAL — supports composed systems)
│   ├── subject_id              # URN identifier (urn:acef:sub:<uuid>)
│   ├── subject_type            # "ai_system" | "ai_model" — reflects EU AI Act provider/deployer split
│   ├── name                    # Human-readable name
│   ├── version                 # System/model version
│   ├── provider                # Organization responsible
│   ├── risk_classification     # high-risk | gpai | gpai-systemic | limited-risk | minimal-risk
│   ├── modalities              # Input/output modalities (text, image, audio, video, multimodal)
│   ├── lifecycle_phase         # Current phase (design, development, testing, deployment, monitoring, decommission)
│   └── lifecycle_timeline[]    # Phase transition history
│       ├── phase               # Lifecycle phase
│       ├── start_date          # ISO 8601
│       └── end_date            # ISO 8601 (null if current)
│
├── entities                    # First-class entity graph (W3C PROV-compatible)
│   ├── components[]            # Subsystems, model versions, deployment components
│   │   ├── component_id        # URN identifier (urn:acef:cmp:<uuid>)
│   │   ├── name                # Component name
│   │   ├── type                # model | retriever | guardrail | orchestrator | tool | database | api
│   │   ├── version             # Component version
│   │   ├── subject_refs[]       # Which subjects this component belongs to (many-to-many; shared components are common)
│   │   └── provider            # Component provider (may differ from system provider)
│   │
│   ├── datasets[]              # Training, validation, test datasets — defined once, referenced by records
│   │   ├── dataset_id          # URN identifier (urn:acef:dat:<uuid>)
│   │   ├── name                # Dataset name
│   │   ├── version             # Dataset version
│   │   ├── source_type         # licensed | scraped | public_domain | synthetic | user_generated
│   │   ├── modality            # text | image | audio | video | tabular | multimodal
│   │   ├── size                # { records: N, size_gb: N }
│   │   └── subject_refs[]      # Which subjects this dataset is associated with (many-to-many)
│   │
│   ├── actors[]                # People and organizations involved — privacy-aware identifiers
│   │   ├── actor_id            # URN identifier (urn:acef:act:<uuid>)
│   │   ├── role                # provider | deployer | importer | distributor | auditor | regulator | data_subject
│   │   ├── name                # Name or pseudonym (redactable)
│   │   └── organization        # Organization affiliation
│   │
│   └── relationships[]         # Entity graph edges (W3C PROV-compatible)
│       ├── source_ref          # URN of source entity
│       ├── target_ref          # URN of target entity
│       ├── relationship_type   # wraps | calls | fine_tunes | deploys | trains_on | evaluates_with | oversees
│       └── description         # Human-readable description
│
├── profiles[]                  # Which regulation mapping templates this package addresses
│   ├── profile_id              # e.g., "eu-ai-act-2024", "nist-ai-rmf-1.0", "china-cac-labeling-2025"
│   ├── template_version        # Version of the regulation mapping template used
│   └── applicable_provisions[] # Specific articles/subcategories (e.g., "article-9.1.a", "govern-1.1")
│   # NOTE: provision_status and pass/fail assessments belong in the ACEF Assessment Bundle,
│   # NOT in the Evidence Bundle. See Section 1.0.2.
│
├── evidence_records[]          # The actual compliance evidence
│   ├── record_id               # URN identifier (urn:acef:rec:<uuid>)
│   ├── record_type             # Semantic type from ACEF conventions (e.g., "risk_register", "dataset_card", "event_log")
│   ├── provisions_addressed[]  # Which regulatory provisions this evidence supports (dotted notation: "article-9.1.a")
│   ├── timestamp               # When this evidence was created/collected (ISO 8601)
│   ├── lifecycle_phase         # Which lifecycle phase this evidence relates to
│   ├── collector               # Tool/person that collected this evidence
│   ├── obligation_role         # provider | deployer | importer | distributor | authorised_representative | notified_body | platform
│   #                           REQUIRED for transparency_marking, disclosure_labeling, and event_log records (EU AI Act and CAC split obligations by role)
│   ├── confidentiality         # public | redacted | hash-committed | regulator-only | under-nda
│   ├── redaction_method        # (if confidentiality != public) hash algorithm, ZKP reference, or attestation method
│   ├── access_policy           # Who can see the full payload: { roles: [], organizations: [] }
│   ├── trust_level             # self-attested | peer-reviewed | independently-verified | notified-body-certified
│   ├── entity_refs             # Links to entities this record concerns
│   │   ├── subject_refs[]      # URNs of subjects (urn:acef:sub:...)
│   │   ├── component_refs[]    # URNs of components (urn:acef:cmp:...)
│   │   ├── dataset_refs[]      # URNs of datasets (urn:acef:dat:...)
│   │   └── actor_refs[]        # URNs of actors (urn:acef:act:...)
│   ├── payload                 # The actual evidence data (schema varies by record_type — see Sections 3.1.4 and 3.3)
│   ├── attachments[]           # References to files in artifacts/ directory
│   │   ├── path                # Relative path within bundle (e.g., "artifacts/eval-report-v3.pdf")
│   │   ├── hash                # SHA-256 hash (advisory — `content-hashes.json` is authoritative for integrity; this field is for quick client-side checks without loading the hash index)
│   │   ├── media_type          # MIME type
│   │   ├── attachment_type     # Logical kind (e.g., "management_review", "post_market_monitoring_plan", "qms_policy") — used by DSL attachment_kind_exists operator
│   │   └── description         # Human-readable description
│   ├── attestation             # Optional cryptographic attestation of evidence authenticity
│   │   ├── method              # "jws" (MUST for v1 — C2PA record attestation deferred to future profile)
│   │   ├── signer              # Signer identity (URN or X.509 subject)
│   │   ├── signed_fields       # JSON Pointer array of fields included in signature scope (MUST include "/payload")
│   │   └── signature           # Detached JWS over RFC 8785-canonicalized JSON of the signed fields extracted from the record
│   └── retention               # Per-record retention requirements (may differ from package-level)
│       ├── min_retention_days  # Minimum retention (e.g., 180 for 6-month log retention)
│       ├── retention_start_event # first_use | first_deployment | record_creation | custom (disambiguates when the clock starts)
│       └── legal_basis         # Regulation requiring this retention (e.g., "eu-ai-act-2024:article-12")
│
├── audit_trail[]               # Package-level audit history
│   ├── event_type              # created | updated | reviewed | submitted | certified
│   ├── timestamp               # When (ISO 8601)
│   ├── actor_ref               # URN of actor (urn:acef:act:...)
│   └── description             # What changed
│
└── versioning                  # Module version declarations (see Section 1.0.1)
    ├── core_version            # ACEF Core module version (semver)
    └── profiles_version        # ACEF Profiles module version (semver)
```

**Note:** This tree describes the ACEF **conceptual data model**. The normative serialized form uses `record_files[]` in `acef-manifest.json` to reference external record files in `records/`. Evidence record payloads are NOT embedded in the manifest. See Section 3.1.2 for the normative JSON shape.

**Note on versioning:** The Evidence Bundle declares `core_version` and `profiles_version` only. The `assessment_version` is declared in the Assessment Bundle, not the Evidence Bundle, because evidence producers do not know which assessment module version a later validator will use.

**Note on integrity:** The manifest contains NO integrity fields. All integrity verification — hashes, Merkle tree, signatures — lives entirely in the `hashes/` and `signatures/` directories, which are **outside** the hash domain. This eliminates any circular dependency between the manifest and its own hash. See Section 3.1.3 for the complete integrity specification.

**Canonical bundle identity:** The canonical identifier for an ACEF Evidence Bundle is the **SHA-256 hash of the RFC 8785-canonicalized `content-hashes.json`** file. This single value MUST be used consistently for: `metadata.prior_package_ref` (chaining to prior versions), `evidence_bundle_ref.content_hash` in Assessment Bundles, and any future transport/registry APIs. This is referred to as the **bundle digest** throughout the spec.
```

**Key design decisions in this structure:**

- **`subjects[]` is plural.** Most real deployments are composed systems (RAG pipeline + LLM + retriever + guardrails). The `entities.relationships[]` graph captures how components relate.
- **No compliance status in the Evidence Bundle.** The Evidence Bundle contains no self-reported compliance claims. All assessment outcomes (provision status, pass/fail) are produced by validators in the separate Assessment Bundle (Section 3.7). This ensures the *consumer* (auditor/regulator) derives compliance from evidence, not from producer assertions.
- **`obligation_role` on every evidence record.** Articles 16 and 26 of the EU AI Act define distinct obligations for providers vs. deployers. Every piece of evidence must declare who is responsible for producing it.
- **`confidentiality` and `access_policy` are first-class.** The EU AI Act explicitly references confidentiality when authorities obtain information. Missing evidence and confidential evidence are distinguishable via `confidentiality` + the `evidence_gap` record type (see Section 3.2).
- **`trust_level` distinguishes evidence provenance.** Self-attested evidence and notified-body-certified evidence carry different weight; auditors need this distinction without reconstructing it from context.
- **Entity-record separation.** Entities (datasets, components, actors) are defined once in the entity graph and referenced by URN from evidence records. This eliminates duplication when the same dataset is referenced by provenance, bias, governance, and copyright records.
- **Per-record retention.** Different records within the same package may have different retention requirements (10 years for technical documentation per Art. 11; 6 months minimum for deployer logs per Art. 12).

### 3.1.1 Canonical Bundle Layout

An ACEF Package (ACEF-P) is a content-addressable bundle stored as a directory or archive (.acef.tar.gz). The layout is normative — tools producing ACEF packages MUST use this structure.

```
my-system-evidence-2026-q1.acef/
├── acef-manifest.json              # The envelope (metadata, subjects, entities, profiles, audit_trail)
├── records/                        # Evidence records — one or more files per record type
│   ├── risk_register.jsonl         # JSON Lines format for high-volume record types
│   ├── event_log/                  # Sharded directory for very large logs
│   │   ├── event_log.0001.jsonl
│   │   ├── event_log.0002.jsonl
│   │   └── ...
│   ├── data_provenance.jsonl        # JSONL — same format regardless of record count
│   ├── evaluation_report.jsonl
│   ├── transparency_marking.jsonl
│   └── ...
├── artifacts/                      # External evidence files referenced by records
│   ├── eval-report-v3.pdf
│   ├── model-card.md
│   ├── qms-policy-v2.1.pdf
│   ├── training-data-summary.csv
│   └── ...
├── hashes/                         # Integrity verification (OUTSIDE the hash domain)
│   ├── content-hashes.json         # SHA-256 hash for every file in acef-manifest.json + records/ + artifacts/
│   └── merkle-tree.json            # Merkle tree over content-hashes, with root hash
└── signatures/                     # Detached signatures (OUTSIDE the hash domain)
    ├── provider-signature.jws      # JWS (RFC 7515) over content-hashes.json
    └── auditor-signature.jws       # Optional third-party attestation signature
```

**Format rules:**

- **All record files MUST use JSON Lines format (`.jsonl`).** Each line is one RFC 8785-canonicalized JSON record followed by `\n` (0x0A). This applies regardless of record count — even single-record files use JSONL.
- **Sharding:** Record types with more than 100,000 entries SHOULD be sharded into a subdirectory named after the record type, with numbered `.jsonl` files (e.g., `records/event_log/event_log.0001.jsonl`). Shard numbers MUST be zero-padded to 4 digits (e.g., `0001`, `0002`). **Deterministic shard-splitting algorithm:** split at the **earlier** of 100,000 records or the last complete record before the shard reaches 256 MB. If 100,000 records fit within 256 MB, split at exactly 100,000. If fewer than 100,000 records would exceed 256 MB, split at the last complete record before the 256 MB boundary. This ensures all conformant exporters produce identical shard boundaries from identical input.
- **Record ordering (normative for conformance):** Within each `.jsonl` file (or shard), records MUST be sorted by `timestamp` ascending (ISO 8601 lexicographic). Records with identical timestamps MUST be sub-sorted by `record_id` ascending (lexicographic). This ensures deterministic output: two exporters producing a bundle from the same logical record set MUST produce byte-identical `.jsonl` files.
- **`acef-manifest.json`** contains the envelope (metadata, subjects, entities, profiles, audit_trail) plus a `record_files[]` index that references records by path and count. It does NOT contain record payloads.
- **Path normalization:** All paths in the manifest and hashes MUST use forward slashes (`/`), be relative to the bundle root, use UTF-8 NFC normalization, and not contain `.` or `..` segments.

**Archive format:** When transmitted, the bundle MUST be packed as `.acef.tar.gz` (gzip-compressed tar). Tools MUST be able to consume both unpacked directories and `.acef.tar.gz` archives.

### 3.1.3 Integrity Model

The integrity model avoids circular dependencies by defining a strict, non-overlapping hash domain. The manifest contains NO integrity fields — all integrity verification lives in `hashes/` and `signatures/`, which are outside the hash domain.

**Hash domain (files that ARE hashed):**
- `acef-manifest.json` (hashed as-is; contains no hash of itself)
- Everything in `records/`
- Everything in `artifacts/`

**Outside hash domain (files that are NOT hashed):**
- `hashes/content-hashes.json` — contains hashes of everything IN the domain
- `hashes/merkle-tree.json` — contains the Merkle tree over `content-hashes.json` entries
- `signatures/*.jws` — detached signatures over `content-hashes.json`

**Critical design constraint:** The manifest MUST NOT contain any field that references, embeds, or depends on the contents of `hashes/` or `signatures/`. This is what eliminates the circular dependency.

**Canonical serialization rules:**

1. **JSON canonicalization:** All JSON files in the hash domain MUST be serialized using [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785) for deterministic output before hashing. Implementations MUST verify that JSON is valid UTF-8 with NFC normalization and no BOM (U+FEFF).
2. **JSONL canonicalization:** Each line in a `.jsonl` file MUST be independently canonicalized per RFC 8785, followed by a single `\n` (0x0A) byte. The file MUST end with a `\n` after the last record. Empty lines MUST NOT appear. Leading/trailing whitespace on lines (other than the final `\n`) is forbidden. No BOM.
3. **Hash algorithm:** SHA-256 (MUST). `content-hashes.json` is a JSON object (RFC 8785 canonicalized) mapping relative paths (lexicographically sorted) to lowercase hex-encoded SHA-256 hashes:
   ```json
   {
     "acef-manifest.json": "e3b0c44298fc1c...",
     "artifacts/eval-report-v3.pdf": "f6e5d4c3b2a1...",
     "records/risk_register.jsonl": "a1b2c3d4e5f6..."
   }
   ```
4. **Merkle tree:** `merkle-tree.json` is built from the sorted entries of `content-hashes.json`:
   - **Leaf nodes:** Each `(path, hash)` pair produces a leaf: `SHA-256(path || 0x00 || hash)` where `path` is UTF-8 bytes and `hash` is the lowercase hex string as UTF-8 bytes.
   - **Inner nodes:** `SHA-256(left_hash || right_hash)` where both are raw 32-byte digests.
   - **Odd leaf:** If a level has an odd number of nodes, the last node is promoted unchanged (NOT duplicated).
   - **Root:** The single remaining hash is the Merkle root.
   - **JSON shape:** `{"leaves": [{"path": "...", "hash": "..."}], "root": "hex-encoded-root-hash"}`
5. **Signatures:** Detached JWS (RFC 7515) signatures over the raw bytes of `content-hashes.json` (after RFC 8785 canonicalization). The JWS header MUST include `alg` (RS256 or ES256 only), `kid` (key identifier), and `x5c` (certificate chain) or `jwk` (public key). Other algorithms MUST be rejected (error ACEF-013). **Unsigned bundles are valid ACEF bundles** — signatures are OPTIONAL. An unsigned bundle passes integrity verification (steps a–d) but skips step e. Conformance does not require signatures, but profiles MAY require them via DSL rules.

**Signature trust model (normative):**
   - If `x5c` is present, verifiers MUST validate the full certificate chain against a locally configured set of trust anchors. Certificate expiry is checked against the `metadata.timestamp` value from the manifest, NOT wall-clock time (this ensures reproducible verification). Revocation checking (CRL/OCSP) is RECOMMENDED but not REQUIRED for v1.
   - If `jwk` is present without `x5c`, the signature proves data integrity but not organizational identity. Verifiers SHOULD treat such signatures as `trust_level: self-attested`.
   - If both `x5c` and `jwk` are present, `x5c` takes precedence for trust evaluation.
   - If neither `x5c` nor `jwk` is present, the signature is invalid (error ACEF-012).
6. **Verification procedure:**
   a. Verify `acef-manifest.json` is valid JSON and conforms to the ACEF Core manifest schema. If not, FATAL (ACEF-002).
   b. Canonicalize (RFC 8785) and hash (SHA-256) every file in the hash domain.
   c. Compare against entries in `content-hashes.json`. Any mismatch is FATAL (ACEF-010). Any file in the domain missing from `content-hashes.json`, or any entry in `content-hashes.json` with no corresponding file, is FATAL (ACEF-014).
   d. Recompute the Merkle tree from `content-hashes.json` using the leaf/inner-node rules above. Compare root against `merkle-tree.json`. Mismatch is FATAL (ACEF-011).
   e. Verify each signature in `signatures/` against the raw bytes of `content-hashes.json`. Invalid signature is FATAL (ACEF-012).
   f. Validators MUST report ALL errors encountered within each validation phase (schema, integrity, evaluation), consistent with the error taxonomy severity rules (Section 3.6). The final result is valid only if zero fatal errors were found.

**Archive canonicalization (for `.acef.tar.gz`):**
- Files MUST be added in lexicographic order by path.
- Timestamps MUST be set to the `metadata.timestamp` value from the manifest (Unix epoch seconds, UTC).
- Owner/group MUST be set to `0/0`. Permissions MUST be `0644` for files, `0755` for directories.
- No symlinks, hard links, or extended attributes.
- Compression: gzip compression level 6 (MUST). The gzip header MUST set mtime to 0 and OS to 0xFF (unknown). This ensures byte-identical archives across runtimes.
- Note: Byte-identical archives are REQUIRED for conformance testing. If an implementation cannot produce identical gzip output, it MUST distribute unpacked directories for conformance verification and MAY use any gzip settings for transport.

### 3.1.4 Record Schema Architecture

Every evidence record in `records/` consists of two parts, each validated by a separate schema:

1. **Common record envelope** — identical structure for all record types. Validated by `acef-conventions/v{major}/record-envelope.schema.json`:
   ```json
   {
     "record_id": "urn:acef:rec:...",
     "record_type": "risk_register",
     "provisions_addressed": ["article-9.1"],
     "timestamp": "2026-03-17T00:00:00Z",
     "lifecycle_phase": "deployment",
     "collector": {"name": "acme-tool", "version": "1.0"},
     "obligation_role": "provider",
     "confidentiality": "public",
     "redaction_method": null,
     "access_policy": null,
     "trust_level": "self-attested",
     "entity_refs": {
       "subject_refs": ["urn:acef:sub:..."],
       "component_refs": [],
       "dataset_refs": [],
       "actor_refs": []
     },
     "retention": {"min_retention_days": 3650, "legal_basis": "eu-ai-act-2024:article-11"},
     "payload": { ... }
   }
   ```

2. **Payload schema** — specific to the `record_type`. Validated by `acef-conventions/v{major}/{record_type}.schema.json`. Only the `payload` object is validated against this schema.

**v1 record types (frozen for v1 conformance):**

| Record Type | Status | Description |
|---|---|---|
| `risk_register` | **v1 mandatory** | Risk identification and assessment |
| `risk_treatment` | **v1 mandatory** | Mitigation/control measures |
| `dataset_card` | **v1 mandatory** | Dataset documentation |
| `data_provenance` | **v1 mandatory** | Dataset lineage and acquisition |
| `evaluation_report` | **v1 mandatory** | Test results and benchmarks |
| `event_log` | v1 optional | Automatic system event records |
| `human_oversight_action` | v1 optional | Override, stop, verification events |
| `transparency_disclosure` | v1 optional | Public-facing documentation |
| `transparency_marking` | v1 optional | Provider-side content marking |
| `disclosure_labeling` | v1 optional | Deployer-side disclosure events |
| `copyright_rights_reservation` | v1 optional | TDM opt-out compliance |
| `license_record` | v1 optional | Content licensing agreements |
| `incident_report` | v1 optional | Safety/security incidents |
| `governance_policy` | v1 optional | Organizational governance |
| `conformity_declaration` | v1 optional | Formal compliance declarations |
| `evidence_gap` | v1 optional | Explicit acknowledgment of missing evidence |

**Section 2 artifact names** (e.g., `risk_management_plan`, `management_review`, `post_market_monitoring_plan`, `marking_standards_compliance`, `interaction_disclosure`, `biometric_disclosure`) are **payload field names or attachment types within the 16 core record types**, NOT separate record types. For example, `management_review` is a payload variant within `risk_register` (with `payload.review_type: "management_review"`). The regulation mapping templates declare which payload fields and attachments are required.

**Payload-variant registry (normative):** Each record-type payload schema in `acef-conventions/v{major}/` MUST include a machine-readable `variant_discriminator` definition that maps Section 2 artifact names to their parent record type, discriminator field, and discriminator value:

```json
// acef-conventions/v1/variant-registry.json
{
  "variants": [
    {"artifact_name": "management_review", "record_type": "risk_register", "discriminator_field": "/payload/review_type", "discriminator_value": "management_review"},
    {"artifact_name": "post_market_monitoring_plan", "record_type": "risk_register", "discriminator_field": "/payload/review_type", "discriminator_value": "post_market_monitoring_plan"},
    {"artifact_name": "risk_testing_log", "record_type": "risk_treatment", "discriminator_field": "/payload/treatment_subtype", "discriminator_value": "testing_log"},
    {"artifact_name": "marking_standards_compliance", "record_type": "transparency_marking", "discriminator_field": "/payload/marking_subtype", "discriminator_value": "standards_compliance"},
    {"artifact_name": "interaction_disclosure", "record_type": "disclosure_labeling", "discriminator_field": "/payload/disclosure_subtype", "discriminator_value": "interaction"},
    {"artifact_name": "biometric_disclosure", "record_type": "disclosure_labeling", "discriminator_field": "/payload/disclosure_subtype", "discriminator_value": "biometric"},
    {"artifact_name": "logging_spec", "record_type": "event_log", "discriminator_field": "/payload/event_type", "discriminator_value": "logging_spec"},
    {"artifact_name": "gpai_annex_xi_model_doc", "record_type": "evaluation_report", "discriminator_field": "/payload/variant", "discriminator_value": "gpai_annex_xi_model_doc"},
    {"artifact_name": "ai_use_case_inventory_entry", "record_type": "governance_policy", "discriminator_field": "/payload/variant", "discriminator_value": "ai_use_case_inventory_entry"},
    {"artifact_name": "mark_detectability_test", "record_type": "evaluation_report", "discriminator_field": "/payload/variant", "discriminator_value": "mark_detectability_test"},
    {"artifact_name": "training_competency_record", "record_type": "governance_policy", "discriminator_field": "/payload/variant", "discriminator_value": "training_competency_record"},
    {"artifact_name": "publication_evidence", "record_type": "transparency_disclosure", "discriminator_field": "/payload/variant", "discriminator_value": "publication_evidence"}
  ]
}
```

This registry enables template authors to use `exists_where` rules with well-known discriminator paths, and SDK implementations to validate that variant names in templates resolve to real record types and payload fields.

### 3.1.5 Normative Minimum Payload Schemas for High-Impact Record Types

While most payload schemas are defined in the schema registry and evolve independently, the following record types have **normative minimum required fields** in v1 because regulators treat them as structured, testable evidence rather than narrative attachments.

#### `event_log` — Minimum Required Payload Fields

EU AI Act Art. 12 requires automatic logging through the system lifecycle; Art. 19 requires at least 6-month retention of provider-controlled logs. China CAC labeling measures require 6-month log retention for unlabeled-by-request outputs. Logs with unspecified payloads fail audit because presence alone is insufficient — traceability requires structured fields.

```json
{
  "event_type": "inference | training | evaluation | deployment | override | error | marking | disclosure",
  "correlation_id": "string (links related events across log entries and to human_oversight_action records)",
  "inputs_commitment": {"hash_alg": "sha-256", "hash": "hex-string (hash of input data, avoids storing raw PII)"},
  "outputs_commitment": {"hash_alg": "sha-256", "hash": "hex-string (hash of output data)"},
  "retention_start_event": "first_use | first_deployment | record_creation | custom (ISO 8601 date)",
  "session_id": "string (optional — links to deployer session context)",
  "actor_ref": "urn:acef:act:... (optional — who triggered the event)",
  "label_exception": "boolean (optional — true if explicit label was omitted by user request, triggering CAC 6-month retention)"
}
```

The `retention_start_event` field resolves ambiguity in computing retention windows. `inputs_commitment` and `outputs_commitment` use hash commitments to enable traceability without storing raw personal data, consistent with GDPR interplay requirements.

#### `event_log` payload variant: `logging_spec`

A `logging_spec` variant describes **what** a system logs and **why**, enabling deployers to interpret logs and auditors to verify completeness against Art. 12 requirements.

```json
{
  "event_type": "logging_spec",
  "logged_event_types": ["inference", "override", "error", "marking"],
  "log_fields_documented": ["event_type", "correlation_id", "inputs_commitment", "outputs_commitment", "timestamp"],
  "traceability_rationale": "Logs enable identification of risk situations per Art. 12(1) and facilitate post-market monitoring per Art. 9(4)",
  "retention_policy_summary": {"min_days": 180, "start_event": "first_deployment", "legal_basis": "eu-ai-act-2024:article-19"}
}
```

#### `transparency_marking` — Minimum Required Payload Fields

EU AI Act Art. 50 requires machine-readable, detectable marking. The EU Code of Practice emphasizes layered marking (secured metadata + watermarking). China CAC measures require explicit and implicit labels with specific metadata fields.

```json
{
  "modality": "text | image | audio | video | multimodal",
  "marking_scheme_id": "string (e.g., 'c2pa-content-credentials', 'cn-cac-implicit-label-2025')",
  "scheme_version": "string (e.g., '2.3')",
  "metadata_container": "string (e.g., 'xmp/c2pa-manifest-store', 'exif', 'id3', 'file-header')",
  "watermark_applied": "boolean",
  "watermark_family": "string (optional — e.g., 'spectral_embedding', 'robust-imperceptible')",
  "verification_method_ref": "string (optional — pointer to verification tool or API artifact)",
  "marking_parameters_ref": "string (optional — pointer to detailed marking config artifact)",
  "jurisdiction": "string (optional — e.g., 'EU', 'CN' — enables jurisdiction-specific marking validation)",
  "label_exception": {
    "applied": "boolean (true if explicit label omitted, e.g., by user request under CAC rules)",
    "reason": "string (e.g., 'user_requested_no_label')",
    "log_retention_triggered": "boolean (true if exception triggers additional retention obligations)"
  }
}
```

The `marking_scheme_id` and `scheme_version` enable testable verification — auditors can validate that the declared scheme was actually applied to outputs. The `label_exception` block supports China CAC's "no explicit label by request" path and its associated 6-month retention trigger.

#### `disclosure_labeling` — Minimum Required Payload Fields

```json
{
  "disclosure_subtype": "deepfake | public_interest_text | interaction | biometric | emotion_recognition",
  "label_type": "string (e.g., 'deepfake_disclosure', 'ai_interaction_notice')",
  "presentation": "string (e.g., 'visible_icon_plus_text', 'audio_cue', 'text_superscript')",
  "locale": "string (BCP 47 language tag, e.g., 'en-US', 'zh-CN')",
  "disclosure_text": "string (the actual disclosure message shown to users)",
  "first_exposure_timestamp": "ISO 8601 (when the disclosure was first shown)",
  "accessibility_standard_refs": ["string (e.g., 'WCAG-2.1-AA', 'EN-301-549')"],
  "usability_test_evidence_ref": "string (optional — pointer to usability test artifact)"
}
```

The `locale` and `accessibility_standard_refs` fields address EU AI Act requirements for clear, distinguishable information and accessibility compliance.

#### `evaluation_report` payload variant: `gpai_annex_xi_model_doc`

Annex XI requires structured technical documentation for GPAI models including training data characteristics, compute resources, and energy consumption. If represented only as PDFs, conformance templates cannot reliably check for required elements.

```json
{
  "variant": "gpai_annex_xi_model_doc",
  "model_description": {
    "release_date": "ISO 8601",
    "architecture": "string (e.g., 'decoder-only transformer')",
    "parameter_count": "integer",
    "modalities": ["string"],
    "context_length": "integer (optional)",
    "license": "string"
  },
  "training_data_summary": {
    "content_categories": ["string (e.g., 'web', 'books', 'licensed_news', 'synthetic')"],
    "acquisition_channels": ["string (e.g., 'public_web_crawl', 'licensed_feeds', 'user_generated')"],
    "geographic_scope": ["string (optional — e.g., 'global', 'EU', 'US')"],
    "languages": ["string (optional — BCP 47 tags)"],
    "processing_steps": ["string (e.g., 'deduplication', 'toxicity_filtering', 'PII_removal')"],
    "known_bias_mitigations": ["string"],
    "quantitative_metrics": {"total_tokens": "integer (optional)", "total_size_gb": "number (optional)"}
  },
  "compute_energy": {
    "compute_resources": {
      "hardware_description": "string (e.g., 'A100-class GPUs')",
      "training_flops_estimate": "string (scientific notation, e.g., '1.2e25')",
      "training_duration_hours": "number (optional)"
    },
    "energy_consumption": {
      "kwh_estimate": "number",
      "estimation_method": "measured | modeled | power_draw_telemetry",
      "carbon_intensity_gco2eq_per_kwh": "number (optional)",
      "scope": "training_only | training_and_inference | full_lifecycle",
      "uncertainty_range": "string (optional — e.g., '±15%')"
    }
  },
  "evaluation_summary": {
    "red_teaming_performed": "boolean",
    "key_metrics": {"metric_name": "number"},
    "evaluation_datasets": ["string"],
    "independent_evaluator": "string (optional)"
  },
  "publication_evidence": {
    "summary_published": "boolean",
    "publication_url": "string (optional)",
    "publication_date": "ISO 8601 (optional)",
    "publication_content_hash": "string (SHA-256 of the published summary, for verifiability)"
  }
}
```

#### `governance_policy` payload variant: `ai_use_case_inventory_entry`

OMB M-24-10 requires US federal agencies to maintain annual AI use-case inventories with rights/safety classification. Without a standardized payload, agencies produce incompatible attachments.

```json
{
  "variant": "ai_use_case_inventory_entry",
  "system_purpose": "string (plain-language description of what the AI does)",
  "decision_influence": "autonomous | advisory | augmentative | none",
  "rights_safety_impact": "rights_impacting | safety_impacting | both | neither",
  "impact_classification_rationale": "string",
  "responsible_owner": "string (or actor_ref URN)",
  "caio_designation": "string (Chief AI Officer name/role, per M-24-10)",
  "governance_board_ref": "string (optional — pointer to governance board charter artifact)",
  "model_version": "string",
  "deployment_context": "string (e.g., 'production', 'pilot', 'development')",
  "last_review_date": "ISO 8601",
  "inventory_reporting_period": "string (e.g., '2026-FY')"
}
```

### 3.1.2 Minimal JSON Shape (acef-manifest.json)

The manifest file captures the full envelope structure. Evidence record payloads live in the `records/` directory, not in the manifest — the manifest references them by path and count.

```json
{
  "metadata": {
    "package_id": "urn:acef:pkg:550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2026-03-17T00:00:00Z",
    "producer": {"name": "acme-compliance-tool", "version": "1.2.0"},
    "prior_package_ref": null,
    "retention_policy": {
      "min_retention_days": 3650,
      "personal_data_interplay": "GDPR Art. 17 erasure requests evaluated per-record"
    }
  },
  "versioning": {
    "core_version": "1.0.0",
    "profiles_version": "1.0.0"
  },
  "subjects": [
    {
      "subject_id": "urn:acef:sub:a1b2c3d4-...",
      "subject_type": "ai_system",
      "name": "Acme RAG Assistant v2",
      "version": "2.1.0",
      "provider": "Acme AI Corp",
      "risk_classification": "high-risk",
      "modalities": ["text"],
      "lifecycle_phase": "deployment",
      "lifecycle_timeline": [
        {"phase": "development", "start_date": "2025-01-15", "end_date": "2025-11-01"},
        {"phase": "testing", "start_date": "2025-11-01", "end_date": "2026-01-15"},
        {"phase": "deployment", "start_date": "2026-01-15", "end_date": null}
      ]
    }
  ],
  "entities": {
    "components": [
      {"component_id": "urn:acef:cmp:...", "name": "Vector Retriever", "type": "retriever", "version": "3.1.0", "subject_refs": ["urn:acef:sub:a1b2c3d4-..."], "provider": "Acme AI Corp"}
    ],
    "datasets": [
      {"dataset_id": "urn:acef:dat:...", "name": "CommonCrawl-2025-Q3", "version": "2025.3", "source_type": "licensed", "modality": "text", "size": {"records": 3200000000, "size_gb": 2400}, "subject_refs": ["urn:acef:sub:a1b2c3d4-..."]}
    ],
    "actors": [
      {"actor_id": "urn:acef:act:...", "role": "provider", "name": "Jane Smith", "organization": "Acme AI Corp"}
    ],
    "relationships": [
      {"source_ref": "urn:acef:sub:a1b2c3d4-...", "target_ref": "urn:acef:cmp:...", "relationship_type": "calls", "description": "System calls retriever for context augmentation"}
    ]
  },
  "profiles": [
    {
      "profile_id": "eu-ai-act-2024",
      "template_version": "1.0.0",
      "applicable_provisions": ["article-9", "article-10", "article-12", "article-50.2"]
    }
  ],
  "record_files": [
    {"path": "records/risk_register.jsonl", "record_type": "risk_register", "count": 12},
    {"path": "records/event_log/event_log.0001.jsonl", "record_type": "event_log", "count": 100000},
    {"path": "records/event_log/event_log.0002.jsonl", "record_type": "event_log", "count": 100000},
    {"path": "records/transparency_marking.jsonl", "record_type": "transparency_marking", "count": 3},
    {"path": "records/evidence_gap.jsonl", "record_type": "evidence_gap", "count": 2}
  ],
  "audit_trail": [
    {"event_type": "created", "timestamp": "2026-03-17T00:00:00Z", "actor_ref": "urn:acef:act:...", "description": "Initial package creation"}
  ]
}
```

**Key structural decisions in this shape:**

- **`record_files`** in the manifest references evidence by file path and count — payloads are NOT embedded in the manifest. This enables partial verification and streaming ingestion of large log files.
- **No `provision_status` in the Evidence Bundle.** Assessment results (pass/fail, provision coverage) belong in the separate ACEF Assessment Bundle (Section 3.7). The Evidence Bundle is a neutral container of proof.
- **No integrity fields in the manifest.** The manifest contains NO hash of itself or any reference to `hashes/` or `signatures/`. This eliminates all circular dependencies. See Section 3.1.3.
- **Three-module versioning.** Evidence Bundles declare `versioning.core_version` and `profiles_version`. Assessment Bundles declare their own `versioning.core_version` and `assessment_version`. The compatibility matrix in Section 6.2 defines valid combinations.
- **All identifiers use URN format** (`urn:acef:{type}:{uuid}`) for unambiguous cross-referencing within and across packages.
- **`subject_refs` is always plural** (array) — components and datasets can belong to multiple subjects (many-to-many).
- **All record files use `.jsonl`** — even files with few records. The format rule is: JSONL for all record files, sharding for files exceeding 256 MB.

### 3.2 Semantic Conventions (Regulation-Specific Record Types)

Like OTLP's semantic conventions, ACEF defines **record type schemas** that evolve independently of the core envelope. Each regulation mapping template declares which record types it expects.

**Core record types (cross-regulation):**

| Record Type | Description | Used By |
|---|---|---|
| `risk_register` | Risk identification and assessment entries | EU AI Act Art. 9, NIST MAP/MEASURE |
| `risk_treatment` | Mitigation/control measures and effectiveness evidence | EU AI Act Art. 9, NIST MANAGE |
| `dataset_card` | Training/validation/test dataset documentation | EU AI Act Art. 10, NIST MAP |
| `data_provenance` | Dataset lineage, acquisition records, and chain of custody | EU AI Act Art. 10, GPAI, US Copyright, UK |
| `evaluation_report` | Test results, benchmarks, performance metrics | EU AI Act Art. 15, NIST MEASURE |
| `event_log` | Automatic system event records (JSON Lines for high volume) | EU AI Act Art. 12, China CAC |
| `human_oversight_action` | Oversight events: override, stop, disregard, manual verification, escalation | EU AI Act Art. 14, NIST GOVERN |
| `transparency_disclosure` | Public-facing documentation and instructions for use | EU AI Act Art. 13, GPAI, China CAC, UK |
| `transparency_marking` | **Provider-side** technical marking of AI-generated content: secure metadata, watermarks, digital signatures, detection methods | EU AI Act Art. 50, EU Labelling CoP, China CAC |
| `disclosure_labeling` | **Deployer-side** disclosure events: deepfake labels, public-interest text disclaimers, layered UI disclosures, icon placement | EU AI Act Art. 50, EU Labelling CoP, China CAC |
| `copyright_rights_reservation` | Evidence of TDM opt-out compliance, rights reservation signal detection (robots.txt, TDMRep, HTTP headers), removal/exclusion processes | GPAI Art. 53, US Copyright, UK |
| `license_record` | Content licensing agreements | GPAI Copyright, US Copyright, UK |
| `incident_report` | Safety/security incident documentation, notification receipts, regulatory communication timestamps | GPAI Systemic Risk, NIST MANAGE |
| `governance_policy` | Organizational AI governance documentation | NIST GOVERN, ISO 42001 |
| `conformity_declaration` | Formal compliance declarations | EU AI Act Art. 47–48 |
| `evidence_gap` | Explicit acknowledgment that required evidence is not yet present, with reason and remediation plan | All regulations |

**Record type changes from v0.1:**
- `content_provenance` split into `transparency_marking` (provider) and `disclosure_labeling` (deployer) — reflecting the EU AI Act's distinct obligations for each role under Articles 16, 26, and 50.
- `copyright_compliance` renamed to `copyright_rights_reservation` — more specific, aligns with EU DSM Directive Art. 4(3) and W3C TDMRep terminology.
- `oversight_record` renamed to `human_oversight_action` — emphasizes that oversight is an operational event, not just a static design feature.
- `evidence_gap` added — auditors and regulators need to distinguish "evidence is missing because we forgot" from "evidence is missing because the system hasn't reached that lifecycle phase" or "evidence is confidential and hash-committed."

### 3.3 Record Type Schema Registry

Each `record_type` has a corresponding JSON Schema that validates the `payload` field. Schemas are stored in a versioned registry and discovered by convention:

```
acef-conventions/
├── v1/
│   ├── manifest.schema.json
│   ├── record-envelope.schema.json
│   ├── assessment-bundle.schema.json
│   ├── variant-registry.json
│   ├── risk_register.schema.json
│   ├── risk_treatment.schema.json
│   ├── dataset_card.schema.json
│   ├── data_provenance.schema.json
│   ├── evaluation_report.schema.json
│   ├── event_log.schema.json
│   ├── human_oversight_action.schema.json
│   ├── transparency_disclosure.schema.json
│   ├── transparency_marking.schema.json
│   ├── disclosure_labeling.schema.json
│   ├── copyright_rights_reservation.schema.json
│   ├── license_record.schema.json
│   ├── incident_report.schema.json
│   ├── governance_policy.schema.json
│   ├── conformity_declaration.schema.json
│   └── evidence_gap.schema.json
└── extensions/
    └── custom-record-type.schema.json
```

**Registry rules:**

- Each schema file MUST be a valid JSON Schema (draft 2020-12).
- Schema filenames MUST match the `record_type` value exactly.
- Schemas are versioned alongside the semantic conventions layer (semver, medium pace).
- Validators discover schemas by resolving `acef-conventions/v{major}/[record_type].schema.json`.
- Custom record types MUST use a namespaced prefix (e.g., `x-myorg/custom_audit`) and place schemas in `extensions/`.
- The `versioning.profiles_version` in the manifest determines which convention version to validate against.

### 3.4 Regulation Mapping Templates

Each template is a separate JSON file that declares what evidence is required for a given regulatory profile. Templates are versioned, date-scoped, and include machine-executable evaluation rules.

```json
{
  "template_id": "eu-ai-act-2024",
  "template_name": "EU Artificial Intelligence Act",
  "version": "1.0.0",
  "jurisdiction": "EU",
  "source_legislation": "Regulation (EU) 2024/1689",
  "instrument_type": "law",
  "legal_force": "binding",
  "instrument_status": "final",
  "default_effective_date": "2026-08-02",
  "superseded_by": null,
  "applicable_system_types": ["high-risk", "gpai", "gpai-systemic", "limited-risk"],
  "provisions": [
    {
      "provision_id": "article-9",
      "provision_name": "Risk Management System",
      "normative_text_ref": "EU AI Act Art. 9(1)–(9)",
      "description": "Continuous, iterative risk management across lifecycle",
      "effective_date": "2026-08-02",
      "applicable_to": ["high-risk"],
      "sub_provisions": [
        {
          "provision_id": "article-9.1",
          "normative_text_ref": "EU AI Act Art. 9(1)",
          "description": "Establish, implement, document, and maintain a risk management system"
        },
        {
          "provision_id": "article-9.2.a",
          "normative_text_ref": "EU AI Act Art. 9(2)(a)",
          "description": "Identification and analysis of known and reasonably foreseeable risks"
        }
      ],
      "required_evidence_types": [
        "risk_register",
        "risk_treatment"
      ],
      "minimum_evidence_count": {
        "risk_register": 1,
        "risk_treatment": 1
      },
      "evidence_freshness_max_days": 365,
      "retention_years": 10,
      "evaluation": [
        {
          "rule_id": "art9-risk-register",
          "rule": "has_record_type",
          "params": {"type": "risk_register", "min_count": 1},
          "severity": "fail",
          "message": "At least one risk_register record is required for Art. 9 compliance"
        },
        {
          "rule_id": "art9-freshness",
          "rule": "evidence_freshness",
          "params": {"max_days": 365, "reference_date": "validation_time"},
          "severity": "warning",
          "message": "Risk management evidence older than 1 year may not satisfy continuous lifecycle requirement"
        },
        {
          "rule_id": "art9-risk-treatment",
          "rule": "has_record_type",
          "params": {"type": "risk_treatment", "min_count": 1},
          "severity": "fail",
          "message": "Risk treatments must be documented for each identified risk"
        },
        {
          "rule_id": "art9-management-review",
          "rule": "exists_where",
          "params": {"record_type": "risk_register", "field": "/payload/review_type", "op": "eq", "value": "management_review", "min_count": 1},
          "severity": "fail",
          "message": "At least one management review record is required for Art. 9"
        },
        {
          "rule_id": "art9-post-market-monitoring",
          "rule": "exists_where",
          "params": {"record_type": "risk_register", "field": "/payload/review_type", "op": "eq", "value": "post_market_monitoring_plan", "min_count": 1},
          "severity": "warning",
          "message": "Post-market monitoring plan should be documented"
        }
      ],
      "tiered_requirements": null
    },
    {
      "provision_id": "article-53",
      "provision_name": "GPAI Model Obligations",
      "normative_text_ref": "EU AI Act Art. 53(1)",
      "description": "Technical documentation, copyright policy, training data summary",
      "effective_date": "2025-08-02",
      "applicable_to": ["gpai", "gpai-systemic"],
      "required_evidence_types": ["data_provenance", "copyright_rights_reservation", "transparency_disclosure"],
      "evaluation": [
        {
          "rule_id": "art53-data-provenance",
          "rule": "has_record_type",
          "params": {"type": "data_provenance", "min_count": 1},
          "severity": "fail",
          "message": "GPAI models must document training data provenance"
        }
      ],
      "tiered_requirements": null
    },
    {
      "provision_id": "article-50.2",
      "provision_name": "Transparency — Synthetic Content Marking",
      "normative_text_ref": "EU AI Act Art. 50(2)",
      "description": "Providers must ensure synthetic content is marked in machine-readable format",
      "effective_date": "2026-08-02",
      "applicable_to": ["high-risk", "gpai", "gpai-systemic", "limited-risk"],
      "required_evidence_types": [
        "transparency_marking"
      ],
      "minimum_evidence_count": {
        "transparency_marking": 1
      },
      "evaluation": [
        {
          "rule_id": "art50-marking-exists",
          "rule": "has_record_type",
          "params": {"type": "transparency_marking", "min_count": 1},
          "severity": "fail",
          "message": "At least one transparency_marking record required for Art. 50(2)"
        },
        {
          "rule_id": "art50-marking-technique",
          "rule": "field_present",
          "params": {"record_type": "transparency_marking", "field": "/payload/marking_technique"},
          "severity": "fail",
          "message": "Marking technique must be specified"
        }
      ],
      "tiered_requirements": null
    }
  ],
  "test_vectors": [
    "test-vectors/eu-ai-act/article-9-minimal-pass.acef/",
    "test-vectors/eu-ai-act/article-9-minimal-fail.acef/",
    "test-vectors/eu-ai-act/article-9-variant-management-review-pass.acef/",
    "test-vectors/eu-ai-act/article-12-logging-spec-pass.acef/",
    "test-vectors/eu-ai-act/article-12-retention-fail.acef/",
    "test-vectors/eu-ai-act/article-50-marking-pass.acef/",
    "test-vectors/eu-ai-act/article-50-marking-no-scheme-id-fail.acef/",
    "test-vectors/eu-ai-act/article-53-annex-xi-pass.acef/",
    "test-vectors/eu-ai-act/article-53-annex-xi-missing-energy-fail.acef/",
    "test-vectors/eu-ai-act/multi-subject-per-subject-eval.acef/"
  ]
}
```

**Template enhancements from v0.1:**
- **`normative_text_ref`** links each provision to the exact legal text, enabling traceability from evidence to law.
- **`evaluation`** rules provide machine-executable pass/fail/warning validators, so compliance tools can assess package completeness programmatically.
- **`effective_date` and `superseded_by`** support date-scoping — critical because the EU AI Act anticipates delegated acts that can amend Annex documentation requirements, shifting evidence expectations over time.
- **`sub_provisions`** support dotted notation (e.g., "article-9.2.a") for sub-requirement granularity.
- **`tiered_requirements`** support the GPAI Code of Practice's tiered compliance model (Tier 1/2/3 for transparency).
- **`test_vectors`** provide sample ACEF packages that MUST pass/fail validation, enabling conformance testing of tools.

**Planned regulation mapping templates (v1.0):**

| Template ID | Jurisdiction | Instrument Type | Legal Force | Effective Date | Status |
|---|---|---|---|---|---|
| `eu-ai-act-2024` | EU | `law` | `binding` | Per-provision (GPAI: 2025-08-02, rest: 2026-08-02) | Priority — most implementation-specific |
| `eu-gpai-code-of-practice-2025` | EU | `code_of_practice` | `voluntary` | 2025-08-02 | Priority — transparency + copyright chapters |
| `eu-labelling-code-of-practice-2026` | EU | `code_of_practice` | `voluntary` | 2026-08-02 (expected) | Priority — marking/labelling; instrument_status: `draft` until finalized |
| `nist-ai-rmf-1.0` | US | `standard` | `voluntary` | N/A | Priority — GOVERN/MAP/MEASURE/MANAGE |
| `nist-ai-600-1-gai-profile` | US | `standard` | `voluntary` | N/A | Priority — generative AI additions |
| `us-copyright-office-part3-2025` | US | `guidance` | `advisory` | N/A | Secondary — evidence defensibility, not binding |
| `china-cac-labeling-2025` | China | `law` | `binding` | 2025-09-01 | Secondary — labeling requirements |
| `uk-ai-copyright-guidance-2026` | UK | `parliamentary_report` | `advisory` | TBD | Secondary — anticipated legislation |
| `iso-iec-42001-2023` | International | `standard` | `voluntary` | N/A (certifiable) | Cross-cutting — AI management system |
| `iso-iec-23894-2023` | International | `standard` | `voluntary` | N/A | Cross-cutting — AI risk management |
| `us-omb-m-24-10` | US | `guidance` | `binding` (federal agencies) | 2024-03-28 | Federal AI governance, CAIO, annual inventory |

**Per-template test vectors (required for v1 templates):**

Each v1 regulation mapping template MUST ship with at least one pass and one fail test vector:

| Template | Test Vectors |
|---|---|
| `eu-ai-act-2024` | `test-vectors/eu-ai-act/` — 10 vectors covering Art. 9 (basic + variants), Art. 12 (logging + retention), Art. 50 (marking), Art. 53 (Annex XI), multi-subject |
| `china-cac-labeling-2025` | `test-vectors/china-cac/cac-explicit-implicit-pass.acef/`, `cac-missing-implicit-metadata-fail.acef/`, `cac-label-exception-retention-pass.acef/` |
| `nist-ai-rmf-1.0` | `test-vectors/nist-rmf/govern-map-measure-manage-pass.acef/`, `govern-missing-policy-fail.acef/` |
| `us-omb-m-24-10` | `test-vectors/omb-m24-10/inventory-governance-pass.acef/`, `missing-caio-fail.acef/` |
| `eu-gpai-code-of-practice-2025` | `test-vectors/eu-gpai-cop/transparency-copyright-pass.acef/`, `missing-training-summary-fail.acef/` |

---

### 3.5 Rule DSL Specification

Regulation mapping templates use a formal rule DSL to define evaluation logic. The DSL is intentionally small and declarative — it defines WHAT to check, not HOW to implement the checker.

**Rule structure (normative):**

```json
{
  "rule_id": "art9-risk-register",
  "rule": "has_record_type",
  "params": { ... },
  "severity": "fail",
  "message": "Human-readable explanation",
  "scope": { ... },
  "condition": { ... }
}
```

**Required fields:** `rule_id` (unique within template, referenced in Assessment Bundle results), `rule` (operator name), `params` (operator-specific), `severity` (`fail` | `warning` | `info`), `message`.

**Optional fields:** `scope` (filters which records/subjects are evaluated), `condition` (when the rule applies).

**Built-in operators (v1):**

| Operator | Params | Semantics |
|---|---|---|
| `has_record_type` | `type`: string, `min_count`: int | At least `min_count` records of the given type exist (within scope) |
| `field_present` | `record_type`: string, `field`: JSON Pointer (RFC 6901) | Every record of the given type has a non-null value at the specified path |
| `field_value` | `record_type`: string, `field`: JSON Pointer, `op`: `eq`\|`ne`\|`gt`\|`gte`\|`lt`\|`lte`\|`in`\|`regex`, `value`: any | Field value satisfies the comparison |
| `evidence_freshness` | `max_days`: int, `reference_date`: `validation_time`\|`package_time`\|`obligation_effective_date` | All records within scope have `timestamp` within `max_days` of the reference date |
| `attachment_exists` | `record_type`: string, `media_type`: string (optional) | At least one record of the given type has an attachment (optionally matching the media type) |
| `entity_linked` | `record_type`: string, `entity_type`: `subject`\|`component`\|`dataset`\|`actor` | Every record of the given type has at least one entity ref of the given type |
| `exists_where` | `record_type`: string, `field`: JSON Pointer, `op`: comparison, `value`: any, `min_count`: int | At least `min_count` records exist where the field satisfies the comparison. Used for payload variant requirements. |
| `attachment_kind_exists` | `record_type`: string, `attachment_type`: string, `min_count`: int (default 1) | At least `min_count` records of the given type have an attachment with matching `attachment_type` field |
| `bundle_signed` | `min_signatures`: int (default 1), `required_alg`: string[] (optional) | The Evidence Bundle has at least `min_signatures` valid signatures in `signatures/`, optionally restricted to specific algorithms |
| `record_attested` | `record_type`: string, `min_count`: int (default 1) | At least `min_count` records of the given type have a non-null `attestation` block with a valid JWS signature (v1 restricts attestation to JWS only; C2PA record attestation is deferred to a future profile). Verification: extract the fields listed in `signed_fields`, canonicalize via RFC 8785, verify the detached JWS. |

**Empty-set semantics (normative):** If a rule's scope or `record_type` filter matches zero records:
- **Existential operators** (`has_record_type`, `exists_where`, `attachment_exists`, `attachment_kind_exists`) evaluate to `failed` if `min_count > 0`. These require evidence to exist.
- **Universal operators** (`field_present`, `field_value`, `entity_linked`) evaluate to `passed` (vacuous truth). These assert properties of existing records and are trivially satisfied when no records exist.
- This prevents absent evidence from being silently treated as compliant via existence checks, while avoiding false negatives from universal quantifiers over empty sets.

**Missing-path behavior (normative):** If a JSON Pointer path in `field_present` or `field_value` does not resolve to a value in a record (the path does not exist), the record is treated as if the field is `null`. For `field_present`, this means the record fails the check. For `field_value`, all comparisons against a missing path evaluate to `false` except `ne` (not-equal), which evaluates to `true`.

**Regex dialect (normative):** The `regex` comparison operator uses [ECMA-262 RegExp](https://tc39.es/ecma262/#sec-regexp-regular-expression-objects) syntax (the JavaScript regex standard). Flags are not supported — all matches are case-sensitive and single-line by default. Implementations MUST reject patterns that do not parse as valid ECMA-262 RegExp (error ACEF-045).

**Path syntax:** All `field` parameters use [JSON Pointer (RFC 6901)](https://www.rfc-editor.org/rfc/rfc6901). Example: `/payload/marking_technique` (NOT dotted notation). Paths are evaluated relative to each record object.

**Scope filter (optional):**

```json
"scope": {
  "risk_classifications": ["high-risk"],
  "obligation_roles": ["provider"],
  "lifecycle_phases": ["deployment", "monitoring"],
  "modalities": ["text", "image"]
}
```

If `scope` is present, the rule only applies to records matching ALL scope criteria. If absent, the rule applies to all records.

**Condition (optional):**

```json
"condition": {
  "if_provision_effective": true,
  "if_system_type": ["gpai-systemic"]
}
```

If `condition` is present and evaluates to false (e.g., the provision is not yet effective), the rule is SKIPPED (not failed, not passed — reported as `skipped` in the Assessment Bundle).

**Precedence:** If `required_evidence_types`, `minimum_evidence_count`, and `evaluation` rules exist on the same provision and disagree, the `evaluation` rules take precedence. `required_evidence_types` and `minimum_evidence_count` are syntactic sugar that the reference validator expands into equivalent `has_record_type` rules before evaluation.

**Extension operators:** Vendor-defined operators MUST use the `x-vendorname/operator_name` namespace. Standard ACEF conformance outcomes MUST NOT depend on extension operators — they are informational only.

### 3.6 Error Taxonomy

ACEF defines a normative error taxonomy so that all validators and SDK implementations produce consistent, machine-readable errors. Each error has a unique code, severity, and category.

**Severity levels:**

| Severity | Meaning | Behavior |
|---|---|---|
| `fatal` | Package is structurally invalid; cannot be processed further | Validator MUST report. Validators MUST NOT stop mid-phase — they MUST collect all errors within the current validation phase (schema → integrity → evaluation) before stopping. |
| `error` | Evidence fails a binding regulatory requirement | Validator MUST report; package MAY still be partially processable |
| `warning` | Evidence fails a voluntary or advisory requirement, or is stale | Validator MUST report; package is processable |
| `info` | Informational observation (e.g., extension detected, optional field missing) | Validator MAY report |

**Error categories and codes:**

| Code | Category | Severity | Description |
|---|---|---|---|
| `ACEF-001` | Schema | `fatal` | Incompatible module versions in `versioning` block — validator cannot process |
| `ACEF-002` | Schema | `fatal` | Manifest fails JSON Schema validation |
| `ACEF-003` | Schema | `error` | Unknown `record_type` — no schema in registry |
| `ACEF-004` | Schema | `fatal` | Record payload fails record-type JSON Schema validation |
| `ACEF-010` | Integrity | `fatal` | File hash mismatch (file content does not match `content-hashes.json`) |
| `ACEF-011` | Integrity | `fatal` | Merkle root mismatch |
| `ACEF-012` | Integrity | `fatal` | Invalid or expired signature |
| `ACEF-013` | Integrity | `fatal` | Unsupported JWS algorithm — signature cannot be verified |
| `ACEF-014` | Integrity | `fatal` | Hash index completeness failure: `content-hashes.json` missing, or file in hash domain not listed, or listed file not found |
| `ACEF-020` | Reference | `error` | Dangling `entity_refs` — URN references a nonexistent entity |
| `ACEF-021` | Reference | `error` | Duplicate URNs within the package |
| `ACEF-022` | Reference | `error` | `record_files` entry references a file that does not exist in `records/` |
| `ACEF-023` | Reference | `error` | Attachment path references a file not in `artifacts/` |
| `ACEF-025` | Reference | `error` | Record count mismatch between `record_files[].count` and actual parsed JSONL lines |
| `ACEF-026` | Reference | `error` | Duplicate `record_id` within the package |
| `ACEF-027` | Reference | `warning` | Attachment `hash` field does not match `content-hashes.json` entry for the same path (advisory — `content-hashes.json` is authoritative) |
| `ACEF-030` | Profile | `error` | Unknown `profile_id` — no matching template in registry |
| `ACEF-031` | Profile | `error` | Unknown `template_version` |
| `ACEF-032` | Profile | `info` | Provision not yet effective (`evaluation_instant` < `effective_date`) — rules produce `skipped` outcome |
| `ACEF-033` | Profile | `error` | Incompatible module versions between Evidence Bundle and template |
| `ACEF-040` | Evaluation | `error` | Required evidence type missing (rule severity: `fail`) |
| `ACEF-041` | Evaluation | `warning` | Evidence freshness exceeded |
| `ACEF-042` | Evaluation | `info` | `evidence_gap` acknowledged for provision |
| `ACEF-043` | Evaluation | `error` | Invalid JSON Pointer in rule `field` parameter |
| `ACEF-045` | Evaluation | `error` | Invalid ECMA-262 regex pattern in rule `value` parameter |
| `ACEF-044` | Evaluation | `error` | Duplicate `rule_id` in template — rule IDs must be unique for Assessment Bundle result keys |
| `ACEF-050` | Format | `fatal` | Malformed JSONL line (not valid JSON) |
| `ACEF-051` | Format | `fatal` | JSON not canonicalized per RFC 8785 (during integrity verification) |
| `ACEF-052` | Format | `error` | Path contains `..` segments or non-UTF-8-NFC characters |
| `ACEF-053` | Format | `error` | Vendor extension field (`x-*`) affects conformance outcome (forbidden) |
| `ACEF-060` | Merge | `warning` | Conflicting records from multiple packages for same entity |

### 3.7 Validation Result Schema (Assessment Bundle)

Validation results are captured in an **ACEF Assessment Bundle** — a separate, signed JSON artifact that references the Evidence Bundle by content hash. This is produced by the reference validator or commercial tools.

**Format:** The Assessment Bundle is a single canonical JSON file (`.acef-assessment.json`), NOT a directory bundle. Signing procedure: set `"integrity": null` in the JSON, canonicalize via RFC 8785, compute the JWS signature over those bytes, then populate the `integrity` block with the signature. Verifiers reverse this by setting `"integrity": null`, re-canonicalizing, and verifying the signature. The `integrity` block is NEVER removed from the JSON — it is always present as either `null` (pre-sign) or populated (post-sign).

**The Assessment Bundle is NOT part of the Evidence Bundle.** It is a separate, independently distributable artifact.

```json
{
  "versioning": {
    "core_version": "1.0.0",
    "assessment_version": "1.0.0"
  },
  "assessment_id": "urn:acef:asx:...",
  "timestamp": "2026-03-17T12:00:00Z",
  "evaluation_instant": "2026-03-17T12:00:00Z",
  "assessor": {
    "name": "acef-validator",
    "version": "1.0.0",
    "organization": "AI Commons"
  },
  "evidence_bundle_ref": {
    "content_hash": "sha256:abc123...",
    "package_id": "urn:acef:pkg:..."
  },
  "profiles_evaluated": ["eu-ai-act-2024:1.0.0"],
  "template_digests": {
    "eu-ai-act-2024:1.0.0": "sha256:def456..."
  },
  "results": [
    {
      "rule_id": "art9-risk-register",
      "provision_id": "article-9",
      "profile_id": "eu-ai-act-2024",
      "rule_severity": "fail",
      "outcome": "passed",
      "message": null,
      "evidence_refs": ["urn:acef:rec:..."],
      "subject_scope": ["urn:acef:sub:..."]
    },
    {
      "rule_id": "art9-freshness",
      "provision_id": "article-9",
      "profile_id": "eu-ai-act-2024",
      "rule_severity": "warning",
      "outcome": "failed",
      "message": "Risk management evidence is 400 days old (threshold: 365)",
      "evidence_refs": ["urn:acef:rec:..."],
      "subject_scope": ["urn:acef:sub:..."]
    }
  ],
  "provision_summary": [
    {
      "provision_id": "article-9",
      "profile_id": "eu-ai-act-2024",
      "provision_outcome": "satisfied",
      "subject_scope": ["urn:acef:sub:..."],
      "fail_count": 0,
      "warning_count": 1,
      "skipped_count": 0,
      "evidence_refs": ["urn:acef:rec:..."]
    }
  ],
  "structural_errors": [],
  "integrity": {
    "signature": {
      "method": "jws",
      "signer": "urn:acef:act:...",
      "value": "eyJhbGciOiJSUzI1NiJ9..."
    }
  }
}
```

**Vocabulary definitions (normative):**

- **`rule_severity`** — the importance level declared by the rule in the template (`fail` | `warning` | `info`). This is a property of the rule, not the evaluation result.
- **`outcome`** — the result of evaluating the rule against the evidence (`passed` | `failed` | `skipped` | `error`). `skipped` means the rule's `condition` evaluated to false. `error` means the rule could not be evaluated.
- **`provision_outcome`** — the roll-up for a provision, computed using the following deterministic precedence algorithm (applied in order, first match wins):
  1. If ANY rule with `rule_severity: fail` has `outcome: failed` → **`not-satisfied`**
  2. If ANY rule has `outcome: error` → **`not-assessed`**
  3. If ALL rules have `outcome: skipped` → **`skipped`**
  4. If an `evidence_gap` record exists for this provision AND no fail-severity rules failed → **`gap-acknowledged`**
  5. If ALL fail-severity rules passed but ANY warning-severity rule has `outcome: failed` → **`partially-satisfied`**
  6. If ALL rules have `outcome: passed` → **`satisfied`**
  7. If no rules exist for this provision → **`not-assessed`**

  `not-satisfied` always takes precedence over `gap-acknowledged`. An evidence gap acknowledgment does not override a failed mandatory rule. Provision-not-yet-effective is handled by the DSL `condition` mechanism (producing `skipped` outcomes), NOT by structural errors.

**Multi-subject evaluation unit (normative):** In bundles with multiple subjects, each provision is evaluated **per subject** by default. A rule's `scope` filter determines which subjects it applies to. `provision_summary[]` entries MUST include `subject_scope` identifying which subject(s) the summary covers. If a template explicitly declares `"evaluation_scope": "package"` on a provision, that provision is evaluated once for the entire bundle (useful for organizational policies like `governance_policy` that apply across all systems).

**Canonical evaluation instant (normative):** All date-sensitive rule logic (`evidence_freshness`, `if_provision_effective`, provision `effective_date` checks) MUST use the `evaluation_instant` field in the Assessment Bundle as the single reference time. This field is set by the validator at the start of evaluation and recorded in the Assessment Bundle. It MUST NOT use wall-clock time during evaluation. When `reference_date` in a rule is set to `validation_time`, it resolves to `evaluation_instant`. When set to `package_time`, it resolves to the Evidence Bundle's `metadata.timestamp`. When set to `obligation_effective_date`, it resolves to the provision's `effective_date` in the template. This ensures reproducible evaluation: re-running the same validator with the same `evaluation_instant` against the same Evidence Bundle MUST produce identical results.

**Assessment Bundle integrity:** The JWS signature is computed over the RFC 8785-canonicalized bytes of the Assessment Bundle JSON with the `integrity` block set to `null`. After signing, the `integrity` block is populated. Verifiers reconstruct the pre-signature form by nulling `integrity`, then verify.

**Key design decisions:**
- **`template_digests`** records the exact hash of each template version used, so the assessment is reproducible even if templates are later updated.
- **`provision_summary`** provides the per-provision roll-up that auditors need, but it lives in the Assessment Bundle, NOT the Evidence Bundle — preserving the separation between evidence and judgment.
- **`structural_errors`** uses the normative error taxonomy from Section 3.6 with JSON Pointer (RFC 6901) `path` for precise location. These are errors in the Evidence Bundle structure, distinct from rule evaluation `results`.

**Extension semantics (normative):** Standard ACEF conformance outcomes (all `results[].outcome` and `provision_summary[].provision_outcome` values) MUST NOT depend on vendor-namespaced (`x-*`) record types, rule operators, or fields. A compliant validator MUST produce identical conformance outcomes whether or not `x-*` extensions are present. "Lossless export to the open core" means: removing all `x-*` prefixed fields and re-canonicalizing MUST produce a valid ACEF package with identical conformance outcomes.

---

## 4. Cross-Regulation Alignment Matrix

This matrix shows how evidence artifacts map across frameworks, enabling "collect once, prove many" efficiency.

| ACEF Record Type | EU AI Act | NIST AI RMF | US Copyright | China CAC | UK (anticipated) | ISO 42001 |
|---|---|---|---|---|---|---|
| `risk_register` | Art. 9 | MAP-1, MAP-3 | — | — | — | 6.1 |
| `risk_treatment` | Art. 9 | MANAGE-1, MANAGE-2 | — | — | — | 6.1 |
| `dataset_card` | Art. 10 | MAP-2 | Lawful acquisition | — | Training data disclosure | A.7.4 |
| `data_provenance` | Art. 10, GPAI Annex XI | MAP-2 | Acquisition records | — | Training data disclosure | A.7.4 |
| `evaluation_report` | Art. 11, Art. 15 | MEASURE-1, MEASURE-2 | — | — | — | 9.1 |
| `event_log` | Art. 12 | MEASURE-2 | — | 6-month retention | — | 9.1 |
| `human_oversight_action` | Art. 14 | GOVERN-1.3 | — | — | — | A.8.4 |
| `transparency_disclosure` | Art. 13 | GOVERN-1.7 | — | Visible labels | Statutory transparency | A.6.2.6 |
| `transparency_marking` | **Art. 50** | — | — | Implicit metadata, watermarks | Provenance standards | — |
| `disclosure_labeling` | **Art. 50** | — | — | Visible labels, user declarations | Statutory transparency | — |
| `copyright_rights_reservation` | GPAI Art. 53 | — | TDM opt-out, licensing | — | Rights reservation compliance | — |
| `license_record` | GPAI Art. 53 | — | Licensing records | — | Licensing compliance | — |
| `incident_report` | GPAI Art. 55 | MANAGE-4 | — | — | — | 10.2 |
| `governance_policy` | Art. 17 (QMS) | GOVERN-1 | — | — | — | 5.1, 5.2 |
| `governance_policy` (variant: `ai_use_case_inventory_entry`) | — | GOVERN-1.7 | — | — | — | — |
| `conformity_declaration` | Art. 47–48 | — | — | — | — | — |
| `evidence_gap` | All articles | All functions | All guidance areas | All requirements | All recommendations | All clauses |

**Note:** OMB M-24-10 (US federal) maps primarily to `governance_policy` variants (`ai_use_case_inventory_entry`, CAIO governance records) and is tracked via the `us-omb-m-24-10` template. Not shown as a separate column to keep the matrix readable.

---

## 5. Reference Implementation — Capture SDK

### 5.1 SDK Design (Python-first)

```python
import acef

# Initialize a compliance package with subjects (plural — supports composed systems)
package = acef.Package(producer={"name": "acme-compliance-tool", "version": "1.2.0"})

# Define the AI system and its components
system = package.add_subject(
    subject_type="ai_system",
    name="Acme RAG Assistant v2",
    provider="Acme AI Corp",
    risk_classification="high-risk",
    modalities=["text"],
    lifecycle_phase="deployment",
)

model = package.add_subject(
    subject_type="ai_model",
    name="Acme LLM v2",
    provider="Acme AI Corp",
    risk_classification="gpai",
    modalities=["text"],
    lifecycle_phase="deployment",
)

# Define entities — datasets, components, actors (defined once, referenced by records)
retriever = package.add_component(
    name="Vector Retriever",
    type="retriever",
    version="3.1.0",
    subject_refs=[system.id],
)

guardrail = package.add_component(
    name="Output Safety Filter",
    type="guardrail",
    version="1.4.0",
    subject_refs=[system.id],
)

training_data = package.add_dataset(
    name="CommonCrawl-2025-Q3",
    version="2025.3",
    source_type="licensed",
    modality="text",
    size={"records": 3_200_000_000, "size_gb": 2400},
    subject_refs=[model.id],
)

# Define relationships between entities
package.add_relationship(system.id, model.id, "wraps")
package.add_relationship(system.id, retriever.id, "calls")
package.add_relationship(model.id, training_data.id, "trains_on")

# Add regulation profiles
package.add_profile("eu-ai-act-2024", provisions=["article-9", "article-10", "article-12", "article-50.2"])
package.add_profile("nist-ai-rmf-1.0", provisions=["map-1", "map-2", "measure-1"])

# Record evidence — dataset provenance (references dataset entity by URN)
package.record(
    record_type="data_provenance",
    provisions=["article-10", "map-2"],
    obligation_role="provider",
    entity_refs={"dataset_refs": [training_data.id]},
    payload={
        "acquisition_method": "licensed",
        "acquisition_date": "2025-09-01",
        "opt_out_compliance": {
            "method": "robots_txt_and_http_headers",
            "verification_date": "2025-09-15",
        },
    },
)

# Record evidence — copyright rights reservation (replaces copyright_compliance)
package.record(
    record_type="copyright_rights_reservation",
    provisions=["article-53"],
    obligation_role="provider",
    entity_refs={"dataset_refs": [training_data.id]},
    confidentiality="regulator-only",  # Trade-secret-sensitive details
    redaction_method="sha256-hash-commitment",
    payload={
        "opt_out_detection_method": "robots_txt_and_tdmrep",
        "tdmrep_protocol_version": "1.0",
        "removal_process": "automated_pipeline_with_manual_review",
        "compliance_verification_date": "2025-09-15",
        "reserved_works_removed": 142_000,
    },
)

# Record evidence — transparency marking (provider-side Art. 50 obligation)
package.record(
    record_type="transparency_marking",
    provisions=["article-50.2"],
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
    payload={
        "marking_technique": "secure_metadata",
        "metadata_format": "c2pa-manifest-v2.3",
        "watermark_applied": True,
        "watermark_method": "spectral_embedding",
        "robustness_parameters": {"compression": "jpeg_q30", "cropping": "25%", "screenshot": True},
        "detection_api_endpoint": "https://api.acme.ai/v1/detect",
    },
)

# Record evidence — event log (automatic capture, high-volume → JSON Lines)
package.record(
    record_type="event_log",
    provisions=["article-12"],
    obligation_role="deployer",
    entity_refs={"subject_refs": [system.id], "component_refs": [retriever.id]},
    retention={"min_retention_days": 180, "legal_basis": "eu-ai-act-2024:article-12"},
    payload={
        "event_type": "inference",
        "session_id": "sess-abc123",
        "input_hash": "sha256:a1b2c3...",
        "output_hash": "sha256:d4e5f6...",
        "latency_ms": 245,
    },
)

# Record evidence — human oversight action (replaces oversight_record)
package.record(
    record_type="human_oversight_action",
    provisions=["article-14"],
    obligation_role="deployer",
    trust_level="self-attested",
    entity_refs={"subject_refs": [system.id]},
    payload={
        "action_type": "override",
        "session_id": "sess-abc123",
        "reason": "Output flagged as potentially harmful by safety filter",
        "operator_decision": "blocked_and_escalated",
        "escalation_path": "safety-team-oncall",
    },
)

# Record an evidence gap (explicit acknowledgment of missing evidence)
package.record(
    record_type="evidence_gap",
    provisions=["article-15"],
    obligation_role="provider",
    entity_refs={"subject_refs": [system.id]},
    payload={
        "missing_record_type": "robustness_assessment",
        "reason": "adversarial_testing_scheduled_for_q2",
        "expected_completion_date": "2026-06-30",
        "remediation_plan": "Contracted with external red team; engagement starts 2026-04-01",
    },
)

# Export as content-addressable bundle
package.sign(key="path/to/private_key.pem", method="jws")
package.export("acme-rag-evidence-2026-q1.acef/")  # Directory bundle
package.export("acme-rag-evidence-2026-q1.acef.tar.gz")  # Archive bundle

# Validate against regulation mapping templates → produces Assessment Bundle
assessment = acef.validate(package, profiles=["eu-ai-act-2024", "nist-ai-rmf-1.0"])
print(assessment.summary())
# => "EU AI Act: 3/4 provisions passed, 1 gap acknowledged (Art. 15) | NIST AI RMF: 2/3 provisions passed"
print(assessment.errors())
# => [ValidationError(code="ACEF-042", provision="article-15", severity="info",
#     message="evidence_gap acknowledged — robustness_assessment pending")]

# Export the Assessment Bundle separately from the Evidence Bundle
assessment.sign(key="path/to/validator_key.pem", method="jws")
assessment.export("acme-rag-assessment-2026-q1.acef-assessment.json")
```

### 5.2 SDK Components

| Component | Description |
|---|---|
| `acef.Package` | Core evidence package builder with entity graph and multi-subject support |
| `acef.Package.add_subject()` | Register AI systems/models as subjects |
| `acef.Package.add_component()` / `add_dataset()` / `add_actor()` | Register entities in the entity graph |
| `acef.Package.add_relationship()` | Define relationships between entities (wraps, calls, trains_on, etc.) |
| `acef.Package.record()` | Evidence recording API with entity linking, obligation role, and confidentiality |
| `acef.validate()` | Validate package against regulation mapping templates with evaluation rules |
| `acef.sign()` / `acef.verify()` | Cryptographic signing (JWS RFC 7515) and verification |
| `acef.export()` / `acef.load()` | Bundle serialization (directory or .acef.tar.gz archive) |
| `acef.chain()` | Link packages to prior versions via `prior_package_ref` |
| `acef.redact()` | Privacy-preserving redaction with hash commitments and access policies |
| `acef.render()` | Generate human-readable compliance reports from packages |
| `acef.merge()` | Merge evidence from multiple sources into a single package |

### 5.3 Integrations

| Integration | How |
|---|---|
| **OpenTelemetry** | OTLP exporter that converts ACEF `event_log` records to/from OTel spans; bidirectional |
| **C2PA** | Read/write C2PA manifests as `transparency_marking` evidence records; bridge for content provenance |
| **W3C TDMRep** | Import TDM reservation signals as `copyright_rights_reservation` records |
| **CycloneDX / SPDX** | Import SBOM data as supply chain evidence linked to `entities.components[]` |
| **MLflow / Weights & Biases** | Auto-capture training run metadata as evidence records linked to `entities.datasets[]` |
| **Hugging Face** | Ingest model cards as `dataset_card` + `evaluation_report` records linked to model subjects |
| **LangSmith / LangFuse** | Capture LLM trace data as `event_log` records (JSON Lines for high volume) |

---

## 6. Governance & Versioning

### 6.1 Specification Governance

- **Owned by AI Commons** (non-profit)
- **Community RFC process** for spec changes (inspired by IETF RFCs and OTel OTEPs)
- **Semantic versioning** — breaking changes require major version bump
- **Regulation mapping templates** versioned independently, with community peer review
- **Working groups** per jurisdiction (EU, US, UK, China, International Standards)

### 6.2 Versioning Strategy

| Layer | Versioning | Governance |
|---|---|---|
| ACEF Core (envelope, integrity, errors) | Semver, slow-moving | AI Commons steering committee |
| ACEF Profiles (record types, templates, rule DSL) | Semver, medium pace | Jurisdiction working groups + legal review |
| ACEF Assessment (validation schema, result format) | Semver, medium pace | AI Commons steering committee |
| Reference SDK | Semver, follows spec | Open source maintainers |
| Reference Validator | Semver, follows profiles | Open source maintainers |

**Module compatibility matrix (normative):** The `versioning` block in the manifest declares which module versions a package was built against. Validators MUST reject packages with incompatible version combinations.

| Core Version | Compatible Profiles Versions | Compatible Assessment Versions |
|---|---|---|
| 1.x | 1.x | 1.x |

Breaking changes to any module require a major version bump in that module. A Core 2.x package cannot be validated by a Profiles 1.x template. The manifest's `versioning` block is the single source of truth for version negotiation — there is no single `acef_version` field.

### 6.3 Licensing

All AI Commons-owned artifacts MUST be published under permissive open licenses:

| Artifact | License |
|---|---|
| ACEF specification documents | CC-BY 4.0 |
| JSON Schemas (envelope, record types) | CC-BY 4.0 |
| Regulation mapping templates | CC-BY 4.0 |
| Reference SDK (Python, TypeScript, Go, Java) | Apache 2.0 |
| Reference Validator | Apache 2.0 |
| Conformance test suite | Apache 2.0 |
| Test vectors / golden files | CC0 1.0 (public domain) |

### 6.4 Conformance Program

To prevent fragmentation and protect the open boundary:

1. **ACEF Core namespace is reserved** for AI Commons-managed schemas and profile IDs. No vendor may publish schemas or profiles under the `acef-conventions/` namespace without going through the RFC process.
2. **All AI Commons-owned schemas, templates, and rule semantics MUST be publicly versioned and signed** in a canonical registry with content-addressed hashes.
3. **Any package claiming conformance to an ACEF profile MUST cite the public template digest** used for validation. This is captured in the Assessment Bundle's `template_digests` field.
4. **Vendor extensions MUST use a namespaced prefix** (e.g., `x-vendorname/custom_record_type`) and MUST be safely ignorable by standard validators.
5. **ACEF Evidence Bundle export MUST be lossless to the open core**, even if a commercial product adds extra metadata in vendor-namespaced extensions.
6. **"ACEF-compatible" trademark** is limited to implementations that pass the public conformance test suite (Section 6.5).

### 6.5 Conformance Test Suite

The conformance test suite is a collection of golden files and test cases that define what "ACEF-compatible" means:

| Test Category | What It Validates |
|---|---|
| **Round-trip** | Create → export → load → re-export produces bit-identical `content-hashes.json` |
| **Cross-language** | Python SDK, TypeScript SDK produce identical bundles from identical inputs |
| **Integrity verification** | Valid bundles pass; bundles with tampered files, bad hashes, invalid signatures fail with correct error codes |
| **Schema validation** | Valid and invalid record payloads produce correct pass/fail results per record-type schemas |
| **Minimum payload validation** | `event_log`, `transparency_marking`, `disclosure_labeling` records missing normative minimum fields (Section 3.1.5) fail schema validation |
| **Variant registry** | `exists_where` rules correctly match payload variants; variant-registry.json entries resolve to valid record types and discriminator paths |
| **Template evaluation** | Reference validator produces identical Assessment Bundles from identical Evidence Bundles + templates |
| **Multi-subject evaluation** | Per-subject default evaluation produces separate `provision_summary` entries per subject; `evaluation_scope: "package"` provisions produce one entry for the whole bundle |
| **DSL operators** | Each built-in operator (including `exists_where`, `bundle_signed`, `record_attested`, `attachment_kind_exists`) has pass and fail test vectors |
| **Empty-set semantics** | Existential operators fail on zero records; universal operators pass vacuously on zero records |
| **Provision roll-up** | Deterministic `provision_outcome` computed correctly for each precedence case (not-satisfied > error > skipped > gap-acknowledged > partially-satisfied > satisfied) |
| **Extension handling** | Vendor-namespaced extensions are preserved on round-trip and ignored by standard validators; `x-*` fields cannot change conformance outcomes (ACEF-053) |
| **Error taxonomy** | Each error code in Section 3.6 has at least one negative test case that triggers it |
| **Redacted packages** | Packages with `confidentiality: hash-committed` records verify correctly with partial evidence |
| **Deterministic sharding** | Shard splitting follows "earlier of 100k records or 256 MB" rule; record ordering is timestamp-ascending with record_id sub-sort |
| **Archive determinism** | `.acef.tar.gz` with gzip level 6, mtime=0, OS=0xFF produces identical bytes across runtimes |

### 6.6 Golden Bundle Specifications

The following golden bundles MUST be published alongside the spec to enable end-to-end conformance testing. Each bundle is a complete, valid ACEF Evidence Bundle with accompanying Assessment Bundle.

| Golden Bundle | Regulatory Coverage | Key Records |
|---|---|---|
| **EU high-risk system core** | EU AI Act Ch. III (Art. 9–17, 19) | risk_register (with management_review and post_market_monitoring_plan variants), risk_treatment, dataset_card, data_provenance, evaluation_report, event_log (with logging_spec variant), human_oversight_action, governance_policy (QMS variants), transparency_disclosure (instructions for use) |
| **GPAI provider Annex XI/XII** | EU AI Act Art. 53, Annex XI, Annex XII | evaluation_report (gpai_annex_xi_model_doc variant with compute/energy), data_provenance, copyright_rights_reservation, license_record, transparency_disclosure (Annex XII downstream info + publication_evidence variant) |
| **Synthetic content marking + labeling** | EU AI Act Art. 50, EU Code of Practice draft, China CAC | transparency_marking (with marking_scheme_id, watermark, verification ref), disclosure_labeling (deepfake + interaction disclosures with locale/accessibility), event_log (marking operations), evaluation_report (mark_detectability_test variant) |
| **China CAC labeling compliance** | CAC Measures (2025) | transparency_marking (CN jurisdiction, explicit + implicit labels, implicit_label_fields), disclosure_labeling (explicit labels), event_log (with label_exception = true triggering 6-month retention) |
| **US federal governance + inventory** | OMB M-24-10, NIST AI RMF | governance_policy (ai_use_case_inventory_entry variant with CAIO, rights/safety classification), governance_policy (QMS/governance board charter), risk_register, evaluation_report |
| **Multi-subject composed system** | Cross-regulation | Two subjects (ai_system + ai_model), shared components via entity graph, per-subject evaluation producing separate provision_summary entries, package-scoped governance_policy |

Each golden bundle includes:
- A valid Evidence Bundle (`.acef/` directory)
- A valid Assessment Bundle (`.acef-assessment.json`) produced by the reference validator
- Expected validation results (pass/fail per rule, provision outcomes, error codes)
- A negative variant with introduced defects (tampered hash, missing field, dangling ref) and expected error codes

---

## 7. Open Questions for Community

### Resolved in v0.2

1. ~~**Multi-system composition:** How to handle compliance evidence for systems composed of multiple AI models?~~ **Resolved:** `subjects[]` is plural with `entities.relationships[]` graph. See Section 3.1.
2. ~~**Confidentiality model:** How to handle trade secrets in evidence?~~ **Resolved:** `confidentiality`, `redaction_method`, and `access_policy` fields on every evidence record. See Section 3.1.
3. ~~**Provider/deployer split:** How to track who is responsible for each piece of evidence?~~ **Resolved:** `obligation_role` field on evidence records + `transparency_marking` / `disclosure_labeling` split. See Sections 3.1, 3.2.

### Still Open

1. **Naming:** ACEF, or something else? (AI Compliance Evidence Format, AI Governance Evidence Protocol, AI Compliance Package...?)
2. **Granularity of event logs:** Should ACEF define minimum logging granularity, or leave it to regulation mapping templates?
3. **Real-time vs. snapshot:** Should ACEF support streaming evidence (like OTLP) in addition to packaged snapshots?
4. **Interop with existing model cards:** Should ACEF subsume model cards / datasheets, or reference them externally?
5. **Certification path:** Should ACEF packages be usable as formal evidence in EU conformity assessment procedures?
6. **Zero-knowledge proofs for confidential evidence:** The `hash-committed` confidentiality level supports basic attestation without disclosure. Should ACEF define a specific ZKP protocol for more advanced selective disclosure (e.g., proving dataset size exceeds a threshold without revealing the exact number)?
7. **Transport protocol:** How do packages get from provider to deployer to regulator? HTTP API? Registry pull? ACEF currently defines the wire format but not the transport. Should a companion transport spec be developed (analogous to OTLP's HTTP/gRPC transports)?
8. **Delegated act versioning:** When EU delegated acts amend Annex requirements, how should existing packages reference both old and new template versions? Should packages declare which template version they were validated against, or should validators always use the latest?

---

## 8. Relationship to Existing Standards & Initiatives

| Initiative | Relationship to ACEF |
|---|---|
| **C2PA / Content Authenticity Initiative** | ACEF's `transparency_marking` record type wraps C2PA manifests; complementary, not competing. C2PA provides the cryptographic content credential; ACEF provides the compliance context. |
| **W3C TDM Reservation Protocol (TDMRep)** | TDMRep signals (rights reservation for text/data mining) feed into `copyright_rights_reservation` records. ACEF treats TDMRep as the canonical protocol for expressing EU DSM Directive Art. 4(3) reservations. |
| **W3C PROV Data Model** | ACEF's entity graph (`subjects[]`, `entities`, `relationships[]`) is designed for compatibility with PROV's Agent/Entity/Activity model, enabling interoperability with provenance ecosystems. |
| **Creative Commons CC Signals** | Rights preference signals could be imported as `copyright_rights_reservation` evidence |
| **Common Crawl Opt-Out Registry** | Opt-out compliance evidence feeds into `copyright_rights_reservation` records |
| **Fairly Trained Certification** | Certification status could be an `attestation` on licensing evidence with `trust_level: independently-verified` |
| **Open Future Commons Governance** | Dataset governance frameworks map to `data_provenance` records linked to `entities.datasets[]` |
| **CEN/CENELEC Harmonised Standards** | Once published, these define compliance benchmarks that mapping templates reference via `normative_text_ref` |
| **ISO/IEC 42001** | ACEF can serve as the evidence layer for 42001's documentation requirements; mapping template planned for v1.0 |
| **OECD AI System Cards** | System card fields map to ACEF's `subjects[]` metadata and `transparency_disclosure` records |

---

## 9. Implementation Roadmap

| Phase | Timeline | Deliverables |
|---|---|---|
| **Phase 0: This document** | Now | Spec outline, regulatory alignment matrix, community feedback |
| **Phase 1: Core schema** | +2 months | JSON Schema for envelope + 5 core record types, validation tooling |
| **Phase 2: EU mapping template** | +3 months | `eu-ai-act-2024` and `eu-gpai-code-of-practice-2025` templates |
| **Phase 3: Reference SDK (Python)** | +4 months | Package builder, validator, signer, exporter |
| **Phase 4: NIST + US templates** | +5 months | `nist-ai-rmf-1.0`, `nist-ai-600-1`, `us-copyright-office-part3` |
| **Phase 5: Community expansion** | +6 months | TypeScript/Go SDKs, China/UK templates, integrations |
| **Phase 6: Conformity assessment pilot** | +9 months | Pilot with EU notified bodies for using ACEF in formal assessment |

---

## Appendix A: Key Regulatory Sources Analyzed

### Europe
- EU AI Act (Regulation 2024/1689) — Articles 9–17, 50, 53, 55, Annexes IV/XI/XII
- General-Purpose AI Code of Practice (July 2025) — Transparency, Copyright, Safety/Security chapters
- Second Draft Code of Practice on Marking and Labelling AI-generated Content (March 2026)
- European Commission Standardisation Request M/593 to CEN/CENELEC
- European Parliament Resolution on Copyright and GenAI (10 March 2026)
- CEN/CENELEC JTC 21 harmonised standards development (EN ISO/IEC 23894, QMS, Conformity Assessment)

### United States
- NIST AI Risk Management Framework 1.0 (AI 100-1)
- NIST AI 600-1 Generative AI Profile
- US Copyright Office Part 3 Report: Generative AI Training (2025)
- OMB Memorandum M-24-10: Advancing Governance, Innovation, and Risk Management for Agency Use of AI (2024)

### United Kingdom
- House of Lords Communications and Digital Committee: "AI, Copyright and the Creative Industries" (March 2026)

### China
- CAC Measures for Labeling AI-Generated and Synthesized Content (effective September 2025)
- GB 45438-2025 Cybersecurity Technology — Labeling Method for AI-Generated Content

### International Standards
- ISO/IEC 42001:2023 — AI Management System
- ISO/IEC 23894:2023 — AI Risk Management Guidance
- C2PA Specification 2.3 — Content Provenance and Authenticity
- W3C TDM Reservation Protocol (TDMRep) — Rights reservation for text and data mining
- W3C PROV Data Model — Provenance entity-activity-agent model
- CycloneDX / SPDX — Software Bill of Materials
- OpenTelemetry Protocol (OTLP) — Observability wire format
- JWS (RFC 7515) — JSON Web Signature for cryptographic signing

---

## Appendix B: Known Gaps & Resolution Status

### B.1 Resolved in v0.2 and v0.3

The following gaps have been addressed:

| Gap | Resolution | Version |
|---|---|---|
| **Multi-system composition** | `subjects[]` is plural; `entities.components[]` and `entities.relationships[]` form an entity graph. See Section 3.1. | v0.2 |
| **Lifecycle transition timestamps** | `subjects[].lifecycle_timeline[]` with phase, start_date, end_date. See Section 3.1. | v0.2 |
| **Confidentiality flags** | `evidence_records[].confidentiality` field: public/redacted/hash-committed/regulator-only/under-nda. See Section 3.1. | v0.2 |
| **Evidence trust levels** | `evidence_records[].trust_level`: self-attested/peer-reviewed/independently-verified/notified-body-certified. See Section 3.1. | v0.2 |
| **Sub-provision granularity** | Dotted notation (e.g., "article-9.1.a") supported in `provisions_addressed[]` and template `sub_provisions`. See Sections 3.1, 3.4. | v0.2 |
| **Provider/deployer obligation split** | `obligation_role` field on every evidence record + `transparency_marking` / `disclosure_labeling` split. See Sections 3.1, 3.2. | v0.2 |
| **Article 50 coverage** | Full Article 50 section added with marking, disclosure, interaction, and biometric transparency. See Section 2.1. | v0.2 |
| **Bundle format** | Canonical directory layout with sharding support. See Section 3.1.1. | v0.2 |
| **Schema registry** | Record type schemas discoverable at `acef-conventions/v{major}/[record_type].schema.json`. See Section 3.3. | v0.2 |
| **Signing mechanism** | JWS (RFC 7515) with RS256/ES256, detached signatures. See Section 3.1.3. | v0.2 |
| **Entity-record separation** | Entities defined once in entity graph, referenced by URN from records. See Section 3.1. | v0.2 |
| **Circular integrity model** | Hash domain explicitly defined; `hashes/` and `signatures/` are outside the hash domain. RFC 8785 canonicalization. See Section 3.1.3. | v0.3 |
| **Evidence vs. assessment separation** | Evidence Bundle and Assessment Bundle are separate artifacts. `provision_status` moved to Assessment Bundle. See Sections 1.0.2, 3.6. | v0.3 |
| **Error taxonomy** | Normative error codes (ACEF-001 through ACEF-060) with severity levels and categories. See Section 3.6. | v0.3 |
| **Legal force model** | Templates now include `instrument_type`, `legal_force`, `instrument_status`, and per-provision `effective_date`. See Section 3.4. | v0.3 |
| **Conformance program** | Conformance test suite, licensing, namespace governance, trademark rules. See Sections 6.3–6.5. | v0.3 |
| **Assessment result schema** | Machine-readable validation output with rule IDs, severity, JSON paths, template digests. See Section 3.7. | v0.3 |
| **Completeness summary** | Moved to Assessment Bundle `provision_summary[]` — auditors see compliance posture without it being self-declared in the evidence. See Section 3.7. | v0.3 |

**Additional items resolved in v0.3r4 (regulatory evidence validation):**

| Gap | Resolution | Version |
|---|---|---|
| **Normative event_log payload** | Minimum required fields defined: event_type, correlation_id, inputs/outputs_commitment, retention_start_event. See Section 3.1.5. | v0.3r4 |
| **logging_spec variant** | Describes what is logged and why, enabling deployers to interpret logs per Art. 12. See Section 3.1.5. | v0.3r4 |
| **Structured training content summary** | `gpai_annex_xi_model_doc` variant with typed fields for training data, compute, energy, and publication evidence. See Section 3.1.5. | v0.3r4 |
| **Testable marking evidence** | `transparency_marking` minimum fields defined: marking_scheme_id, scheme_version, modality, metadata_container, label_exception. See Section 3.1.5. | v0.3r4 |
| **China CAC implicit label structure** | `transparency_marking` supports jurisdiction-specific metadata containers and label_exception block for "no explicit label" path. See Section 3.1.5. | v0.3r4 |
| **US federal inventory** | `ai_use_case_inventory_entry` variant with rights/safety classification, CAIO, governance board. See Section 3.1.5. | v0.3r4 |
| **Compute and energy schema** | Typed fields for hardware, FLOPs, kWh, estimation method, carbon intensity, scope, uncertainty. See Section 3.1.5 Annex XI variant. | v0.3r4 |
| **Accessibility/localization** | `disclosure_labeling` minimum fields include locale (BCP 47), accessibility_standard_refs, usability_test_evidence_ref. See Section 3.1.5. | v0.3r4 |
| **Retention start disambiguation** | `retention_start_event` field added to per-record retention block. See Section 3.1. | v0.3r4 |
| **Platform role** | `obligation_role` vocabulary expanded to include `platform` for China CAC platform verification duties. See Section 3.1. | v0.3r4 |
| **OMB M-24-10 template** | Added to planned templates with `binding` (federal agencies) legal force. See Section 3.4. | v0.3r4 |

### B.2 Remaining Gaps for v0.4

| Artifact / Enhancement | Gap | Regulation |
|---|---|---|
| `mitigation_effectiveness` | No way to prove a risk mitigation *actually reduced* the risk after implementation | EU AI Act Art. 9 |
| `post_mitigation_fairness` | Bias detection exists, but no re-test artifact after mitigation | EU AI Act Art. 10 |
| `legal_review_signoff` | No artifact for IP attorney review or fair use analysis per dataset | US Copyright Office |
| `role_assignment_record` | `entities.actors[]` captures roles but not *named individual assignment transitions* with history | NIST GOVERN |
| `api_uptime_validation` | Verification API documented but no evidence of reliability/SLA compliance | EU Labelling CoP |
| `archival_verification` | Retention policies declared but no proof of retrieval capability | EU AI Act Art. 11–12 |
| `notification_receipt` | Incident reports now include notification timestamps, but no confirmation of *delivery receipt* from regulatory authority | GPAI Art. 55 |
| **Conditional compliance** | "Collect once, prove many" doesn't handle jurisdiction-specific interpretation differences for the same evidence | Cross-regulation |
| **Transport protocol** | ACEF defines wire format but not how packages are transmitted between parties | All |
| **ZKP selective disclosure** | `hash-committed` confidentiality is basic; advanced selective disclosure (proving properties without revealing values) not specified | EU AI Act confidentiality, GPAI MDF |

### B.3 Cross-Regulation Matrix Expansion

The alignment matrix in Section 4 now covers 16 ACEF record types mapped across 6 regulatory frameworks. The detailed sections define 70+ specific artifact types within those record types. The v0.3 spec should introduce a two-tier system: high-level record type domains in the matrix (as currently shown) with detailed payload field mappings documented per-record-type in the schema registry (Section 3.3).
