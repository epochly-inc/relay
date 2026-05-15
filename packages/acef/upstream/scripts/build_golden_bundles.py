#!/usr/bin/env python3
"""Build all 6 ACEF golden bundles and per-template test vectors.

This script programmatically constructs each golden bundle and test vector
using the ACEF SDK, exports them to their canonical directories, validates
them against the appropriate regulation templates, and writes Assessment
Bundles alongside.

Golden Bundles (tests/conformance/golden-bundles/):
  1. eu-high-risk-core
  2. gpai-provider-annex-xi-xii
  3. synthetic-content-marking
  4. china-cac-labeling
  5. us-federal-governance
  6. multi-subject-composed

Test Vectors (test-vectors/):
  eu-ai-act/     - 10 bundles (pass/fail)
  china-cac/     - 3  bundles (pass/fail)
  nist-rmf/      - 2  bundles (pass/fail)
  omb-m24-10/    - 2  bundles (pass/fail)
  eu-gpai-cop/   - 2  bundles (pass/fail)
"""

from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure src is on the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import acef
from acef.package import Package

# ── Constants ──────────────────────────────────────────────────────────

GOLDEN_DIR = PROJECT_ROOT / "tests" / "conformance" / "golden-bundles"
VECTORS_DIR = PROJECT_ROOT / "test-vectors"

# Fixed timestamps for determinism
TS_NOW = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)
TS_RECENT = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)
TS_OLD = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)

# Default collector for all records
DEFAULT_COLLECTOR = {"name": "acef-golden-builder", "version": "1.0.0"}
TV_COLLECTOR = {"name": "acef-test-vector-builder", "version": "1.0.0"}


# ── Helpers ────────────────────────────────────────────────────────────


def _clean_dir(path: Path) -> None:
    """Remove and recreate a directory."""
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _export_and_validate(
    pkg: Package,
    output_dir: Path,
    profiles: list[str],
    *,
    evaluation_instant: str | None = None,
) -> acef.assessment_builder.AssessmentBundle:
    """Export bundle, validate, write assessment alongside."""
    pkg.export(str(output_dir))
    assessment = acef.validate(
        pkg,
        profiles=profiles,
        evaluation_instant=evaluation_instant or TS_NOW,
    )
    assessment_path = output_dir.parent / f"{output_dir.name}.acef-assessment.json"
    acef.export_assessment(assessment, str(assessment_path))
    return assessment


def _print_assessment(name: str, assessment) -> None:
    """Print assessment summary for a bundle."""
    errors = assessment.errors()
    status = "PASS" if not errors else "FAIL"
    print(f"  [{status}] {name}: {assessment.summary()}")
    if errors:
        for e in errors[:5]:
            rule_id = e.get("rule_id", e.get("code", "unknown"))
            msg = e.get("message", "")
            print(f"         - {rule_id}: {msg[:120]}")


# ═══════════════════════════════════════════════════════════════════════
# GOLDEN BUNDLE 1: EU High-Risk Core
# ═══════════════════════════════════════════════════════════════════════


def build_eu_high_risk_core() -> None:
    """EU AI Act high-risk with all core record types."""
    output = GOLDEN_DIR / "eu-high-risk-core"
    _clean_dir(output)

    pkg = Package(producer={"name": "acef-golden-builder", "version": "1.0.0"})

    # Subject: high-risk AI system (tabular -> multimodal per manifest schema)
    system = pkg.add_subject(
        "ai_system",
        name="MedAssist Clinical Decision Support System",
        version="3.2.0",
        provider="HealthAI Corp",
        risk_classification="high-risk",
        modalities=["text", "multimodal"],
        lifecycle_phase="deployment",
        lifecycle_timeline=[
            {"phase": "design", "start_date": "2024-01-15"},
            {"phase": "development", "start_date": "2024-04-01"},
            {"phase": "testing", "start_date": "2025-06-01"},
            {"phase": "deployment", "start_date": "2025-12-01"},
        ],
    )

    # Entities
    model = pkg.add_component(
        "ClinicalBERT-v3",
        "model",
        version="3.2.0",
        subject_refs=[system.subject_id],
        provider="HealthAI Corp",
    )
    guardrail = pkg.add_component(
        "SafetyGuardrail",
        "guardrail",
        version="1.5.0",
        subject_refs=[system.subject_id],
        provider="HealthAI Corp",
    )
    dataset = pkg.add_dataset(
        "MIMIC-IV-Clinical-Subset",
        version="2.0",
        source_type="licensed",
        modality="tabular",
        size={"records": 524000, "size_gb": 12.4},
        subject_refs=[system.subject_id],
    )
    provider_actor = pkg.add_actor(
        name="Dr. Elena Vasquez",
        role="provider",
        organization="HealthAI Corp",
    )
    deployer_actor = pkg.add_actor(
        name="Berlin University Hospital",
        role="deployer",
        organization="Charite Universitaetsmedizin Berlin",
    )

    # Relationships
    pkg.add_relationship(
        system.subject_id, model.component_id, "wraps",
        description="System wraps ClinicalBERT-v3 transformer model",
    )
    pkg.add_relationship(
        model.component_id, dataset.dataset_id, "trains_on",
        description="Model trained on MIMIC-IV clinical dataset",
    )
    pkg.add_relationship(
        deployer_actor.actor_id, system.subject_id, "oversees",
        description="Deployer oversees system in clinical environment",
    )

    # Profile: EU AI Act
    pkg.add_profile(
        "eu-ai-act-2024",
        provisions=[
            "article-9", "article-10", "article-11", "article-12",
            "article-13", "article-14", "article-15", "article-17",
        ],
    )

    refs_subj = {"subject_refs": [system.subject_id]}
    refs_dataset = {
        "subject_refs": [system.subject_id],
        "dataset_refs": [dataset.dataset_id],
    }
    refs_actor = {
        "subject_refs": [system.subject_id],
        "actor_refs": [provider_actor.actor_id],
    }
    refs_deployer_actor = {
        "subject_refs": [system.subject_id],
        "actor_refs": [deployer_actor.actor_id],
    }

    # Attachments
    pkg.add_attachment(
        "post-market-monitoring-plan-v2.pdf",
        b"[Post-Market Monitoring Plan Document Content - MedAssist v3.2]",
    )
    pkg.add_attachment(
        "qms-policy-healthai-v4.pdf",
        b"[Quality Management System Policy - HealthAI Corp v4.0]",
    )

    # ── risk_register: management_review variant ──
    pkg.record(
        "risk_register",
        provisions=["article-9"],
        payload={
            "risk_id": "RISK-MED-001",
            "description": "Potential misdiagnosis due to distribution shift in patient demographics between training data and deployment population, leading to reduced accuracy for underrepresented groups",
            "category": "safety",
            "likelihood": "possible",
            "severity": "major",
            "risk_level": "high",
            "assessment_method": "quantitative_model",
            "assessment_date": "2026-02-15",
            "identified_by": provider_actor.actor_id,
            "status": "mitigated",
            "residual_risk_level": "medium",
            "residual_risk_justification": "Demographic-aware recalibration layer reduces differential error rates to below 3% across all subgroups. Continuous monitoring dashboard deployed.",
            "residual_risk_approver": "Dr. Elena Vasquez, Chief Medical AI Officer",
            "review_type": "management_review",
            "review_date": "2026-02-28",
            "review_attendees": [
                "Dr. Elena Vasquez (CMAIO)",
                "Prof. Karl Weber (Clinical Safety Lead)",
                "Maria Hoffman (Regulatory Affairs)",
                "Stefan Mueller (Engineering Director)",
            ],
            "review_decisions": [
                "Accept residual risk with enhanced monitoring",
                "Implement quarterly demographic drift analysis",
                "Extend recalibration to include age-stratified analysis",
            ],
            "review_signatories": [
                "Dr. Elena Vasquez",
                "Prof. Karl Weber",
            ],
            "linked_risk_ids": ["RISK-MED-002", "RISK-MED-005"],
        },
        obligation_role="provider",
        entity_refs=refs_actor,
        trust_level="peer-reviewed",
        lifecycle_phase="monitoring",
        collector=DEFAULT_COLLECTOR,
        attachments=[{
            "path": "artifacts/post-market-monitoring-plan-v2.pdf",
            "media_type": "application/pdf",
            "attachment_type": "post_market_monitoring_plan",
            "description": "Post-market monitoring plan for MedAssist v3.2",
        }],
        timestamp=TS_RECENT,
    )

    # ── risk_register: post_market_monitoring_plan variant ──
    pkg.record(
        "risk_register",
        provisions=["article-9"],
        payload={
            "risk_id": "RISK-MED-PMM-001",
            "description": "Post-market monitoring of model performance degradation in deployed clinical environments",
            "category": "reliability",
            "likelihood": "likely",
            "severity": "moderate",
            "risk_level": "medium",
            "assessment_method": "qualitative_matrix",
            "assessment_date": "2026-01-10",
            "identified_by": provider_actor.actor_id,
            "status": "monitoring",
            "review_type": "post_market_monitoring_plan",
            "monitoring_trigger_conditions": [
                "Accuracy drops below 92% on rolling 30-day window",
                "False negative rate exceeds 5% for any demographic subgroup",
                "Deployer reports unexpected behavior via incident channel",
            ],
            "monitoring_data_sources": [
                "Production inference telemetry (anonymized)",
                "Deployer feedback portal",
                "Regulatory safety database (EUDAMED)",
            ],
            "linked_risk_ids": ["RISK-MED-001"],
        },
        obligation_role="provider",
        entity_refs=refs_subj,
        trust_level="self-attested",
        lifecycle_phase="monitoring",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    # ── risk_treatment ──
    pkg.record(
        "risk_treatment",
        provisions=["article-9"],
        payload={
            "risk_id": "RISK-MED-001",
            "treatment_type": "mitigate",
            "control_description": "Demographic-aware recalibration layer that adjusts model confidence thresholds based on patient demographics. Combined with a safety guardrail that flags low-confidence predictions for mandatory human review.",
            "implementation_status": "verified",
            "implementation_date": "2025-11-15",
            "responsible_party": "Stefan Mueller, Engineering Director",
            "effectiveness_assessment": "Recalibration reduces differential error rates from 8.2% to 2.7% across demographic subgroups. Safety guardrail captures 99.1% of cases where recalibrated confidence is below threshold.",
            "effectiveness_rating": "highly_effective",
            "verification_method": "A/B testing on held-out clinical data with demographic stratification",
            "verification_date": "2026-01-20",
            "review_cycle_days": 90,
            "residual_risk_after_treatment": "medium",
        },
        obligation_role="provider",
        entity_refs=refs_subj,
        lifecycle_phase="deployment",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    # ── dataset_card ──
    pkg.record(
        "dataset_card",
        provisions=["article-10"],
        payload={
            "dataset_name": "MIMIC-IV Clinical Subset",
            "dataset_version": "2.0",
            "source": "PhysioNet / MIT Lab for Computational Physiology",
            "modality": "tabular",
            "purpose": "training",
            "size": {"records": 524000, "size_gb": 12.4},
            "collection_methodology": "Electronic health records from Beth Israel Deaconess Medical Center, de-identified per HIPAA Safe Harbor",
            "collection_date_range": {"start": "2008-01-01", "end": "2022-12-31"},
            "representativeness_assessment": "Dataset covers 524k patient admissions with broad demographic representation. Known underrepresentation of pediatric (<5%) and geriatric (>90 years, <2%) populations.",
            "geographic_coverage": ["US-MA"],
            "language_coverage": ["en-US"],
            "known_limitations": [
                "Single-center data may not generalize to all clinical settings",
                "ICD-10 coding inconsistencies present in approximately 3% of records",
            ],
            "quality_checks_performed": [
                {"check_name": "duplicate_detection", "result": "0.2% duplicates removed", "date": "2025-03-15"},
                {"check_name": "missing_value_analysis", "result": "4.1% missing values imputed using clinical rules", "date": "2025-03-20"},
            ],
            "bias_mitigation_methods": ["Demographic stratification analysis", "Synthetic augmentation for underrepresented cohorts"],
            "license": "PhysioNet Credentialed Health Data License 1.5.0",
            "personal_data_present": False,
        },
        obligation_role="provider",
        entity_refs=refs_dataset,
        lifecycle_phase="development",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    # ── data_provenance ──
    pkg.record(
        "data_provenance",
        provisions=["article-10"],
        payload={
            "acquisition_method": "licensed",
            "acquisition_date": "2025-02-01",
            "source_uri": "https://physionet.org/content/mimiciv/2.0/",
            "source_uris": ["https://physionet.org/content/mimiciv/2.0/"],
            "source_description": "MIMIC-IV v2.0 clinical database from PhysioNet",
            "legal_basis": "license",
            "chain_of_custody": [
                {"step": "Data acquisition", "actor": "HealthAI Corp Data Engineering", "date": "2025-02-01", "action": "received"},
                {"step": "De-identification verification", "actor": "HealthAI Privacy Team", "date": "2025-02-10", "action": "processed"},
            ],
            "processing_steps": ["Schema normalization to OMOP CDM v5.4", "Temporal feature extraction"],
            "geographic_origin": ["US"],
            "content_categories": ["clinical_records", "lab_results"],
            "source_type": "licensed",
        },
        obligation_role="provider",
        entity_refs=refs_dataset,
        lifecycle_phase="development",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    # ── evaluation_report ──
    pkg.record(
        "evaluation_report",
        provisions=["article-11", "article-15"],
        payload={
            "methodology": "Stratified k-fold cross-validation (k=5) with demographic subgroup analysis, supplemented by prospective validation on 3-month held-out deployment data",
            "evaluation_date": "2026-01-15",
            "test_datasets": ["MIMIC-IV holdout (20%)", "Prospective Berlin deployment data (3-month)"],
            "metrics": [
                {"metric_name": "accuracy", "value": 0.943, "threshold": 0.90, "unit": "percent"},
                {"metric_name": "sensitivity", "value": 0.962, "threshold": 0.95, "unit": "percent"},
                {"metric_name": "f1_score", "value": 0.947, "threshold": 0.90, "unit": "percent"},
            ],
            "reviewer": "Prof. Karl Weber, Clinical Safety Lead",
            "independent_evaluator": "TUV SUD AI Assessment Division",
            "results_summary": "MedAssist v3.2 exceeds all performance thresholds across overall and subgroup metrics.",
            "red_teaming_performed": True,
        },
        obligation_role="provider",
        entity_refs=refs_subj,
        lifecycle_phase="testing",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    # ── event_log: logging_spec variant ──
    pkg.record(
        "event_log",
        provisions=["article-12"],
        payload={
            "event_type": "logging_spec",
            "correlation_id": "LOGSPEC-MEDASSIST-v3.2",
            "logged_event_types": ["inference", "override", "error", "deployment"],
            "log_fields_documented": ["timestamp", "correlation_id", "session_id", "inputs_commitment", "outputs_commitment"],
            "traceability_rationale": "Logging captures all inference events with input/output hash commitments enabling traceability without storing patient data.",
            "retention_policy_summary": {
                "min_days": 3650,
                "start_event": "record_creation",
                "legal_basis": "EU AI Act Art. 12(1)",
            },
        },
        obligation_role="provider",
        entity_refs=refs_subj,
        lifecycle_phase="deployment",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    # ── event_log: inference event ──
    pkg.record(
        "event_log",
        provisions=["article-12"],
        payload={
            "event_type": "inference",
            "correlation_id": "INF-2026-03-01-00142",
            "session_id": "SES-BUH-2026-03-01-007",
            "inputs_commitment": {"hash_alg": "sha-256", "hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
            "outputs_commitment": {"hash_alg": "sha-256", "hash": "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5"},
            "latency_ms": 127,
            "actor_ref": deployer_actor.actor_id,
        },
        obligation_role="deployer",
        entity_refs=refs_deployer_actor,
        lifecycle_phase="deployment",
        collector={"name": "medassist-logging-agent", "version": "2.1.0"},
        timestamp=TS_RECENT,
    )

    # ── human_oversight_action ──
    pkg.record(
        "human_oversight_action",
        provisions=["article-14"],
        payload={
            "action_type": "override",
            "session_id": "SES-BUH-2026-03-01-007",
            "correlation_id": "INF-2026-03-01-00142",
            "reason": "Model confidence below clinical threshold (0.72) for differential diagnosis of rare cardiac arrhythmia.",
            "operator_decision": "modified_and_released",
            "operator_id": "CLINICIAN-BUH-4521",
            "operator_role": "deployer_admin",
            "intervention_mechanism": "dashboard_button",
            "ai_system_response": "fallback_activated",
            "resolution": "Clinician ordered additional ECG and echocardiogram.",
            "resolution_timestamp": "2026-03-01T10:45:00Z",
            "impact_assessment": "No patient harm. Additional diagnostics confirmed clinician override was appropriate.",
            "follow_up_required": True,
            "follow_up_description": "Retrain model on expanded arrhythmia dataset.",
        },
        obligation_role="deployer",
        entity_refs=refs_deployer_actor,
        lifecycle_phase="deployment",
        collector={"name": "medassist-oversight-logger", "version": "2.1.0"},
        timestamp=TS_RECENT,
    )

    # ── governance_policy ──
    pkg.record(
        "governance_policy",
        provisions=["article-17"],
        payload={
            "policy_type": "qms_policy",
            "title": "HealthAI Quality Management System for AI-Enabled Medical Devices",
            "document_version": "4.0",
            "approval_date": "2025-09-01",
            "review_cycle": "annual",
            "next_review_date": "2026-09-01",
            "scope": "All AI-enabled medical devices developed and distributed by HealthAI Corp",
            "owner": "Maria Hoffman, Head of Regulatory Affairs",
            "approver": "Dr. Elena Vasquez, Chief Medical AI Officer",
        },
        obligation_role="provider",
        entity_refs=refs_subj,
        lifecycle_phase="deployment",
        collector=DEFAULT_COLLECTOR,
        attachments=[{
            "path": "artifacts/qms-policy-healthai-v4.pdf",
            "media_type": "application/pdf",
            "attachment_type": "qms_document",
            "description": "HealthAI QMS Policy v4.0",
        }],
        timestamp=TS_RECENT,
    )

    # ── transparency_disclosure ──
    pkg.record(
        "transparency_disclosure",
        provisions=["article-13"],
        payload={
            "disclosure_type": "instructions_for_use",
            "title": "MedAssist v3.2 Instructions for Use",
            "document_version": "3.2.1",
            "publication_date": "2025-12-01",
            "audience": ["deployers", "end_users"],
            "capabilities": ["Clinical diagnosis suggestion", "Differential diagnosis ranking", "Drug interaction screening"],
            "limitations": ["Not validated for pediatric patients under 18", "Performance degrades on non-English clinical notes"],
            "intended_use": "Aid licensed clinicians in differential diagnosis. Not intended for autonomous diagnosis.",
        },
        obligation_role="provider",
        entity_refs=refs_subj,
        lifecycle_phase="deployment",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    assessment = _export_and_validate(pkg, output, ["eu-ai-act-2024"])
    _print_assessment("eu-high-risk-core", assessment)


# ═══════════════════════════════════════════════════════════════════════
# GOLDEN BUNDLE 2: GPAI Provider Annex XI/XII
# ═══════════════════════════════════════════════════════════════════════


def build_gpai_provider_annex_xi_xii() -> None:
    """GPAI model documentation per Annex XI and XII."""
    output = GOLDEN_DIR / "gpai-provider-annex-xi-xii"
    _clean_dir(output)

    pkg = Package(producer={"name": "acef-golden-builder", "version": "1.0.0"})

    model = pkg.add_subject(
        "ai_model",
        name="Frontier-LLM-70B",
        version="2.0.0",
        provider="GenerativeAI Inc",
        risk_classification="gpai",
        modalities=["text"],
        lifecycle_phase="deployment",
    )

    training_dataset = pkg.add_dataset(
        "WebCorpus-2025", version="1.0", source_type="scraped", modality="text",
        size={"records": 15000000000, "size_gb": 8500.0}, subject_refs=[model.subject_id],
    )
    licensed_dataset = pkg.add_dataset(
        "Licensed-News-Archive", version="3.1", source_type="licensed", modality="text",
        size={"records": 850000000, "size_gb": 420.0}, subject_refs=[model.subject_id],
    )

    pkg.add_relationship(model.subject_id, training_dataset.dataset_id, "trains_on")
    pkg.add_relationship(model.subject_id, licensed_dataset.dataset_id, "trains_on")

    pkg.add_profile("eu-ai-act-2024", provisions=["article-53"])

    refs_model = {"subject_refs": [model.subject_id]}
    refs_ds = {"subject_refs": [model.subject_id], "dataset_refs": [training_dataset.dataset_id]}

    # ── evaluation_report: gpai_annex_xi_model_doc variant ──
    pkg.record(
        "evaluation_report",
        provisions=["article-53"],
        payload={
            "variant": "gpai_annex_xi_model_doc",
            "methodology": "Comprehensive evaluation per Annex XI covering model architecture, training data, compute resources, evaluation benchmarks, and known limitations",
            "evaluation_date": "2026-02-01",
            "model_description": {
                "release_date": "2026-01-15",
                "architecture": "decoder-only transformer with grouped-query attention and rotary position embeddings",
                "parameter_count": 70000000000,
                "modalities": ["text"],
                "context_length": 128000,
                "license": "Frontier-LLM Community License 2.0",
            },
            "training_data_summary": {
                "content_categories": ["web_text", "books", "code", "licensed_news", "scientific_papers"],
                "acquisition_channels": ["public_web_crawl", "licensed_feeds", "open_access_repositories"],
                "geographic_scope": ["global"],
                "languages": ["en", "de", "fr", "es", "zh", "ja", "ko", "pt", "it", "nl"],
                "quantitative_metrics": {"total_tokens": 15000000000000, "total_size_gb": 8920.0},
            },
            "compute_energy": {
                "compute_resources": {
                    "hardware_description": "4096 H100 GPUs in 512-node cluster",
                    "training_flops_estimate": "1.2e25",
                    "training_duration_hours": 2160.0,
                },
                "energy_consumption": {
                    "kwh_estimate": 3240000.0,
                    "estimation_method": "power_draw_telemetry",
                    "carbon_intensity_gco2eq_per_kwh": 85.0,
                    "scope": "training_only",
                    "uncertainty_range": "+/-12%",
                },
            },
            "evaluation_summary": {
                "red_teaming_performed": True,
                "key_metrics": {"mmlu": 0.847, "hellaswag": 0.912, "humaneval": 0.723},
                "evaluation_datasets": ["MMLU", "HellaSwag", "HumanEval", "TruthfulQA"],
                "independent_evaluator": "AI Safety Institute (AISI)",
            },
            "metrics": [
                {"metric_name": "mmlu", "value": 0.847, "threshold": 0.80, "unit": "percent"},
                {"metric_name": "hellaswag", "value": 0.912, "threshold": 0.85, "unit": "percent"},
            ],
            "results_summary": "Frontier-LLM-70B demonstrates strong performance across standard benchmarks.",
        },
        obligation_role="provider",
        entity_refs=refs_model,
        lifecycle_phase="deployment",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    # ── data_provenance ──
    pkg.record(
        "data_provenance",
        provisions=["article-53"],
        payload={
            "acquisition_method": "scraped",
            "source_uri": "https://commoncrawl.org/2025-Q1/",
            "source_uris": ["https://commoncrawl.org/2025-Q1/"],
            "source_description": "Common Crawl web archives supplemented with licensed news feeds",
            "legal_basis": "legitimate_interest",
            "source_type": "scraped",
            "opt_out_compliance": {
                "method": "robots_txt_and_http_headers",
                "verification_date": "2025-06-10",
                "exclusions_applied": 142857,
            },
        },
        obligation_role="provider",
        entity_refs=refs_ds,
        lifecycle_phase="development",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    # ── copyright_rights_reservation ──
    pkg.record(
        "copyright_rights_reservation",
        provisions=["article-53"],
        payload={
            "opt_out_detection_method": "robots_txt_and_tdmrep",
            "tdmrep_protocol_version": "1.0",
            "removal_process": "automated_pipeline_with_manual_review",
            "compliance_verification_date": "2025-06-10",
            "reserved_works_removed": 142857,
            "opt_out_signals_detected": 198432,
            "detection_methods": [
                {"method": "robots_txt", "signals_found": 156000, "coverage": "all_web_sources"},
                {"method": "tdmrep", "signals_found": 28432, "coverage": "top_10_percent_domains"},
            ],
            "crawler_identifiers": ["GenerativeAI-Bot/2.0"],
        },
        obligation_role="provider",
        entity_refs=refs_model,
        lifecycle_phase="development",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    # ── license_record ──
    pkg.record(
        "license_record",
        provisions=["article-53"],
        payload={
            "licensor": "Global News Syndicate",
            "content_type": "text",
            "license_type": "non-exclusive",
            "license_identifier": "GNS-AI-Training-2024",
            "scope": "Use of archived news articles for AI model training",
            "agreement_reference": "GNS-GENAI-2024-00742",
            "agreement_date": "2024-09-15",
            "expiration_date": "2027-09-14",
            "ai_training_permitted": True,
            "tdm_permitted": True,
            "attribution_required": True,
            "attribution_text": "Training data includes content licensed from Global News Syndicate",
        },
        obligation_role="provider",
        entity_refs={"subject_refs": [model.subject_id], "dataset_refs": [licensed_dataset.dataset_id]},
        lifecycle_phase="development",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    # ── transparency_disclosure: publication_evidence variant ──
    pkg.record(
        "transparency_disclosure",
        provisions=["article-53"],
        payload={
            "variant": "publication_evidence",
            "disclosure_type": "model_card",
            "title": "Frontier-LLM-70B Model Card and Technical Summary",
            "document_version": "2.0.0",
            "publication_date": "2026-01-20",
            "audience": ["deployers", "regulators", "public"],
            "summary_published": True,
            "publication_url": "https://generativeai.example.com/models/frontier-llm-70b/model-card",
            "publication_content_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb924",
        },
        obligation_role="provider",
        entity_refs=refs_model,
        lifecycle_phase="deployment",
        collector=DEFAULT_COLLECTOR,
        timestamp=TS_RECENT,
    )

    assessment = _export_and_validate(pkg, output, ["eu-ai-act-2024"])
    _print_assessment("gpai-provider-annex-xi-xii", assessment)


# ═══════════════════════════════════════════════════════════════════════
# GOLDEN BUNDLE 3: Synthetic Content Marking
# ═══════════════════════════════════════════════════════════════════════


def build_synthetic_content_marking() -> None:
    """EU Art. 50 and Labelling CoP synthetic content marking."""
    output = GOLDEN_DIR / "synthetic-content-marking"
    _clean_dir(output)

    pkg = Package(producer={"name": "acef-golden-builder", "version": "1.0.0"})

    system = pkg.add_subject(
        "ai_system", name="ContentGen Studio", version="5.0.0",
        provider="SynthMedia Corp", risk_classification="limited-risk",
        modalities=["image", "video", "text"], lifecycle_phase="deployment",
    )

    pkg.add_profile("eu-ai-act-2024", provisions=["article-50.2"])
    refs = {"subject_refs": [system.subject_id]}

    pkg.record("transparency_marking", provisions=["article-50.2"], payload={
        "modality": "image", "marking_scheme_id": "c2pa-content-credentials",
        "scheme_version": "2.3", "metadata_container": "xmp/c2pa-manifest-store",
        "watermark_applied": True, "watermark_family": "spectral_embedding",
        "jurisdiction": "EU", "marking_technique": "secure_metadata",
        "detection_confidence_threshold": 0.95,
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector={"name": "contentgen-marking-service", "version": "5.0.0"}, timestamp=TS_RECENT)

    pkg.record("transparency_marking", provisions=["article-50.2"], payload={
        "modality": "video", "marking_scheme_id": "c2pa-content-credentials",
        "scheme_version": "2.3", "metadata_container": "xmp/c2pa-manifest-store",
        "watermark_applied": True, "watermark_family": "robust-imperceptible",
        "jurisdiction": "EU", "marking_technique": "secure_metadata",
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector={"name": "contentgen-marking-service", "version": "5.0.0"}, timestamp=TS_RECENT)

    pkg.record("disclosure_labeling", provisions=["article-50.2"], payload={
        "disclosure_subtype": "deepfake", "label_type": "deepfake_disclosure",
        "presentation": "visible_icon_plus_text", "locale": "en-US",
        "disclosure_text": "This content was generated using AI.",
        "first_exposure_timestamp": "2026-03-01T00:00:00Z",
        "accessibility_standard_refs": ["WCAG-2.1-AA", "EN-301-549"],
    }, obligation_role="deployer", entity_refs=refs, lifecycle_phase="deployment",
    collector={"name": "contentgen-disclosure-service", "version": "5.0.0"}, timestamp=TS_RECENT)

    pkg.record("event_log", provisions=["article-50.2"], payload={
        "event_type": "marking", "correlation_id": "MRK-2026-03-01-00001",
        "session_id": "GEN-SES-20260301-00042", "system_state": "operational", "latency_ms": 23,
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector={"name": "contentgen-marking-service", "version": "5.0.0"}, timestamp=TS_RECENT)

    pkg.record("evaluation_report", provisions=["article-50.2"], payload={
        "variant": "mark_detectability_test",
        "methodology": "Automated detectability testing using adversarial transformations on 10,000 marked images and 1,000 marked videos",
        "evaluation_date": "2026-02-15",
        "marking_technique_tested": "C2PA + spectral watermark",
        "detection_accuracy": 0.974,
        "robustness_results": {"jpeg_compression_q40": 0.968, "crop_30_percent": 0.951, "social_media_recompression": 0.923},
        "metrics": [
            {"metric_name": "overall_detection_accuracy", "value": 0.974, "threshold": 0.90, "unit": "percent"},
            {"metric_name": "false_positive_rate", "value": 0.003, "threshold": 0.01, "unit": "percent"},
        ],
        "results_summary": "C2PA metadata and spectral watermark combination achieves 97.4% detection accuracy.",
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="testing",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    assessment = _export_and_validate(pkg, output, ["eu-ai-act-2024"])
    _print_assessment("synthetic-content-marking", assessment)


# ═══════════════════════════════════════════════════════════════════════
# GOLDEN BUNDLE 4: China CAC Labeling
# ═══════════════════════════════════════════════════════════════════════


def build_china_cac_labeling() -> None:
    """China CAC labeling measures with explicit + implicit labels."""
    output = GOLDEN_DIR / "china-cac-labeling"
    _clean_dir(output)

    pkg = Package(producer={"name": "acef-golden-builder", "version": "1.0.0"})

    system = pkg.add_subject(
        "ai_system", name="SmartChat CN", version="4.0.0",
        provider="SinoAI Technology Co., Ltd.", risk_classification="gpai",
        modalities=["text", "image"], lifecycle_phase="deployment",
    )

    pkg.add_profile("china-cac-labeling-2025", provisions=[
        "cac-explicit-label", "cac-implicit-metadata", "cac-watermark", "cac-log-retention",
    ])
    refs = {"subject_refs": [system.subject_id]}

    pkg.record("transparency_marking", provisions=["cac-implicit-metadata", "cac-watermark"], payload={
        "modality": "text", "marking_scheme_id": "cn-cac-implicit-label-2025",
        "scheme_version": "1.0", "metadata_container": "file-header",
        "watermark_applied": True, "watermark_family": "spectral_embedding",
        "verification_method_ref": "artifacts/cn-implicit-verification-tool.json",
        "jurisdiction": "CN",
        "implicit_label_fields": {
            "provider_id": "SINOAI-2025-00142", "content_id": "GENTEXT-20260301-874921",
            "content_type": "text", "reference_number": "CAC-REF-2026-874921",
        },
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector={"name": "smartchat-marking-service", "version": "4.0.0"}, timestamp=TS_RECENT)

    pkg.record("transparency_marking", provisions=["cac-implicit-metadata", "cac-watermark"], payload={
        "modality": "image", "marking_scheme_id": "cn-cac-implicit-label-2025",
        "scheme_version": "1.0", "metadata_container": "exif",
        "watermark_applied": True, "watermark_family": "robust-imperceptible",
        "verification_method_ref": "artifacts/cn-implicit-verification-tool.json",
        "jurisdiction": "CN",
        "implicit_label_fields": {
            "provider_id": "SINOAI-2025-00142", "content_id": "GENIMG-20260301-100234",
            "content_type": "image", "reference_number": "CAC-REF-2026-100234",
        },
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector={"name": "smartchat-marking-service", "version": "4.0.0"}, timestamp=TS_RECENT)

    pkg.record("disclosure_labeling", provisions=["cac-explicit-label"], payload={
        "disclosure_subtype": "public_interest_text", "label_type": "ai_generated_content_notice",
        "presentation": "text_superscript", "locale": "zh-CN",
        "disclosure_text": "\u672c\u5185\u5bb9\u7531\u4eba\u5de5\u667a\u80fd\u751f\u6210",
        "first_exposure_timestamp": "2026-03-01T08:00:00Z",
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector={"name": "smartchat-labeling-service", "version": "4.0.0"}, timestamp=TS_RECENT)

    pkg.record("event_log", provisions=["cac-log-retention"], payload={
        "event_type": "disclosure", "correlation_id": "DIS-CN-2026-03-01-00047",
        "session_id": "CHAT-CN-20260301-00012", "label_exception": True,
        "system_state": "operational", "retention_start_event": "record_creation",
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector={"name": "smartchat-logging-service", "version": "4.0.0"},
    retention={"min_retention_days": 180, "retention_start_event": "record_creation",
               "legal_basis": "CAC Labeling Measures Art. 14"},
    timestamp=TS_RECENT)

    pkg.record("event_log", provisions=["cac-log-retention"], payload={
        "event_type": "inference", "correlation_id": "INF-CN-2026-03-01-00048",
        "session_id": "CHAT-CN-20260301-00013", "label_exception": False,
        "system_state": "operational",
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector={"name": "smartchat-logging-service", "version": "4.0.0"}, timestamp=TS_RECENT)

    assessment = _export_and_validate(pkg, output, ["china-cac-labeling-2025"])
    _print_assessment("china-cac-labeling", assessment)


# ═══════════════════════════════════════════════════════════════════════
# GOLDEN BUNDLE 5: US Federal Governance
# ═══════════════════════════════════════════════════════════════════════


def build_us_federal_governance() -> None:
    """US Federal AI governance per OMB M-24-10 and NIST AI RMF."""
    output = GOLDEN_DIR / "us-federal-governance"
    _clean_dir(output)

    pkg = Package(producer={"name": "acef-golden-builder", "version": "1.0.0"})

    system = pkg.add_subject(
        "ai_system", name="FedBenefitsAssist", version="2.1.0",
        provider="Federal Benefits Administration", risk_classification="high-risk",
        modalities=["text", "multimodal"], lifecycle_phase="deployment",
    )

    pkg.add_profile("nist-ai-rmf-1.0", provisions=["govern-1", "map-1", "measure-1", "manage-1"])
    refs = {"subject_refs": [system.subject_id]}

    # Attachment
    pkg.add_attachment("governance-board-charter-fba.pdf",
                       b"[Federal Benefits Administration AI Governance Board Charter Document]")

    # ── governance_policy: ai_use_case_inventory_entry variant ──
    pkg.record("governance_policy", provisions=["govern-1"], payload={
        "variant": "ai_use_case_inventory_entry",
        "policy_type": "ai_use_case_inventory",
        "title": "FedBenefitsAssist - AI Use Case Inventory Entry per OMB M-24-10",
        "document_version": "2.0", "approval_date": "2025-11-01",
        "scope": "Automated benefits eligibility determination for federal assistance programs",
        "owner": "Chief AI Officer, Federal Benefits Administration",
        "system_purpose": "Automate initial eligibility screening for federal benefit programs",
        "decision_influence": "advisory", "rights_safety_impact": "rights_impacting",
        "impact_classification_rationale": "System influences access to federal benefits. Classified as rights-impacting per OMB M-24-10.",
        "responsible_owner": "Dr. Sarah Chen, Chief AI Officer",
        "caio_designation": "Dr. Sarah Chen, Chief AI Officer",
        "governance_board_ref": "artifacts/governance-board-charter-fba.pdf",
        "deployment_context": "production", "inventory_reporting_period": "2026-FY",
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector=DEFAULT_COLLECTOR,
    attachments=[{"path": "artifacts/governance-board-charter-fba.pdf", "media_type": "application/pdf",
                  "attachment_type": "governance_charter"}],
    timestamp=TS_RECENT)

    pkg.record("governance_policy", provisions=["govern-1"], payload={
        "policy_type": "ai_governance_policy",
        "title": "Federal Benefits Administration AI Governance Framework",
        "document_version": "3.0", "approval_date": "2025-08-15",
        "scope": "All AI systems developed and deployed by the Federal Benefits Administration",
        "owner": "Dr. Sarah Chen, Chief AI Officer",
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    pkg.record("risk_register", provisions=["map-1"], payload={
        "risk_id": "FBA-RISK-001",
        "description": "Algorithmic bias in benefits eligibility determination may disproportionately affect protected classes",
        "category": "fairness", "risk_category": "fairness",
        "likelihood": "possible", "severity": "major", "risk_level": "high",
        "assessment_method": "quantitative_model", "assessment_date": "2025-10-15",
        "status": "mitigated", "residual_risk_level": "low",
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    pkg.record("evaluation_report", provisions=["measure-1"], payload={
        "methodology": "Comprehensive evaluation using stratified testing across 12 demographic subgroups",
        "evaluation_date": "2025-10-20",
        "metrics": [
            {"metric_name": "accuracy", "value": 0.992, "threshold": 0.98, "unit": "percent"},
            {"metric_name": "demographic_parity_difference", "value": 0.018, "threshold": 0.05, "unit": "absolute_difference"},
        ],
        "reviewer": "GAO AI Assessment Team",
        "independent_evaluator": "GAO AI Assessment Team",
        "results_summary": "FedBenefitsAssist v2.1 demonstrates strong accuracy and fairness across all tested subgroups.",
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="testing",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    pkg.record("risk_treatment", provisions=["manage-1"], payload={
        "risk_id": "FBA-RISK-001", "treatment_type": "mitigate",
        "control_description": "Multi-layered bias mitigation: pre-processing demographic parity sampling, in-processing adversarial debiasing, post-processing threshold calibration, and mandatory human review for all denials",
        "implementation_status": "verified", "implementation_date": "2025-09-01",
        "responsible_party": "ML Engineering Lead, Federal Benefits Administration",
        "effectiveness_rating": "highly_effective",
        "verification_method": "Independent audit by GAO AI Assessment Team",
        "verification_date": "2025-10-25",
        "residual_risk_after_treatment": "low",
    }, obligation_role="provider", entity_refs=refs, lifecycle_phase="deployment",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    assessment = _export_and_validate(pkg, output, ["nist-ai-rmf-1.0"])
    _print_assessment("us-federal-governance", assessment)


# ═══════════════════════════════════════════════════════════════════════
# GOLDEN BUNDLE 6: Multi-Subject Composed
# ═══════════════════════════════════════════════════════════════════════


def build_multi_subject_composed() -> None:
    """Two subjects (ai_system + ai_model) with shared components."""
    output = GOLDEN_DIR / "multi-subject-composed"
    _clean_dir(output)

    pkg = Package(producer={"name": "acef-golden-builder", "version": "1.0.0"})

    system = pkg.add_subject(
        "ai_system", name="InsightAnalytics Platform", version="4.0.0",
        provider="DataInsight Corp", risk_classification="high-risk",
        modalities=["text", "multimodal"], lifecycle_phase="deployment",
    )
    model = pkg.add_subject(
        "ai_model", name="InsightBERT-Large", version="2.0.0",
        provider="DataInsight Corp", risk_classification="gpai",
        modalities=["text"], lifecycle_phase="deployment",
    )

    shared_db = pkg.add_component(
        "InsightVectorDB", "database", version="3.0.0",
        subject_refs=[system.subject_id, model.subject_id], provider="DataInsight Corp",
    )
    retriever = pkg.add_component(
        "InsightRetriever", "retriever", version="2.5.0",
        subject_refs=[system.subject_id], provider="DataInsight Corp",
    )
    dataset = pkg.add_dataset(
        "Enterprise-Corpus-2025", version="1.0", source_type="licensed", modality="text",
        size={"records": 50000000, "size_gb": 120.0}, subject_refs=[model.subject_id],
    )

    pkg.add_relationship(system.subject_id, model.subject_id, "wraps")
    pkg.add_relationship(system.subject_id, retriever.component_id, "calls")
    pkg.add_relationship(retriever.component_id, shared_db.component_id, "calls")
    pkg.add_relationship(model.subject_id, dataset.dataset_id, "trains_on")

    pkg.add_profile("eu-ai-act-2024", provisions=["article-9", "article-10", "article-11", "article-13", "article-53"])
    pkg.add_profile("nist-ai-rmf-1.0", provisions=["govern-1", "map-1", "measure-1"])

    refs_sys = {"subject_refs": [system.subject_id]}
    refs_model = {"subject_refs": [model.subject_id]}
    refs_both = {"subject_refs": [system.subject_id, model.subject_id]}
    refs_both_ds = {"subject_refs": [system.subject_id, model.subject_id], "dataset_refs": [dataset.dataset_id]}

    # System risk_register with management_review (for Art. 9)
    pkg.add_attachment("pmp-insight.pdf", b"[Post-Market Monitoring Plan for InsightAnalytics]")
    pkg.record("risk_register", provisions=["article-9"], payload={
        "risk_id": "SYS-RISK-001", "description": "Hallucination risk in RAG pipeline",
        "category": "reliability", "review_type": "management_review",
        "review_date": "2026-02-01",
        "review_attendees": ["CTO", "VP Engineering", "Head of AI Safety"],
        "review_decisions": ["Implement retrieval confidence scoring"],
        "review_signatories": ["CTO", "VP Engineering"],
    }, obligation_role="provider", entity_refs=refs_both, lifecycle_phase="deployment",
    collector=DEFAULT_COLLECTOR,
    attachments=[{"path": "artifacts/pmp-insight.pdf", "media_type": "application/pdf",
                  "attachment_type": "post_market_monitoring_plan"}],
    timestamp=TS_RECENT)

    pkg.record("risk_treatment", provisions=["article-9"], payload={
        "risk_id": "SYS-RISK-001", "treatment_type": "mitigate",
        "control_description": "Retrieval confidence scoring with threshold-based human review",
        "implementation_status": "implemented",
    }, obligation_role="provider", entity_refs=refs_both, lifecycle_phase="deployment",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    # Model data_provenance (for Art. 10 and Art. 53)
    pkg.record("data_provenance", provisions=["article-10", "article-53"], payload={
        "acquisition_method": "licensed", "source_uri": "https://enterprise-data-consortium.example.com/corpus/2025/",
        "source_uris": ["https://enterprise-data-consortium.example.com/corpus/2025/"],
        "source_description": "Licensed enterprise corpus covering business documents",
        "legal_basis": "license", "source_type": "licensed",
    }, obligation_role="provider", entity_refs=refs_both_ds, lifecycle_phase="development",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    pkg.record("dataset_card", provisions=["article-10"], payload={
        "dataset_name": "Enterprise Corpus 2025", "dataset_version": "1.0",
        "source": "Enterprise Data Consortium", "modality": "text", "purpose": "training",
        "size": {"records": 50000000, "size_gb": 120.0},
        "representativeness_assessment": "Corpus covers 15 industry verticals with balanced representation.",
        "license": "Enterprise Data Consortium License v2.0",
    }, obligation_role="provider", entity_refs=refs_both_ds, lifecycle_phase="development",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    pkg.record("copyright_rights_reservation", provisions=["article-53"], payload={
        "opt_out_detection_method": "robots_txt_and_tdmrep",
        "compliance_verification_date": "2025-05-01",
        "reserved_works_removed": 0, "opt_out_signals_detected": 0,
        "removal_process": "No removal required; all data is licensed with explicit AI training permissions",
    }, obligation_role="provider", entity_refs=refs_model, lifecycle_phase="development",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    pkg.record("evaluation_report", provisions=["article-11", "article-53"], payload={
        "methodology": "End-to-end evaluation of InsightAnalytics Platform including underlying InsightBERT-Large model",
        "metrics": [
            {"metric_name": "answer_accuracy", "value": 0.921, "threshold": 0.85, "unit": "percent"},
            {"metric_name": "faithfulness", "value": 0.934, "threshold": 0.90, "unit": "percent"},
        ],
        "results_summary": "Platform and model exceed all performance thresholds.",
        "reviewer": "Internal AI Safety Review Board",
    }, obligation_role="provider", entity_refs=refs_both, lifecycle_phase="testing",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    pkg.record("transparency_disclosure", provisions=["article-13"], payload={
        "disclosure_type": "instructions_for_use",
        "title": "InsightAnalytics Platform - Instructions for Use",
        "document_version": "4.0.0", "publication_date": "2025-12-15",
        "audience": ["deployers"],
        "capabilities": ["Enterprise document analysis", "Financial report interpretation"],
        "limitations": ["Healthcare and defense domain accuracy not validated"],
        "intended_use": "Enterprise analytics platform for business document analysis",
    }, obligation_role="provider", entity_refs=refs_both, lifecycle_phase="deployment",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    pkg.record("governance_policy", provisions=["govern-1"], payload={
        "policy_type": "ai_governance_policy",
        "title": "DataInsight Corp AI Governance and Risk Management Policy",
        "document_version": "2.0", "approval_date": "2025-10-01",
        "scope": "All AI systems and models developed by DataInsight Corp",
        "owner": "VP of AI Safety",
    }, obligation_role="provider", entity_refs=refs_both, lifecycle_phase="deployment",
    collector=DEFAULT_COLLECTOR, timestamp=TS_RECENT)

    assessment = _export_and_validate(pkg, output, ["eu-ai-act-2024", "nist-ai-rmf-1.0"])
    _print_assessment("multi-subject-composed", assessment)


# ═══════════════════════════════════════════════════════════════════════
# TEST VECTORS: EU AI Act
# ═══════════════════════════════════════════════════════════════════════


def build_eu_test_vectors() -> None:
    """Build 10 test vectors for EU AI Act template."""
    base = VECTORS_DIR / "eu-ai-act"
    _clean_dir(base)
    profiles = ["eu-ai-act-2024"]

    # ── 1. article-9-minimal-pass ──
    def art9_pass():
        out = base / "article-9-minimal-pass.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="MinimalRiskSystem", risk_classification="high-risk",
                            modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-9"])
        refs = {"subject_refs": [s.subject_id]}

        pkg.add_attachment("pmp.pdf", b"[Post-Market Monitoring Plan]")
        pkg.record("risk_register", provisions=["article-9"], payload={
            "risk_id": "R-001", "description": "Bias risk in scoring", "category": "fairness",
            "review_type": "management_review", "review_date": "2026-02-01",
            "review_attendees": ["CTO"], "review_decisions": ["Accept"],
            "review_signatories": ["CTO"],
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="monitoring",
        collector=TV_COLLECTOR,
        attachments=[{"path": "artifacts/pmp.pdf", "media_type": "application/pdf",
                      "attachment_type": "post_market_monitoring_plan"}],
        timestamp=TS_RECENT)

        pkg.record("risk_treatment", provisions=["article-9"], payload={
            "risk_id": "R-001", "treatment_type": "mitigate",
            "control_description": "Bias mitigation via resampling",
            "implementation_status": "verified",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("article-9-minimal-pass", a)

    # ── 2. article-9-minimal-fail ──
    def art9_fail():
        out = base / "article-9-minimal-fail.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        pkg.add_subject("ai_system", name="IncompleteSystem", risk_classification="high-risk",
                        modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-9"])
        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("article-9-minimal-fail", a)

    # ── 3. article-9-variant-management-review-pass ──
    def art9_variant_pass():
        out = base / "article-9-variant-management-review-pass.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="ReviewedSystem", risk_classification="high-risk",
                            modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-9"])
        refs = {"subject_refs": [s.subject_id]}

        pkg.add_attachment("pmmp.pdf", b"[PMMP Doc]")
        pkg.record("risk_register", provisions=["article-9"], payload={
            "risk_id": "R-010", "description": "Data drift risk", "category": "reliability",
            "review_type": "management_review", "review_date": "2026-01-15",
            "review_attendees": ["VP Eng", "CISO"], "review_decisions": ["Enhance monitoring"],
            "review_signatories": ["VP Eng", "CISO"],
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="monitoring",
        collector=TV_COLLECTOR,
        attachments=[{"path": "artifacts/pmmp.pdf", "media_type": "application/pdf",
                      "attachment_type": "post_market_monitoring_plan"}],
        timestamp=TS_RECENT)

        pkg.record("risk_treatment", provisions=["article-9"], payload={
            "risk_id": "R-010", "treatment_type": "reduce",
            "control_description": "Automated drift detection pipeline with weekly retraining",
            "implementation_status": "implemented",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("article-9-variant-management-review-pass", a)

    # ── 4. article-12-logging-spec-pass ──
    def art12_pass():
        out = base / "article-12-logging-spec-pass.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="LoggedSystem", risk_classification="high-risk",
                            modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-12"])
        refs = {"subject_refs": [s.subject_id]}

        pkg.record("event_log", provisions=["article-12"], payload={
            "event_type": "logging_spec", "correlation_id": "LOGSPEC-001",
            "logged_event_types": ["inference", "error"],
            "traceability_rationale": "Captures all inference events for Art. 12 traceability",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("event_log", provisions=["article-12"], payload={
            "event_type": "inference", "correlation_id": "INF-001",
        }, entity_refs=refs, obligation_role="deployer", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("article-12-logging-spec-pass", a)

    # ── 5. article-12-retention-fail ──
    def art12_fail():
        out = base / "article-12-retention-fail.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        pkg.add_subject("ai_system", name="NoLogSystem", risk_classification="high-risk",
                        modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-12"])
        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("article-12-retention-fail", a)

    # ── 6. article-50-marking-pass ──
    def art50_pass():
        out = base / "article-50-marking-pass.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="MarkedSystem", risk_classification="limited-risk",
                            modalities=["image"], provider="TestProvider Inc")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-50.2"])
        refs = {"subject_refs": [s.subject_id]}

        pkg.record("transparency_marking", provisions=["article-50.2"], payload={
            "modality": "image", "marking_scheme_id": "c2pa-content-credentials",
            "scheme_version": "2.3", "metadata_container": "xmp/c2pa-manifest-store",
            "watermark_applied": True, "jurisdiction": "EU",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("article-50-marking-pass", a)

    # ── 7. article-50-marking-no-scheme-id-fail ──
    def art50_fail():
        out = base / "article-50-marking-no-scheme-id-fail.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="BadMarkingSystem", risk_classification="limited-risk",
                            modalities=["image"], provider="TestProvider Inc")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-50.2"])
        refs = {"subject_refs": [s.subject_id]}

        # transparency_marking WITHOUT marking_scheme_id -> should fail
        pkg.record("transparency_marking", provisions=["article-50.2"], payload={
            "modality": "image", "scheme_version": "2.3",
            "metadata_container": "xmp/c2pa-manifest-store", "watermark_applied": False,
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("article-50-marking-no-scheme-id-fail", a)

    # ── 8. article-53-annex-xi-pass ──
    def art53_pass():
        out = base / "article-53-annex-xi-pass.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_model", name="GPAIModel", risk_classification="gpai",
                            modalities=["text"], provider="TestProvider Inc")
        d = pkg.add_dataset("TrainingData", source_type="scraped", modality="text",
                            subject_refs=[s.subject_id])
        pkg.add_profile("eu-ai-act-2024", provisions=["article-53"])
        refs = {"subject_refs": [s.subject_id]}
        refs_ds = {"subject_refs": [s.subject_id], "dataset_refs": [d.dataset_id]}

        pkg.record("data_provenance", provisions=["article-53"], payload={
            "acquisition_method": "scraped", "source_uri": "https://data.example.com/corpus",
            "source_type": "scraped",
        }, entity_refs=refs_ds, obligation_role="provider", lifecycle_phase="development",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("copyright_rights_reservation", provisions=["article-53"], payload={
            "opt_out_detection_method": "robots_txt_and_tdmrep",
            "compliance_verification_date": "2025-06-01",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="development",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("evaluation_report", provisions=["article-53"], payload={
            "variant": "gpai_annex_xi_model_doc",
            "methodology": "Comprehensive Annex XI evaluation",
            "model_description": {
                "architecture": "transformer", "parameter_count": 7000000000,
                "modalities": ["text"], "context_length": 32000,
            },
            "compute_energy": {
                "energy_consumption": {"kwh_estimate": 500000.0, "estimation_method": "measured"},
            },
            "metrics": [{"metric_name": "mmlu", "value": 0.78, "unit": "percent"}],
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("article-53-annex-xi-pass", a)

    # ── 9. article-53-annex-xi-missing-energy-fail ──
    def art53_fail():
        out = base / "article-53-annex-xi-missing-energy-fail.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        pkg.add_subject("ai_model", name="IncompleteGPAI", risk_classification="gpai",
                        modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-53"])
        # Missing data_provenance and copyright_rights_reservation -> should fail
        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("article-53-annex-xi-missing-energy-fail", a)

    # ── 10. multi-subject-per-subject-eval ──
    def multi_subject():
        out = base / "multi-subject-per-subject-eval.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        sys_subj = pkg.add_subject("ai_system", name="MultiSubSys", risk_classification="high-risk",
                                   modalities=["text"], provider="TestProvider Inc")
        mdl_subj = pkg.add_subject("ai_model", name="MultiSubModel", risk_classification="gpai",
                                   modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("eu-ai-act-2024", provisions=["article-9", "article-53"])

        pkg.add_attachment("pmp-ms.pdf", b"[PMP for multi-subject]")
        pkg.record("risk_register", provisions=["article-9"], payload={
            "risk_id": "MS-R-001", "description": "System-level risk", "category": "safety",
            "review_type": "management_review", "review_date": "2026-01-01",
            "review_attendees": ["CTO"], "review_decisions": ["Mitigate"],
            "review_signatories": ["CTO"],
        }, entity_refs={"subject_refs": [sys_subj.subject_id]}, obligation_role="provider",
        lifecycle_phase="monitoring", collector=TV_COLLECTOR,
        attachments=[{"path": "artifacts/pmp-ms.pdf", "media_type": "application/pdf",
                      "attachment_type": "post_market_monitoring_plan"}],
        timestamp=TS_RECENT)

        pkg.record("risk_treatment", provisions=["article-9"], payload={
            "risk_id": "MS-R-001", "treatment_type": "mitigate",
            "control_description": "System-level guardrails",
            "implementation_status": "implemented",
        }, entity_refs={"subject_refs": [sys_subj.subject_id]}, obligation_role="provider",
        lifecycle_phase="deployment", collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("data_provenance", provisions=["article-53"], payload={
            "acquisition_method": "licensed", "source_uri": "https://data.example.com",
            "source_type": "licensed",
        }, entity_refs={"subject_refs": [mdl_subj.subject_id]}, obligation_role="provider",
        lifecycle_phase="development", collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("copyright_rights_reservation", provisions=["article-53"], payload={
            "opt_out_detection_method": "manual_review",
        }, entity_refs={"subject_refs": [mdl_subj.subject_id]}, obligation_role="provider",
        lifecycle_phase="development", collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("multi-subject-per-subject-eval", a)

    art9_pass()
    art9_fail()
    art9_variant_pass()
    art12_pass()
    art12_fail()
    art50_pass()
    art50_fail()
    art53_pass()
    art53_fail()
    multi_subject()


# ═══════════════════════════════════════════════════════════════════════
# TEST VECTORS: China CAC
# ═══════════════════════════════════════════════════════════════════════


def build_china_cac_test_vectors() -> None:
    """Build 3 test vectors for China CAC template."""
    base = VECTORS_DIR / "china-cac"
    _clean_dir(base)
    profiles = ["china-cac-labeling-2025"]

    def cac_pass():
        out = base / "cac-explicit-implicit-pass.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="CACCompliantSystem", risk_classification="gpai",
                            modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("china-cac-labeling-2025", provisions=[
            "cac-explicit-label", "cac-implicit-metadata", "cac-watermark", "cac-log-retention",
        ])
        refs = {"subject_refs": [s.subject_id]}

        pkg.record("transparency_marking", provisions=["cac-implicit-metadata"], payload={
            "modality": "text", "marking_scheme_id": "cn-cac-implicit-label-2025",
            "scheme_version": "1.0", "metadata_container": "file-header",
            "watermark_applied": True, "watermark_family": "spectral_embedding",
            "jurisdiction": "CN",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("disclosure_labeling", provisions=["cac-explicit-label"], payload={
            "disclosure_subtype": "public_interest_text", "label_type": "ai_generated_notice",
            "presentation": "text_superscript", "locale": "zh-CN",
            "disclosure_text": "\u672c\u5185\u5bb9\u7531\u4eba\u5de5\u667a\u80fd\u751f\u6210",
            "first_exposure_timestamp": "2026-03-01T08:00:00Z",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("event_log", provisions=["cac-log-retention"], payload={
            "event_type": "inference", "correlation_id": "CAC-INF-001",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("cac-explicit-implicit-pass", a)

    def cac_fail():
        out = base / "cac-missing-implicit-metadata-fail.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="CACIncompleteSystem", risk_classification="gpai",
                            modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("china-cac-labeling-2025", provisions=[
            "cac-explicit-label", "cac-implicit-metadata", "cac-log-retention",
        ])
        refs = {"subject_refs": [s.subject_id]}

        pkg.record("disclosure_labeling", provisions=["cac-explicit-label"], payload={
            "disclosure_subtype": "public_interest_text", "label_type": "ai_generated_notice",
            "presentation": "text_superscript", "locale": "zh-CN",
            "disclosure_text": "AI\u751f\u6210",
            "first_exposure_timestamp": "2026-03-01T08:00:00Z",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("event_log", provisions=["cac-log-retention"], payload={
            "event_type": "inference", "correlation_id": "CAC-INF-002",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)
        # NO transparency_marking -> cac-implicit-metadata fails

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("cac-missing-implicit-metadata-fail", a)

    def cac_exception_pass():
        out = base / "cac-label-exception-retention-pass.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="CACExceptionSystem", risk_classification="gpai",
                            modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("china-cac-labeling-2025", provisions=[
            "cac-explicit-label", "cac-implicit-metadata", "cac-watermark", "cac-log-retention",
        ])
        refs = {"subject_refs": [s.subject_id]}

        pkg.record("transparency_marking", provisions=["cac-implicit-metadata", "cac-watermark"], payload={
            "modality": "text", "marking_scheme_id": "cn-cac-implicit-label-2025",
            "scheme_version": "1.0", "metadata_container": "file-header",
            "watermark_applied": True, "watermark_family": "spectral_embedding",
            "verification_method_ref": "artifacts/cn-verify.json", "jurisdiction": "CN",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("disclosure_labeling", provisions=["cac-explicit-label"], payload={
            "disclosure_subtype": "public_interest_text", "label_type": "ai_generated_notice",
            "presentation": "visible_icon_plus_text", "locale": "zh-CN",
            "disclosure_text": "\u672c\u5185\u5bb9\u7531\u4eba\u5de5\u667a\u80fd\u751f\u6210",
            "first_exposure_timestamp": "2026-03-01T08:00:00Z",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("event_log", provisions=["cac-log-retention"], payload={
            "event_type": "disclosure", "correlation_id": "CAC-EXC-001",
            "label_exception": True,
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR,
        retention={"min_retention_days": 180, "retention_start_event": "record_creation",
                   "legal_basis": "CAC Art. 14"},
        timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("cac-label-exception-retention-pass", a)

    cac_pass()
    cac_fail()
    cac_exception_pass()


# ═══════════════════════════════════════════════════════════════════════
# TEST VECTORS: NIST RMF
# ═══════════════════════════════════════════════════════════════════════


def build_nist_test_vectors() -> None:
    """Build 2 test vectors for NIST AI RMF template."""
    base = VECTORS_DIR / "nist-rmf"
    _clean_dir(base)
    profiles = ["nist-ai-rmf-1.0"]

    def nist_pass():
        out = base / "govern-map-measure-manage-pass.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="NISTPlatform", risk_classification="high-risk",
                            modalities=["text"], provider="TestProvider Inc")
        d = pkg.add_dataset("NISTTrainData", source_type="licensed", modality="tabular",
                            subject_refs=[s.subject_id])
        pkg.add_profile("nist-ai-rmf-1.0", provisions=["govern-1", "map-1", "map-2", "measure-1", "manage-1", "manage-4"])
        refs = {"subject_refs": [s.subject_id]}
        refs_ds = {"subject_refs": [s.subject_id], "dataset_refs": [d.dataset_id]}

        pkg.add_attachment("nist-gov.pdf", b"[NIST Gov Policy]")
        pkg.record("governance_policy", provisions=["govern-1"], payload={
            "policy_type": "ai_governance_policy", "title": "NIST RMF Governance Framework",
            "document_version": "1.0", "approval_date": "2025-06-01",
            "scope": "All AI systems", "owner": "Chief AI Officer",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR,
        attachments=[{"path": "artifacts/nist-gov.pdf", "media_type": "application/pdf"}],
        timestamp=TS_RECENT)

        pkg.record("risk_register", provisions=["map-1"], payload={
            "risk_id": "NIST-R-001", "description": "Model accuracy degradation",
            "category": "reliability", "risk_category": "reliability",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("dataset_card", provisions=["map-2"], payload={
            "dataset_name": "NISTTrainData", "dataset_version": "1.0",
            "source": "Internal data lake", "modality": "tabular",
        }, entity_refs=refs_ds, obligation_role="provider", lifecycle_phase="development",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("data_provenance", provisions=["map-2"], payload={
            "acquisition_method": "licensed", "source_uri": "https://internal.example.com/data",
        }, entity_refs=refs_ds, obligation_role="provider", lifecycle_phase="development",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("evaluation_report", provisions=["measure-1"], payload={
            "methodology": "Comprehensive evaluation per NIST MEASURE",
            "metrics": [{"metric_name": "accuracy", "value": 0.95, "unit": "percent"}],
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="testing",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("risk_treatment", provisions=["manage-1"], payload={
            "risk_id": "NIST-R-001", "treatment_type": "mitigate",
            "control_description": "Automated retraining pipeline",
            "implementation_status": "verified",
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        pkg.record("incident_report", provisions=["manage-4"], payload={
            "incident_type": "operational_failure", "severity": "minor",
            "description": "Transient latency spike during peak load causing 50ms additional delay",
            "corrective_actions": [
                {"action": "Scaled inference cluster", "status": "completed", "responsible_party": "SRE Team"},
            ],
        }, entity_refs=refs, obligation_role="provider", lifecycle_phase="deployment",
        collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("govern-map-measure-manage-pass", a)

    def nist_fail():
        out = base / "govern-missing-policy-fail.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        pkg.add_subject("ai_system", name="NoPolicySystem", risk_classification="high-risk",
                        modalities=["text"], provider="TestProvider Inc")
        pkg.add_profile("nist-ai-rmf-1.0", provisions=["govern-1"])
        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("govern-missing-policy-fail", a)

    nist_pass()
    nist_fail()



# ═══════════════════════════════════════════════════════════════════════
# TEST VECTORS: OMB M-24-10
# ═══════════════════════════════════════════════════════════════════════


def build_omb_test_vectors() -> None:
    """Build 2 test vectors for OMB M-24-10 template."""
    base = VECTORS_DIR / "omb-m24-10"
    _clean_dir(base)
    profiles = ["us-omb-m-24-10"]

    def omb_pass():
        out = base / "inventory-governance-pass.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="FederalBenefitsClassifier",
                            risk_classification="high-risk", modalities=["text"],
                            provider="US Federal Agency",
                            lifecycle_phase="deployment")
        oversight_actor = pkg.add_actor(
            name="Dr. Sarah Chen", role="provider",
            organization="US Federal Agency",
        )
        pkg.add_profile("us-omb-m-24-10",
                        provisions=["omb-inventory", "omb-caio", "omb-rights-safety", "omb-governance"])
        refs = {"subject_refs": [s.subject_id]}
        refs_actor = {"subject_refs": [s.subject_id], "actor_refs": [oversight_actor.actor_id]}

        pkg.add_attachment("ai-governance-framework.pdf",
                           b"[AI Governance Framework Document - Federal Agency]")

        # governance_policy: ai_use_case_inventory_entry variant with all required fields
        pkg.record("governance_policy", provisions=["omb-inventory", "omb-caio", "omb-rights-safety"],
                   payload={
                       "variant": "ai_use_case_inventory_entry",
                       "policy_type": "ai_use_case_inventory",
                       "title": "FederalBenefitsClassifier AI Use-Case Inventory Entry",
                       "system_purpose": "Automated classification of federal benefit applications to route to appropriate review teams based on complexity and eligibility criteria",
                       "decision_influence": "advisory",
                       "rights_safety_impact": "rights_impacting",
                       "impact_classification_rationale": "System influences decisions about federal benefit eligibility which has material impact on individuals access to government services and financial assistance",
                       "responsible_owner": oversight_actor.actor_id,
                       "caio_designation": "Dr. Sarah Chen, Chief AI Officer",
                       "governance_board_ref": "AI Governance Board Charter v2.0",
                       "model_version": "2.1.0",
                       "deployment_context": "production",
                       "last_review_date": "2026-02-15",
                       "inventory_reporting_period": "2026-FY",
                   },
                   entity_refs=refs_actor, obligation_role="provider",
                   lifecycle_phase="deployment",
                   collector=TV_COLLECTOR, timestamp=TS_RECENT)

        # governance_policy: governance framework document
        pkg.record("governance_policy", provisions=["omb-governance"],
                   payload={
                       "policy_type": "ai_governance_policy",
                       "title": "Federal Agency AI Governance Framework",
                       "document_version": "2.0",
                       "approval_date": "2025-09-01",
                       "scope": "All AI systems deployed or procured by the agency",
                       "owner": "Dr. Sarah Chen, Chief AI Officer",
                       "caio_designation": "Dr. Sarah Chen, Chief AI Officer",
                       "rights_safety_impact": "rights_impacting",
                       "impact_classification_rationale": "Agency governance framework applies to all AI systems including those with rights-impacting classification per OMB M-24-10",
                   },
                   entity_refs=refs, obligation_role="provider",
                   lifecycle_phase="deployment",
                   collector=TV_COLLECTOR,
                   attachments=[{"path": "artifacts/ai-governance-framework.pdf",
                                 "media_type": "application/pdf",
                                 "description": "Federal Agency AI Governance Framework v2.0"}],
                   timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("inventory-governance-pass", a)

    def omb_fail():
        out = base / "missing-caio-fail.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_system", name="NoInventorySystem",
                            risk_classification="high-risk", modalities=["text"],
                            provider="US Federal Agency",
                            lifecycle_phase="deployment")
        pkg.add_profile("us-omb-m-24-10",
                        provisions=["omb-inventory", "omb-caio", "omb-rights-safety", "omb-governance"])
        refs = {"subject_refs": [s.subject_id]}

        # governance_policy WITHOUT the ai_use_case_inventory_entry variant
        # This should fail omb-inv-inventory-variant rule
        pkg.record("governance_policy", provisions=["omb-governance"],
                   payload={
                       "policy_type": "ai_governance_policy",
                       "title": "Basic Governance Policy",
                       "document_version": "1.0",
                       "scope": "All AI systems",
                       "owner": "Agency Director",
                   },
                   entity_refs=refs, obligation_role="provider",
                   lifecycle_phase="deployment",
                   collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("missing-caio-fail", a)

    omb_pass()
    omb_fail()


# ═══════════════════════════════════════════════════════════════════════
# TEST VECTORS: EU GPAI Code of Practice
# ═══════════════════════════════════════════════════════════════════════


def build_gpai_cop_test_vectors() -> None:
    """Build 2 test vectors for EU GPAI Code of Practice template."""
    base = VECTORS_DIR / "eu-gpai-cop"
    _clean_dir(base)
    profiles = ["eu-gpai-code-of-practice-2025"]

    def gpai_cop_pass():
        out = base / "transparency-copyright-pass.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_model", name="GPAICoPModel",
                            risk_classification="gpai", modalities=["text"],
                            provider="EUModelProvider Inc",
                            lifecycle_phase="deployment")
        d = pkg.add_dataset("WebTrainingCorpus", source_type="scraped", modality="text",
                            size={"records": 5000000000, "size_gb": 2400.0},
                            subject_refs=[s.subject_id])
        licensed_ds = pkg.add_dataset("LicensedNewsArchive", source_type="licensed", modality="text",
                                      size={"records": 500000000, "size_gb": 200.0},
                                      subject_refs=[s.subject_id])
        pkg.add_relationship(s.subject_id, d.dataset_id, "trains_on")
        pkg.add_relationship(s.subject_id, licensed_ds.dataset_id, "trains_on")
        pkg.add_profile("eu-gpai-code-of-practice-2025",
                        provisions=["gpai-transparency-1", "gpai-transparency-2",
                                    "gpai-copyright-1", "gpai-copyright-2"])
        refs = {"subject_refs": [s.subject_id]}
        refs_ds = {"subject_refs": [s.subject_id], "dataset_refs": [d.dataset_id]}
        refs_lic_ds = {"subject_refs": [s.subject_id], "dataset_refs": [licensed_ds.dataset_id]}

        # data_provenance: training data summary
        pkg.record("data_provenance", provisions=["gpai-transparency-1", "gpai-transparency-2"],
                   payload={
                       "summary_type": "training_data_summary",
                       "source_type": "scraped",
                       "source_uri": "https://corpus.example.com/webcrawl-2025",
                       "source_uris": [
                           "https://corpus.example.com/webcrawl-2025",
                           "https://commoncrawl.org/2025",
                       ],
                       "acquisition_method": "scraped",
                       "modalities": ["text"],
                       "total_records": 5000000000,
                       "total_size_gb": 2400.0,
                       "language_coverage": ["en", "fr", "de", "es", "zh"],
                       "content_categories": ["web_pages", "news_articles", "academic_papers"],
                       "processing_steps": [
                           "Deduplication via MinHash LSH",
                           "Quality filtering via perplexity score",
                           "PII removal pipeline",
                       ],
                   },
                   entity_refs=refs_ds, obligation_role="provider",
                   lifecycle_phase="development",
                   collector=TV_COLLECTOR, timestamp=TS_RECENT)

        # copyright_rights_reservation
        pkg.record("copyright_rights_reservation", provisions=["gpai-copyright-1"],
                   payload={
                       "opt_out_detection_method": "robots_txt_and_tdmrep",
                       "compliance_verification_date": "2025-07-15",
                       "tdmrep_version": "1.0",
                       "opted_out_domains_count": 42850,
                       "removal_process": "Automated weekly re-crawl of robots.txt and TDMRep signals with batch removal from training pipeline",
                   },
                   entity_refs=refs, obligation_role="provider",
                   lifecycle_phase="development",
                   collector=TV_COLLECTOR, timestamp=TS_RECENT)

        # license_record
        pkg.record("license_record", provisions=["gpai-copyright-2"],
                   payload={
                       "licensor": "Global News Syndicate",
                       "scope": "Training and fine-tuning of generative AI models for commercial use",
                       "content_type": "news_articles",
                       "license_type": "non-exclusive",
                       "agreement_date": "2024-11-01",
                       "expiration_date": "2027-10-31",
                       "restrictions": ["No verbatim reproduction in model outputs", "Attribution required in training data summaries"],
                   },
                   entity_refs=refs_lic_ds, obligation_role="provider",
                   lifecycle_phase="development",
                   collector=TV_COLLECTOR, timestamp=TS_RECENT)

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("transparency-copyright-pass", a)

    def gpai_cop_fail():
        out = base / "missing-training-summary-fail.acef"
        pkg = Package(producer={"name": "acef-test-vector-builder", "version": "1.0.0"})
        s = pkg.add_subject("ai_model", name="NoSummaryModel",
                            risk_classification="gpai", modalities=["text"],
                            provider="EUModelProvider Inc",
                            lifecycle_phase="deployment")
        pkg.add_profile("eu-gpai-code-of-practice-2025",
                        provisions=["gpai-transparency-1", "gpai-transparency-2",
                                    "gpai-copyright-1", "gpai-copyright-2"])

        # No data_provenance records -> should fail gpai-t1 and gpai-t2 rules
        # Also no copyright_rights_reservation or license_record -> fails copyright provisions

        a = _export_and_validate(pkg, out, profiles)
        _print_assessment("missing-training-summary-fail", a)

    gpai_cop_pass()
    gpai_cop_fail()

# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════


def main() -> None:
    """Build all golden bundles and test vectors."""
    print("=" * 72)
    print("ACEF Golden Bundle & Test Vector Builder")
    print("=" * 72)

    print("\n--- Golden Bundles ---")
    build_eu_high_risk_core()
    build_gpai_provider_annex_xi_xii()
    build_synthetic_content_marking()
    build_china_cac_labeling()
    build_us_federal_governance()
    build_multi_subject_composed()

    print("\n--- Test Vectors: EU AI Act ---")
    build_eu_test_vectors()

    print("\n--- Test Vectors: China CAC ---")
    build_china_cac_test_vectors()

    print("\n--- Test Vectors: NIST AI RMF ---")
    build_nist_test_vectors()

    print("\n--- Test Vectors: OMB M-24-10 ---")
    build_omb_test_vectors()

    print("\n--- Test Vectors: EU GPAI Code of Practice ---")
    build_gpai_cop_test_vectors()

    print("\n" + "=" * 72)

    golden_count = sum(1 for _ in GOLDEN_DIR.rglob("acef-manifest.json"))
    vector_count = sum(1 for _ in VECTORS_DIR.rglob("acef-manifest.json"))
    print(f"Golden bundles created: {golden_count}")
    print(f"Test vectors created:   {vector_count}")
    print(f"Total bundles:          {golden_count + vector_count}")
    print("=" * 72)

    if golden_count < 6:
        print(f"ERROR: Expected 6 golden bundles, got {golden_count}")
        sys.exit(1)
    if vector_count < 19:
        print(f"ERROR: Expected 19 test vectors, got {vector_count}")
        sys.exit(1)

    print("All bundles created successfully.")


if __name__ == "__main__":
    main()
