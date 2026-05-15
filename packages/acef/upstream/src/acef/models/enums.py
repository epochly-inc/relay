"""ACEF enumeration types — all enum values from the spec."""

from __future__ import annotations

from enum import Enum


class SubjectType(str, Enum):
    """AI system or model type per EU AI Act provider/deployer split."""

    AI_SYSTEM = "ai_system"
    AI_MODEL = "ai_model"


class RiskClassification(str, Enum):
    """Risk classification levels per EU AI Act."""

    HIGH_RISK = "high-risk"
    GPAI = "gpai"
    GPAI_SYSTEMIC = "gpai-systemic"
    LIMITED_RISK = "limited-risk"
    MINIMAL_RISK = "minimal-risk"


class LifecyclePhase(str, Enum):
    """AI system lifecycle phases."""

    DESIGN = "design"
    DEVELOPMENT = "development"
    TESTING = "testing"
    DEPLOYMENT = "deployment"
    MONITORING = "monitoring"
    DECOMMISSION = "decommission"


class ComponentType(str, Enum):
    """Entity component types."""

    MODEL = "model"
    RETRIEVER = "retriever"
    GUARDRAIL = "guardrail"
    ORCHESTRATOR = "orchestrator"
    TOOL = "tool"
    DATABASE = "database"
    API = "api"


class DatasetSourceType(str, Enum):
    """Dataset acquisition source types."""

    LICENSED = "licensed"
    SCRAPED = "scraped"
    PUBLIC_DOMAIN = "public_domain"
    SYNTHETIC = "synthetic"
    USER_GENERATED = "user_generated"


class DatasetModality(str, Enum):
    """Dataset modality types."""

    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    TABULAR = "tabular"
    MULTIMODAL = "multimodal"


class ActorRole(str, Enum):
    """Actor roles per EU AI Act."""

    PROVIDER = "provider"
    DEPLOYER = "deployer"
    IMPORTER = "importer"
    DISTRIBUTOR = "distributor"
    AUDITOR = "auditor"
    REGULATOR = "regulator"
    DATA_SUBJECT = "data_subject"


class RelationshipType(str, Enum):
    """Entity relationship types (W3C PROV-compatible)."""

    WRAPS = "wraps"
    CALLS = "calls"
    FINE_TUNES = "fine_tunes"
    DEPLOYS = "deploys"
    TRAINS_ON = "trains_on"
    EVALUATES_WITH = "evaluates_with"
    OVERSEES = "oversees"


class ObligationRole(str, Enum):
    """Who is responsible for producing the evidence."""

    PROVIDER = "provider"
    DEPLOYER = "deployer"
    IMPORTER = "importer"
    DISTRIBUTOR = "distributor"
    AUTHORISED_REPRESENTATIVE = "authorised_representative"
    NOTIFIED_BODY = "notified_body"
    PLATFORM = "platform"


class Confidentiality(str, Enum):
    """Evidence confidentiality levels."""

    PUBLIC = "public"
    REDACTED = "redacted"
    HASH_COMMITTED = "hash-committed"
    REGULATOR_ONLY = "regulator-only"
    UNDER_NDA = "under-nda"


class TrustLevel(str, Enum):
    """Evidence trust/provenance levels."""

    SELF_ATTESTED = "self-attested"
    PEER_REVIEWED = "peer-reviewed"
    INDEPENDENTLY_VERIFIED = "independently-verified"
    NOTIFIED_BODY_CERTIFIED = "notified-body-certified"


class EventType(str, Enum):
    """Event log event types."""

    INFERENCE = "inference"
    TRAINING = "training"
    EVALUATION = "evaluation"
    DEPLOYMENT = "deployment"
    OVERRIDE = "override"
    ERROR = "error"
    MARKING = "marking"
    DISCLOSURE = "disclosure"
    LOGGING_SPEC = "logging_spec"


class AuditEventType(str, Enum):
    """Audit trail event types."""

    CREATED = "created"
    UPDATED = "updated"
    REVIEWED = "reviewed"
    SUBMITTED = "submitted"
    CERTIFIED = "certified"


class RuleSeverity(str, Enum):
    """DSL rule severity levels — used in templates."""

    FAIL = "fail"
    WARNING = "warning"
    INFO = "info"


class RuleOutcome(str, Enum):
    """DSL rule evaluation outcomes."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class ProvisionOutcome(str, Enum):
    """Provision roll-up outcome per 7-step precedence algorithm."""

    SATISFIED = "satisfied"
    NOT_SATISFIED = "not-satisfied"
    PARTIALLY_SATISFIED = "partially-satisfied"
    GAP_ACKNOWLEDGED = "gap-acknowledged"
    SKIPPED = "skipped"
    NOT_ASSESSED = "not-assessed"


# Record types — the 16 v1 record types
RECORD_TYPES = frozenset({
    "risk_register",
    "risk_treatment",
    "dataset_card",
    "data_provenance",
    "evaluation_report",
    "event_log",
    "human_oversight_action",
    "transparency_disclosure",
    "transparency_marking",
    "disclosure_labeling",
    "copyright_rights_reservation",
    "license_record",
    "incident_report",
    "governance_policy",
    "conformity_declaration",
    "evidence_gap",
})

MANDATORY_RECORD_TYPES = frozenset({
    "risk_register",
    "risk_treatment",
    "dataset_card",
    "data_provenance",
    "evaluation_report",
})
