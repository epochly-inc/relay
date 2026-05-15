"""ACEF error taxonomy — all 60 error codes with severity and category.

Error codes follow the ACEF specification Section 3.6.
Each error has a unique code, severity (fatal/error/warning/info), and category.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Error severity levels per ACEF spec."""

    FATAL = "fatal"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ErrorCategory(str, Enum):
    """Error categories per ACEF spec."""

    SCHEMA = "schema"
    INTEGRITY = "integrity"
    REFERENCE = "reference"
    PROFILE = "profile"
    EVALUATION = "evaluation"
    FORMAT = "format"
    MERGE = "merge"


# Complete error code registry mapping code -> (severity, category, description)
ERROR_REGISTRY: dict[str, tuple[Severity, ErrorCategory, str]] = {
    "ACEF-001": (Severity.FATAL, ErrorCategory.SCHEMA, "Incompatible module versions in versioning block"),
    "ACEF-002": (Severity.FATAL, ErrorCategory.SCHEMA, "Manifest fails JSON Schema validation"),
    "ACEF-003": (Severity.ERROR, ErrorCategory.SCHEMA, "Unknown record_type — no schema in registry"),
    "ACEF-004": (Severity.FATAL, ErrorCategory.SCHEMA, "Record payload fails record-type JSON Schema validation"),
    "ACEF-010": (Severity.FATAL, ErrorCategory.INTEGRITY, "File hash mismatch"),
    "ACEF-011": (Severity.FATAL, ErrorCategory.INTEGRITY, "Merkle root mismatch"),
    "ACEF-012": (Severity.FATAL, ErrorCategory.INTEGRITY, "Invalid or expired signature"),
    "ACEF-013": (Severity.FATAL, ErrorCategory.INTEGRITY, "Unsupported JWS algorithm"),
    "ACEF-014": (Severity.FATAL, ErrorCategory.INTEGRITY, "Hash index completeness failure"),
    "ACEF-020": (Severity.ERROR, ErrorCategory.REFERENCE, "Dangling entity_refs — URN references nonexistent entity"),
    "ACEF-021": (Severity.ERROR, ErrorCategory.REFERENCE, "Duplicate URNs within the package"),
    "ACEF-022": (Severity.ERROR, ErrorCategory.REFERENCE, "record_files entry references nonexistent file"),
    "ACEF-023": (Severity.ERROR, ErrorCategory.REFERENCE, "Attachment path references file not in artifacts/"),
    "ACEF-025": (Severity.ERROR, ErrorCategory.REFERENCE, "Record count mismatch between manifest and actual JSONL"),
    "ACEF-026": (Severity.ERROR, ErrorCategory.REFERENCE, "Duplicate record_id within the package"),
    "ACEF-027": (
        Severity.WARNING,
        ErrorCategory.REFERENCE,
        "Attachment hash does not match content-hashes.json entry",
    ),
    "ACEF-030": (Severity.ERROR, ErrorCategory.PROFILE, "Unknown profile_id — no matching template"),
    "ACEF-031": (Severity.ERROR, ErrorCategory.PROFILE, "Unknown template_version"),
    "ACEF-032": (Severity.INFO, ErrorCategory.PROFILE, "Provision not yet effective — rules produce skipped outcome"),
    "ACEF-033": (Severity.ERROR, ErrorCategory.PROFILE, "Incompatible module versions between bundle and template"),
    "ACEF-040": (Severity.ERROR, ErrorCategory.EVALUATION, "Required evidence type missing"),
    "ACEF-041": (Severity.WARNING, ErrorCategory.EVALUATION, "Evidence freshness exceeded"),
    "ACEF-042": (Severity.INFO, ErrorCategory.EVALUATION, "evidence_gap acknowledged for provision"),
    "ACEF-043": (Severity.ERROR, ErrorCategory.EVALUATION, "Invalid JSON Pointer in rule field parameter"),
    "ACEF-044": (Severity.ERROR, ErrorCategory.EVALUATION, "Duplicate rule_id in template"),
    "ACEF-045": (Severity.ERROR, ErrorCategory.EVALUATION, "Invalid ECMA-262 regex pattern in rule value"),
    "ACEF-050": (Severity.FATAL, ErrorCategory.FORMAT, "Malformed JSONL line"),
    "ACEF-051": (Severity.FATAL, ErrorCategory.FORMAT, "JSON not canonicalized per RFC 8785"),
    "ACEF-052": (Severity.ERROR, ErrorCategory.FORMAT, "Path contains .. segments or non-UTF-8-NFC characters"),
    "ACEF-053": (Severity.ERROR, ErrorCategory.FORMAT, "Vendor extension field affects conformance outcome"),
    "ACEF-060": (Severity.WARNING, ErrorCategory.MERGE, "Conflicting records from multiple packages"),
}


class ACEFError(Exception):
    """Base exception for all ACEF errors."""

    code: str = "ACEF-000"

    def __init__(self, message: str, *, code: str | None = None, details: dict[str, Any] | None = None) -> None:
        self.code = code or self.__class__.code
        self.details = details or {}
        if self.code in ERROR_REGISTRY:
            severity, category, _ = ERROR_REGISTRY[self.code]
            self.severity = severity
            self.category = category
        else:
            self.severity = Severity.ERROR
            self.category = ErrorCategory.SCHEMA
        super().__init__(f"[{self.code}] {message}")

    @property
    def message(self) -> str:
        """The error message without the code prefix."""
        full = str(self)
        prefix = f"[{self.code}] "
        return full[len(prefix):] if full.startswith(prefix) else full


class ACEFSchemaError(ACEFError):
    """Schema validation errors (ACEF-001 through ACEF-004)."""

    code = "ACEF-002"


class ACEFIntegrityError(ACEFError):
    """Integrity verification errors (ACEF-010 through ACEF-014)."""

    code = "ACEF-010"


class ACEFReferenceError(ACEFError):
    """Reference integrity errors (ACEF-020 through ACEF-027)."""

    code = "ACEF-020"


class ACEFProfileError(ACEFError):
    """Profile/template errors (ACEF-030 through ACEF-033)."""

    code = "ACEF-030"


class ACEFEvaluationError(ACEFError):
    """Rule evaluation errors (ACEF-040 through ACEF-045)."""

    code = "ACEF-040"


class ACEFFormatError(ACEFError):
    """Format errors (ACEF-050 through ACEF-053)."""

    code = "ACEF-050"


class ACEFMergeError(ACEFError):
    """Merge conflict errors (ACEF-060)."""

    code = "ACEF-060"


class ACEFExportError(ACEFError):
    """Export/serialization errors."""

    code = "ACEF-050"


class ACEFSigningError(ACEFError):
    """Signing/verification errors."""

    code = "ACEF-012"


class ValidationDiagnostic:
    """A single validation finding — used by the validation engine to collect
    all errors within a phase before stopping."""

    __slots__ = ("code", "severity", "category", "message", "path", "details")

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.path = path
        self.details = details or {}
        if code in ERROR_REGISTRY:
            self.severity, self.category, _ = ERROR_REGISTRY[code]
        else:
            self.severity = Severity.ERROR
            self.category = ErrorCategory.SCHEMA

    def __repr__(self) -> str:
        path_str = f" at {self.path}" if self.path else ""
        return f"ValidationDiagnostic({self.code}, {self.severity.value}, {self.message!r}{path_str})"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for Assessment Bundle structural_errors."""
        result: dict[str, Any] = {
            "code": self.code,
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
        }
        if self.path:
            result["path"] = self.path
        if self.details:
            result["details"] = self.details
        return result
