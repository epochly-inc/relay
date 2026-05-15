"""Tests for acef.errors — error hierarchy, codes, severity mapping, ValidationDiagnostic."""

from __future__ import annotations

import pytest

from acef.errors import (
    ACEFError,
    ACEFEvaluationError,
    ACEFExportError,
    ACEFFormatError,
    ACEFIntegrityError,
    ACEFMergeError,
    ACEFProfileError,
    ACEFReferenceError,
    ACEFSchemaError,
    ACEFSigningError,
    ERROR_REGISTRY,
    ErrorCategory,
    Severity,
    ValidationDiagnostic,
)


class TestSeverityEnum:
    """Test Severity enum has all required levels."""

    def test_severity_values(self):
        assert Severity.FATAL.value == "fatal"
        assert Severity.ERROR.value == "error"
        assert Severity.WARNING.value == "warning"
        assert Severity.INFO.value == "info"

    def test_severity_is_str_enum(self):
        assert isinstance(Severity.FATAL, str)
        assert Severity.FATAL == "fatal"


class TestErrorCategory:
    """Test ErrorCategory enum has all required categories."""

    def test_category_values(self):
        assert ErrorCategory.SCHEMA.value == "schema"
        assert ErrorCategory.INTEGRITY.value == "integrity"
        assert ErrorCategory.REFERENCE.value == "reference"
        assert ErrorCategory.PROFILE.value == "profile"
        assert ErrorCategory.EVALUATION.value == "evaluation"
        assert ErrorCategory.FORMAT.value == "format"
        assert ErrorCategory.MERGE.value == "merge"


class TestErrorRegistry:
    """Test the ERROR_REGISTRY mapping is complete and correct."""

    def test_registry_has_all_codes(self):
        expected_codes = {
            "ACEF-001", "ACEF-002", "ACEF-003", "ACEF-004",
            "ACEF-010", "ACEF-011", "ACEF-012", "ACEF-013", "ACEF-014",
            "ACEF-020", "ACEF-021", "ACEF-022", "ACEF-023", "ACEF-025", "ACEF-026", "ACEF-027",
            "ACEF-030", "ACEF-031", "ACEF-032", "ACEF-033",
            "ACEF-040", "ACEF-041", "ACEF-042", "ACEF-043", "ACEF-044", "ACEF-045",
            "ACEF-050", "ACEF-051", "ACEF-052", "ACEF-053",
            "ACEF-060",
        }
        assert set(ERROR_REGISTRY.keys()) == expected_codes

    def test_registry_entry_structure(self):
        for code, entry in ERROR_REGISTRY.items():
            severity, category, description = entry
            assert isinstance(severity, Severity), f"{code} severity is not Severity"
            assert isinstance(category, ErrorCategory), f"{code} category is not ErrorCategory"
            assert isinstance(description, str), f"{code} description is not str"
            assert len(description) > 0, f"{code} has empty description"

    def test_fatal_codes_correct(self):
        fatal_codes = {"ACEF-001", "ACEF-002", "ACEF-004", "ACEF-010", "ACEF-011",
                       "ACEF-012", "ACEF-013", "ACEF-014", "ACEF-050", "ACEF-051"}
        for code in fatal_codes:
            severity, _, _ = ERROR_REGISTRY[code]
            assert severity == Severity.FATAL, f"{code} should be FATAL"


class TestACEFError:
    """Test base ACEFError exception."""

    def test_error_with_registered_code(self):
        err = ACEFError("test message", code="ACEF-010")
        assert err.code == "ACEF-010"
        assert err.severity == Severity.FATAL
        assert err.category == ErrorCategory.INTEGRITY
        assert str(err) == "[ACEF-010] test message"

    def test_error_with_unknown_code(self):
        err = ACEFError("unknown error", code="ACEF-999")
        assert err.code == "ACEF-999"
        assert err.severity == Severity.ERROR
        assert err.category == ErrorCategory.SCHEMA

    def test_error_message_property(self):
        err = ACEFError("test msg", code="ACEF-020")
        assert err.message == "test msg"

    def test_error_details(self):
        err = ACEFError("test", code="ACEF-001", details={"file": "manifest.json"})
        assert err.details == {"file": "manifest.json"}

    def test_error_defaults_empty_details(self):
        err = ACEFError("test", code="ACEF-001")
        assert err.details == {}

    def test_error_is_exception(self):
        with pytest.raises(ACEFError):
            raise ACEFError("boom", code="ACEF-010")


class TestErrorHierarchy:
    """Test the error subclass hierarchy with default codes."""

    def test_schema_error_default_code(self):
        err = ACEFSchemaError("schema fail")
        assert err.code == "ACEF-002"

    def test_integrity_error_default_code(self):
        err = ACEFIntegrityError("hash fail")
        assert err.code == "ACEF-010"

    def test_reference_error_default_code(self):
        err = ACEFReferenceError("dangling ref")
        assert err.code == "ACEF-020"

    def test_profile_error_default_code(self):
        err = ACEFProfileError("unknown profile")
        assert err.code == "ACEF-030"

    def test_evaluation_error_default_code(self):
        err = ACEFEvaluationError("eval fail")
        assert err.code == "ACEF-040"

    def test_format_error_default_code(self):
        err = ACEFFormatError("format fail")
        assert err.code == "ACEF-050"

    def test_merge_error_default_code(self):
        err = ACEFMergeError("merge conflict")
        assert err.code == "ACEF-060"

    def test_export_error_default_code(self):
        err = ACEFExportError("export fail")
        assert err.code == "ACEF-050"

    def test_signing_error_default_code(self):
        err = ACEFSigningError("signing fail")
        assert err.code == "ACEF-012"

    def test_subclass_inherits_acef_error(self):
        err = ACEFSchemaError("test")
        assert isinstance(err, ACEFError)
        assert isinstance(err, Exception)

    def test_subclass_code_override(self):
        err = ACEFSchemaError("test", code="ACEF-003")
        assert err.code == "ACEF-003"
        assert err.severity == Severity.ERROR


class TestValidationDiagnostic:
    """Test ValidationDiagnostic creation and serialization."""

    def test_creation_with_registered_code(self):
        diag = ValidationDiagnostic("ACEF-020", "Dangling ref")
        assert diag.code == "ACEF-020"
        assert diag.severity == Severity.ERROR
        assert diag.category == ErrorCategory.REFERENCE
        assert diag.message == "Dangling ref"

    def test_creation_with_path(self):
        diag = ValidationDiagnostic("ACEF-020", "test", path="/subjects/0/subject_id")
        assert diag.path == "/subjects/0/subject_id"

    def test_creation_with_details(self):
        diag = ValidationDiagnostic("ACEF-020", "test", details={"urn": "urn:acef:sub:abc"})
        assert diag.details == {"urn": "urn:acef:sub:abc"}

    def test_to_dict_minimal(self):
        diag = ValidationDiagnostic("ACEF-020", "Dangling ref")
        d = diag.to_dict()
        assert d["code"] == "ACEF-020"
        assert d["severity"] == "error"
        assert d["category"] == "reference"
        assert d["message"] == "Dangling ref"
        assert "path" not in d
        assert "details" not in d

    def test_to_dict_full(self):
        diag = ValidationDiagnostic(
            "ACEF-010", "Hash mismatch",
            path="/records/0",
            details={"expected": "abc", "actual": "def"},
        )
        d = diag.to_dict()
        assert d["path"] == "/records/0"
        assert d["details"] == {"expected": "abc", "actual": "def"}

    def test_repr(self):
        diag = ValidationDiagnostic("ACEF-020", "Dangling ref", path="/subjects/0")
        r = repr(diag)
        assert "ACEF-020" in r
        assert "error" in r
        assert "Dangling ref" in r
        assert "/subjects/0" in r

    def test_unknown_code_defaults(self):
        diag = ValidationDiagnostic("ACEF-999", "Unknown")
        assert diag.severity == Severity.ERROR
        assert diag.category == ErrorCategory.SCHEMA
