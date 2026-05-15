"""Unit tests for fixes identified in the 4-agent code review.

Covers:
- C-IMPL-1: Path traversal in add_attachment
- M-IMPL-1: Stale files on re-export
- M-IMPL-2: Loader raises on missing record files
- M-IMPL-4: redact_package preserves attachments
- M-IMPL-5: Merge timestamp comparison with timezone offsets
- M-ARCH-3: ActorRole and AuditEventType exported from models
- M-SCOUT-1: SIGALRM threading safety
- M-SCOUT-3: Streaming sha256 for binary files
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from acef.errors import ACEFError, ACEFFormatError, ACEFMergeError
from acef.export import export_directory
from acef.integrity import sha256_file, sha256_hex
from acef.loader import load
from acef.merge import _timestamp_is_newer_or_equal, merge_packages
from acef.package import Package
from acef.redaction import redact_package
from acef.validation.operators import _safe_regex_search


class TestPathTraversalInAddAttachment:
    """C-IMPL-1: add_attachment must reject unsafe paths."""

    def test_rejects_absolute_path(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFError, match="Absolute"):
            pkg.add_attachment("/etc/passwd", b"bad")

    def test_rejects_dot_dot_traversal(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFError, match="traversal"):
            pkg.add_attachment("artifacts/../../escaped.txt", b"bad")

    def test_rejects_dot_segment(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFError, match="Current-directory"):
            pkg.add_attachment("artifacts/./file.txt", b"bad")

    def test_accepts_valid_path(self) -> None:
        pkg = Package()
        pkg.add_attachment("report.pdf", b"content")
        assert "artifacts/report.pdf" in pkg.attachments

    def test_accepts_nested_path(self) -> None:
        pkg = Package()
        pkg.add_attachment("artifacts/reports/eval-v3.pdf", b"content")
        assert "artifacts/reports/eval-v3.pdf" in pkg.attachments


class TestStaleFilesOnReExport:
    """M-IMPL-1: re-exporting clears old records and artifacts."""

    def test_old_records_removed_on_re_export(self, tmp_dir: Path) -> None:
        # First export with risk_register
        pkg1 = Package()
        pkg1.record("risk_register", payload={"description": "r1", "likelihood": "low", "severity": "low"})
        bundle = tmp_dir / "bundle.acef"
        export_directory(pkg1, str(bundle))
        assert (bundle / "records" / "risk_register.jsonl").exists()

        # Second export with event_log (no risk_register)
        pkg2 = Package()
        pkg2.record("event_log", payload={"event_type": "inference", "description": "e1"})
        export_directory(pkg2, str(bundle))

        # Old risk_register.jsonl must be gone
        assert not (bundle / "records" / "risk_register.jsonl").exists()
        assert (bundle / "records" / "event_log.jsonl").exists()


class TestLoaderMissingRecordFile:
    """M-IMPL-2: Loader must raise ACEF-022 when manifest-listed record files are missing."""

    def test_missing_record_file_raises_acef_022(self, tmp_dir: Path) -> None:
        bundle = tmp_dir / "bundle.acef"
        bundle.mkdir(parents=True)
        (bundle / "records").mkdir()
        (bundle / "artifacts").mkdir()
        (bundle / "hashes").mkdir()
        (bundle / "signatures").mkdir()

        manifest = {
            "metadata": {
                "package_id": "urn:acef:pkg:test",
                "timestamp": "2025-01-01T00:00:00Z",
                "producer": {"name": "t", "version": "1"},
            },
            "versioning": {"core_version": "1.0.0", "profiles_version": "1.0.0"},
            "subjects": [],
            "entities": {"components": [], "datasets": [], "actors": [], "relationships": []},
            "profiles": [],
            "record_files": [
                {"path": "records/risk_register.jsonl", "record_type": "risk_register", "count": 1}
            ],
            "audit_trail": [],
        }
        (bundle / "acef-manifest.json").write_text(json.dumps(manifest))

        with pytest.raises(ACEFFormatError, match="not found on disk") as exc_info:
            load(str(bundle))
        assert exc_info.value.code == "ACEF-022"


class TestRedactionPreservesAttachments:
    """M-IMPL-4: redact_package must copy attachments to the new package."""

    def test_attachments_preserved(self) -> None:
        pkg = Package()
        pkg.add_attachment("report.pdf", b"PDF content here")
        pkg.record(
            "evaluation_report",
            payload={"methodology": "benchmark", "results": {"accuracy": 0.95}},
            attachments=[{"path": "artifacts/report.pdf", "media_type": "application/pdf"}],
        )

        redacted = redact_package(
            pkg,
            record_filter={"record_types": ["evaluation_report"]},
        )

        assert len(redacted.attachments) == 1
        assert "artifacts/report.pdf" in redacted.attachments
        assert redacted.attachments["artifacts/report.pdf"] == b"PDF content here"


class TestMergeTimestampComparison:
    """M-IMPL-5: Timestamp comparison must handle timezone offsets properly."""

    def test_timezone_offset_comparison(self) -> None:
        # These represent the same instant:
        # 2025-01-01T00:00:00Z == 2025-01-01T01:00:00+01:00
        assert _timestamp_is_newer_or_equal(
            "2025-01-01T01:00:00+01:00",
            "2025-01-01T00:00:00Z",
        )
        assert _timestamp_is_newer_or_equal(
            "2025-01-01T00:00:00Z",
            "2025-01-01T01:00:00+01:00",
        )

    def test_newer_with_different_offset(self) -> None:
        # 2025-01-02T00:00:00Z is later than 2025-01-01T23:00:00-02:00
        # (which is 2025-01-02T01:00:00Z)
        # Actually -02:00 means 23:00 + 02:00 = 01:00 next day
        assert _timestamp_is_newer_or_equal(
            "2025-01-02T02:00:00Z",
            "2025-01-01T23:00:00-02:00",
        )

    def test_invalid_timestamps_raise_merge_error(self) -> None:
        """Invalid timestamps must raise ACEFMergeError instead of falling back
        to lexicographic string comparison, which produces nonsense results."""
        with pytest.raises(ACEFMergeError) as exc_info:
            _timestamp_is_newer_or_equal("b", "a")
        assert exc_info.value.code == "ACEF-060"

        with pytest.raises(ACEFMergeError) as exc_info:
            _timestamp_is_newer_or_equal("not-a-timestamp", "2025-01-01T00:00:00Z")
        assert exc_info.value.code == "ACEF-060"

    def test_unknown_conflict_strategy_raises(self) -> None:
        pkg = Package()
        pkg.add_subject("ai_system", name="Test")
        with pytest.raises(ACEFMergeError, match="Unknown conflict_strategy"):
            merge_packages([pkg], conflict_strategy="invalid_strategy")


class TestModelExports:
    """M-ARCH-3: ActorRole and AuditEventType must be importable from acef.models."""

    def test_actor_role_importable(self) -> None:
        from acef.models import ActorRole
        assert hasattr(ActorRole, "PROVIDER")

    def test_audit_event_type_importable(self) -> None:
        from acef.models import AuditEventType
        assert hasattr(AuditEventType, "CREATED")


class TestSigalrmThreadingSafety:
    """M-SCOUT-1: _safe_regex_search must not crash in non-main threads."""

    def test_regex_works_in_thread(self) -> None:
        results: list[bool] = []
        errors: list[str] = []

        def run_regex():
            try:
                result = _safe_regex_search(r"hello", "hello world")
                results.append(result)
            except Exception as e:
                errors.append(str(e))

        thread = threading.Thread(target=run_regex)
        thread.start()
        thread.join(timeout=10)

        assert len(errors) == 0, f"Regex in thread raised: {errors}"
        assert len(results) == 1
        assert results[0] is True


class TestStreamingSha256:
    """M-SCOUT-3: sha256_file must use streaming for binary files."""

    def test_binary_file_hash_correct(self, tmp_dir: Path) -> None:
        """Streaming hash of a binary file must match direct hash."""
        content = b"\x00\x01\x02" * 100_000  # 300KB binary content
        file_path = tmp_dir / "binary.bin"
        file_path.write_bytes(content)

        streamed_hash = sha256_file(file_path)
        direct_hash = sha256_hex(content)
        assert streamed_hash == direct_hash

    def test_small_binary_file_hash_correct(self, tmp_dir: Path) -> None:
        """Even small files must produce correct hashes via streaming."""
        content = b"small"
        file_path = tmp_dir / "small.bin"
        file_path.write_bytes(content)

        assert sha256_file(file_path) == sha256_hex(content)


class TestTimestampValidationInRecord:
    """Package.record() must validate timestamp overrides as ISO 8601."""

    def test_valid_timestamps_accepted(self) -> None:
        pkg = Package()
        # Valid ISO 8601 timestamps
        pkg.record("risk_register", payload={"description": "t", "likelihood": "low", "severity": "low"},
                    timestamp="2025-06-01T00:00:00Z")
        pkg.record("risk_register", payload={"description": "t", "likelihood": "low", "severity": "low"},
                    timestamp="2025-06-01T12:30:00+05:30")
        pkg.record("risk_register", payload={"description": "t", "likelihood": "low", "severity": "low"},
                    timestamp="2025-06-01T00:00:00+00:00")
        assert len(pkg.records) == 3

    def test_invalid_timestamp_rejected(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFError) as exc_info:
            pkg.record("risk_register", payload={"description": "t", "likelihood": "low", "severity": "low"},
                        timestamp="not-an-iso-timestamp")
        assert exc_info.value.code == "ACEF-050"

    def test_garbage_timestamp_rejected(self) -> None:
        pkg = Package()
        with pytest.raises(ACEFError) as exc_info:
            pkg.record("risk_register", payload={"description": "t", "likelihood": "low", "severity": "low"},
                        timestamp="zzz")
        assert exc_info.value.code == "ACEF-050"

    def test_no_timestamp_uses_default(self) -> None:
        pkg = Package()
        rec = pkg.record("risk_register", payload={"description": "t", "likelihood": "low", "severity": "low"})
        # Default timestamp should be valid ISO 8601
        assert rec.timestamp is not None
        datetime.fromisoformat(rec.timestamp.replace("Z", "+00:00"))
