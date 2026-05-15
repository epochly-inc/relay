"""Tests for acef.models.urns — URN generation, validation, and parsing."""

from __future__ import annotations

import pytest

from acef.errors import ACEFError
from acef.models.urns import ParsedURN, URNType, generate_urn, parse_urn, validate_urn


class TestURNType:
    """Test URNType enum values."""

    def test_all_types(self):
        expected = {"pkg", "sub", "cmp", "dat", "act", "rec", "asx"}
        actual = {t.value for t in URNType}
        assert actual == expected


class TestGenerateURN:
    """Test generate_urn for all types."""

    @pytest.mark.parametrize("urn_type", list(URNType))
    def test_generate_all_types(self, urn_type: URNType):
        urn = generate_urn(urn_type)
        assert urn.startswith(f"urn:acef:{urn_type.value}:")
        assert validate_urn(urn)

    def test_generate_returns_unique_urns(self):
        urns = {generate_urn(URNType.RECORD) for _ in range(100)}
        assert len(urns) == 100

    def test_generate_urn_format(self):
        urn = generate_urn(URNType.PACKAGE)
        parts = urn.split(":")
        assert len(parts) == 4
        assert parts[0] == "urn"
        assert parts[1] == "acef"
        assert parts[2] == "pkg"
        # UUID part: 8-4-4-4-12 hex chars
        uuid_part = parts[3]
        segments = uuid_part.split("-")
        assert len(segments) == 5
        assert len(segments[0]) == 8
        assert len(segments[1]) == 4
        assert len(segments[2]) == 4
        assert len(segments[3]) == 4
        assert len(segments[4]) == 12


class TestValidateURN:
    """Test validate_urn for valid and invalid URNs."""

    def test_valid_urn(self):
        assert validate_urn("urn:acef:sub:550e8400-e29b-41d4-a716-446655440000")

    def test_valid_urn_all_types(self):
        for t in URNType:
            urn = f"urn:acef:{t.value}:550e8400-e29b-41d4-a716-446655440000"
            assert validate_urn(urn), f"Should be valid: {urn}"

    def test_invalid_missing_prefix(self):
        assert not validate_urn("acef:sub:550e8400-e29b-41d4-a716-446655440000")

    def test_invalid_wrong_namespace(self):
        assert not validate_urn("urn:other:sub:550e8400-e29b-41d4-a716-446655440000")

    def test_invalid_unknown_type(self):
        assert not validate_urn("urn:acef:xyz:550e8400-e29b-41d4-a716-446655440000")

    def test_invalid_uuid_too_short(self):
        assert not validate_urn("urn:acef:sub:550e8400-e29b-41d4-a716")

    def test_invalid_uuid_uppercase(self):
        assert not validate_urn("urn:acef:sub:550E8400-E29B-41D4-A716-446655440000")

    def test_invalid_empty_string(self):
        assert not validate_urn("")

    def test_invalid_random_string(self):
        assert not validate_urn("not a urn at all")

    def test_invalid_extra_colon(self):
        assert not validate_urn("urn:acef:sub:550e8400-e29b-41d4-a716-446655440000:extra")


class TestParseURN:
    """Test parse_urn extracts correct fields."""

    def test_parse_subject_urn(self):
        urn = "urn:acef:sub:550e8400-e29b-41d4-a716-446655440000"
        parsed = parse_urn(urn)
        assert isinstance(parsed, ParsedURN)
        assert parsed.urn_type == URNType.SUBJECT
        assert parsed.uuid_str == "550e8400-e29b-41d4-a716-446655440000"
        assert parsed.full_urn == urn

    def test_parse_package_urn(self):
        urn = "urn:acef:pkg:00000000-0000-0000-0000-000000000001"
        parsed = parse_urn(urn)
        assert parsed.urn_type == URNType.PACKAGE

    def test_parse_component_urn(self):
        urn = "urn:acef:cmp:11111111-1111-1111-1111-111111111111"
        parsed = parse_urn(urn)
        assert parsed.urn_type == URNType.COMPONENT

    def test_parse_dataset_urn(self):
        urn = "urn:acef:dat:22222222-2222-2222-2222-222222222222"
        parsed = parse_urn(urn)
        assert parsed.urn_type == URNType.DATASET

    def test_parse_record_urn(self):
        urn = "urn:acef:rec:33333333-3333-3333-3333-333333333333"
        parsed = parse_urn(urn)
        assert parsed.urn_type == URNType.RECORD

    def test_parse_assessment_urn(self):
        urn = "urn:acef:asx:44444444-4444-4444-4444-444444444444"
        parsed = parse_urn(urn)
        assert parsed.urn_type == URNType.ASSESSMENT

    def test_parse_invalid_raises(self):
        with pytest.raises(ACEFError, match="Invalid ACEF URN"):
            parse_urn("not-a-urn")

    def test_parse_invalid_code(self):
        with pytest.raises(ACEFError) as exc_info:
            parse_urn("not-a-urn")
        assert exc_info.value.code == "ACEF-020"

    def test_parse_roundtrip(self):
        for urn_type in URNType:
            generated = generate_urn(urn_type)
            parsed = parse_urn(generated)
            assert parsed.urn_type == urn_type
            assert parsed.full_urn == generated
