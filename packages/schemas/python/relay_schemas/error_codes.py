"""Generated Relay error-code constants (DO NOT EDIT BY HAND).

Source: ``packages/schemas/raw/relay-error-codes.yaml``.
Generator: ``packages/schemas/scripts/gen_error_codes.py``.

W1.5 will replace this minimal generator with the full codegen pipeline
(datamodel-code-generator + openapi-typescript + drift check). Until then,
re-run ``python packages/schemas/scripts/gen_error_codes.py`` after editing
the YAML.

ASCII-only per CLAUDE.md "ASCII-Safe Source".

VAL-W1-030 evidence: every documented RELAY-* code from spec section B.4
appears as a constant on ``RelayErrorCode``.
"""

from __future__ import annotations

from typing import Final


class RelayErrorCode:
    """Container for canonical Relay error-code string constants.

    Each constant value is the wire-format token (e.g., ``"RELAY-ING-031"``).
    Attribute names mirror the wire token with hyphens replaced by
    underscores (e.g., ``RelayErrorCode.RELAY_ING_031``).

    Per VAL-W1-029, every token matches ``^RELAY-[A-Z]+-[0-9]{3}$``. The
    generator refuses to emit constants for tokens violating that pattern.
    """

    RELAY_AUTH_001: Final[str] = "RELAY-AUTH-001"
    RELAY_AUTH_014: Final[str] = "RELAY-AUTH-014"
    RELAY_CLI_070: Final[str] = "RELAY-CLI-070"
    RELAY_COVERAGE_001: Final[str] = "RELAY-COVERAGE-001"
    RELAY_COVERAGE_002: Final[str] = "RELAY-COVERAGE-002"
    RELAY_COVERAGE_003: Final[str] = "RELAY-COVERAGE-003"
    RELAY_COVERAGE_004: Final[str] = "RELAY-COVERAGE-004"
    RELAY_EVID_001: Final[str] = "RELAY-EVID-001"
    RELAY_EVID_002: Final[str] = "RELAY-EVID-002"
    RELAY_EVID_014: Final[str] = "RELAY-EVID-014"
    RELAY_EVID_024: Final[str] = "RELAY-EVID-024"
    RELAY_EVID_031: Final[str] = "RELAY-EVID-031"
    RELAY_EVID_038: Final[str] = "RELAY-EVID-038"
    RELAY_FUTURE_999: Final[str] = "RELAY-FUTURE-999"
    RELAY_GATE_001: Final[str] = "RELAY-GATE-001"
    RELAY_GATE_014: Final[str] = "RELAY-GATE-014"
    RELAY_GATE_021: Final[str] = "RELAY-GATE-021"
    RELAY_GATE_024: Final[str] = "RELAY-GATE-024"
    RELAY_GATE_041: Final[str] = "RELAY-GATE-041"
    RELAY_GATE_051: Final[str] = "RELAY-GATE-051"
    RELAY_GATE_061: Final[str] = "RELAY-GATE-061"
    RELAY_IDEMPOTENCY_001: Final[str] = "RELAY-IDEMPOTENCY-001"
    RELAY_ING_001: Final[str] = "RELAY-ING-001"
    RELAY_ING_014: Final[str] = "RELAY-ING-014"
    RELAY_ING_021: Final[str] = "RELAY-ING-021"
    RELAY_ING_022: Final[str] = "RELAY-ING-022"
    RELAY_ING_031: Final[str] = "RELAY-ING-031"
    RELAY_ING_032: Final[str] = "RELAY-ING-032"
    RELAY_RATE_001: Final[str] = "RELAY-RATE-001"
    RELAY_RATE_014: Final[str] = "RELAY-RATE-014"
    RELAY_RELEASE_001: Final[str] = "RELAY-RELEASE-001"
    RELAY_RELEASE_002: Final[str] = "RELAY-RELEASE-002"
    RELAY_RELEASE_004: Final[str] = "RELAY-RELEASE-004"
    RELAY_RELEASE_005: Final[str] = "RELAY-RELEASE-005"
    RELAY_RELEASE_006: Final[str] = "RELAY-RELEASE-006"
    RELAY_RELEASE_007: Final[str] = "RELAY-RELEASE-007"
    RELAY_RELEASE_008: Final[str] = "RELAY-RELEASE-008"
    RELAY_RELEASE_009: Final[str] = "RELAY-RELEASE-009"
    RELAY_RELEASE_010: Final[str] = "RELAY-RELEASE-010"
    RELAY_RELEASE_011: Final[str] = "RELAY-RELEASE-011"
    RELAY_RELEASE_012: Final[str] = "RELAY-RELEASE-012"
    RELAY_RELEASE_013: Final[str] = "RELAY-RELEASE-013"
    RELAY_RELEASE_014: Final[str] = "RELAY-RELEASE-014"
    RELAY_RELEASE_015: Final[str] = "RELAY-RELEASE-015"
    RELAY_RELEASE_016: Final[str] = "RELAY-RELEASE-016"
    RELAY_RELEASE_017: Final[str] = "RELAY-RELEASE-017"
    RELAY_RELEASE_018: Final[str] = "RELAY-RELEASE-018"
    RELAY_RELEASE_019: Final[str] = "RELAY-RELEASE-019"
    RELAY_RELEASE_020: Final[str] = "RELAY-RELEASE-020"
    RELAY_RELEASE_021: Final[str] = "RELAY-RELEASE-021"
    RELAY_RELEASE_022: Final[str] = "RELAY-RELEASE-022"
    RELAY_RELEASE_023: Final[str] = "RELAY-RELEASE-023"
    RELAY_RELEASE_024: Final[str] = "RELAY-RELEASE-024"
    RELAY_RELEASE_025: Final[str] = "RELAY-RELEASE-025"
    RELAY_RELEASE_026: Final[str] = "RELAY-RELEASE-026"
    RELAY_RELEASE_028: Final[str] = "RELAY-RELEASE-028"
    RELAY_RELEASE_029: Final[str] = "RELAY-RELEASE-029"
    RELAY_RELEASE_030: Final[str] = "RELAY-RELEASE-030"
    RELAY_RELEASE_032: Final[str] = "RELAY-RELEASE-032"
    RELAY_RELEASE_033: Final[str] = "RELAY-RELEASE-033"
    RELAY_RELEASE_034: Final[str] = "RELAY-RELEASE-034"
    RELAY_RELEASE_035: Final[str] = "RELAY-RELEASE-035"
    RELAY_RELEASE_036: Final[str] = "RELAY-RELEASE-036"
    RELAY_RELEASE_037: Final[str] = "RELAY-RELEASE-037"
    RELAY_RELEASE_038: Final[str] = "RELAY-RELEASE-038"
    RELAY_RELEASE_039: Final[str] = "RELAY-RELEASE-039"
    RELAY_RELEASE_040: Final[str] = "RELAY-RELEASE-040"
    RELAY_RELEASE_041: Final[str] = "RELAY-RELEASE-041"
    RELAY_RELEASE_042: Final[str] = "RELAY-RELEASE-042"
    RELAY_RELEASE_043: Final[str] = "RELAY-RELEASE-043"
    RELAY_RELEASE_044: Final[str] = "RELAY-RELEASE-044"
    RELAY_RELEASE_045: Final[str] = "RELAY-RELEASE-045"
    RELAY_RELEASE_046: Final[str] = "RELAY-RELEASE-046"
    RELAY_RELEASE_047: Final[str] = "RELAY-RELEASE-047"
    RELAY_REPLAY_001: Final[str] = "RELAY-REPLAY-001"
    RELAY_REPLAY_002: Final[str] = "RELAY-REPLAY-002"
    RELAY_REPLAY_014: Final[str] = "RELAY-REPLAY-014"
    RELAY_SCHEMA_001: Final[str] = "RELAY-SCHEMA-001"
    RELAY_SCHEMA_011: Final[str] = "RELAY-SCHEMA-011"
    RELAY_SCHEMA_014: Final[str] = "RELAY-SCHEMA-014"
    RELAY_SCHEMA_017: Final[str] = "RELAY-SCHEMA-017"
    RELAY_SCHEMA_018: Final[str] = "RELAY-SCHEMA-018"
    RELAY_SCHEMA_023: Final[str] = "RELAY-SCHEMA-023"
    RELAY_SDK_001: Final[str] = "RELAY-SDK-001"
    RELAY_SDK_002: Final[str] = "RELAY-SDK-002"
    RELAY_SDK_003: Final[str] = "RELAY-SDK-003"
    RELAY_SDK_004: Final[str] = "RELAY-SDK-004"
    RELAY_SDK_005: Final[str] = "RELAY-SDK-005"
    RELAY_SDK_006: Final[str] = "RELAY-SDK-006"
    RELAY_SDK_007: Final[str] = "RELAY-SDK-007"
    RELAY_SDK_008: Final[str] = "RELAY-SDK-008"
    RELAY_SDK_009: Final[str] = "RELAY-SDK-009"
    RELAY_SDK_010: Final[str] = "RELAY-SDK-010"
    RELAY_SDK_011: Final[str] = "RELAY-SDK-011"
    RELAY_SDK_012: Final[str] = "RELAY-SDK-012"
    RELAY_SDK_013: Final[str] = "RELAY-SDK-013"
    RELAY_SIDECAR_001: Final[str] = "RELAY-SIDECAR-001"
    RELAY_SIDECAR_002: Final[str] = "RELAY-SIDECAR-002"
    RELAY_SIDECAR_003: Final[str] = "RELAY-SIDECAR-003"
    RELAY_SIDECAR_004: Final[str] = "RELAY-SIDECAR-004"
    RELAY_SIDECAR_005: Final[str] = "RELAY-SIDECAR-005"
    RELAY_SIDECAR_006: Final[str] = "RELAY-SIDECAR-006"
    RELAY_SIDECAR_007: Final[str] = "RELAY-SIDECAR-007"
    RELAY_SIDECAR_008: Final[str] = "RELAY-SIDECAR-008"
    RELAY_SIDECAR_009: Final[str] = "RELAY-SIDECAR-009"
    RELAY_SIDECAR_010: Final[str] = "RELAY-SIDECAR-010"
    RELAY_SIDECAR_011: Final[str] = "RELAY-SIDECAR-011"
    RELAY_SIDECAR_012: Final[str] = "RELAY-SIDECAR-012"
    RELAY_SIDECAR_013: Final[str] = "RELAY-SIDECAR-013"
    RELAY_SQLITE_001: Final[str] = "RELAY-SQLITE-001"
    RELAY_VENDOR_001: Final[str] = "RELAY-VENDOR-001"
    RELAY_VENDOR_002: Final[str] = "RELAY-VENDOR-002"
    RELAY_VERIFY_001: Final[str] = "RELAY-VERIFY-001"
    RELAY_VERIFY_050: Final[str] = "RELAY-VERIFY-050"

    @classmethod
    def all(cls) -> frozenset[str]:
        """Return the frozenset of every known wire-format code."""
        return _ALL_CODES


_ALL_CODES: Final[frozenset[str]] = frozenset({
    "RELAY-AUTH-001",
    "RELAY-AUTH-014",
    "RELAY-CLI-070",
    "RELAY-COVERAGE-001",
    "RELAY-COVERAGE-002",
    "RELAY-COVERAGE-003",
    "RELAY-COVERAGE-004",
    "RELAY-EVID-001",
    "RELAY-EVID-002",
    "RELAY-EVID-014",
    "RELAY-EVID-024",
    "RELAY-EVID-031",
    "RELAY-EVID-038",
    "RELAY-FUTURE-999",
    "RELAY-GATE-001",
    "RELAY-GATE-014",
    "RELAY-GATE-021",
    "RELAY-GATE-024",
    "RELAY-GATE-041",
    "RELAY-GATE-051",
    "RELAY-GATE-061",
    "RELAY-IDEMPOTENCY-001",
    "RELAY-ING-001",
    "RELAY-ING-014",
    "RELAY-ING-021",
    "RELAY-ING-022",
    "RELAY-ING-031",
    "RELAY-ING-032",
    "RELAY-RATE-001",
    "RELAY-RATE-014",
    "RELAY-RELEASE-001",
    "RELAY-RELEASE-002",
    "RELAY-RELEASE-004",
    "RELAY-RELEASE-005",
    "RELAY-RELEASE-006",
    "RELAY-RELEASE-007",
    "RELAY-RELEASE-008",
    "RELAY-RELEASE-009",
    "RELAY-RELEASE-010",
    "RELAY-RELEASE-011",
    "RELAY-RELEASE-012",
    "RELAY-RELEASE-013",
    "RELAY-RELEASE-014",
    "RELAY-RELEASE-015",
    "RELAY-RELEASE-016",
    "RELAY-RELEASE-017",
    "RELAY-RELEASE-018",
    "RELAY-RELEASE-019",
    "RELAY-RELEASE-020",
    "RELAY-RELEASE-021",
    "RELAY-RELEASE-022",
    "RELAY-RELEASE-023",
    "RELAY-RELEASE-024",
    "RELAY-RELEASE-025",
    "RELAY-RELEASE-026",
    "RELAY-RELEASE-028",
    "RELAY-RELEASE-029",
    "RELAY-RELEASE-030",
    "RELAY-RELEASE-032",
    "RELAY-RELEASE-033",
    "RELAY-RELEASE-034",
    "RELAY-RELEASE-035",
    "RELAY-RELEASE-036",
    "RELAY-RELEASE-037",
    "RELAY-RELEASE-038",
    "RELAY-RELEASE-039",
    "RELAY-RELEASE-040",
    "RELAY-RELEASE-041",
    "RELAY-RELEASE-042",
    "RELAY-RELEASE-043",
    "RELAY-RELEASE-044",
    "RELAY-RELEASE-045",
    "RELAY-RELEASE-046",
    "RELAY-RELEASE-047",
    "RELAY-REPLAY-001",
    "RELAY-REPLAY-002",
    "RELAY-REPLAY-014",
    "RELAY-SCHEMA-001",
    "RELAY-SCHEMA-011",
    "RELAY-SCHEMA-014",
    "RELAY-SCHEMA-017",
    "RELAY-SCHEMA-018",
    "RELAY-SCHEMA-023",
    "RELAY-SDK-001",
    "RELAY-SDK-002",
    "RELAY-SDK-003",
    "RELAY-SDK-004",
    "RELAY-SDK-005",
    "RELAY-SDK-006",
    "RELAY-SDK-007",
    "RELAY-SDK-008",
    "RELAY-SDK-009",
    "RELAY-SDK-010",
    "RELAY-SDK-011",
    "RELAY-SDK-012",
    "RELAY-SDK-013",
    "RELAY-SIDECAR-001",
    "RELAY-SIDECAR-002",
    "RELAY-SIDECAR-003",
    "RELAY-SIDECAR-004",
    "RELAY-SIDECAR-005",
    "RELAY-SIDECAR-006",
    "RELAY-SIDECAR-007",
    "RELAY-SIDECAR-008",
    "RELAY-SIDECAR-009",
    "RELAY-SIDECAR-010",
    "RELAY-SIDECAR-011",
    "RELAY-SIDECAR-012",
    "RELAY-SIDECAR-013",
    "RELAY-SQLITE-001",
    "RELAY-VENDOR-001",
    "RELAY-VENDOR-002",
    "RELAY-VERIFY-001",
    "RELAY-VERIFY-050",
})

__all__ = ["RelayErrorCode"]
