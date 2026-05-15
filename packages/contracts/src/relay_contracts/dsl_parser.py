"""Relay contract DSL parser (Python).

Implements w6.4: parse + validate the five contract document kinds
defined in spec section D (BehavioralAssertion, SchemaContract,
GatePolicy, ToolArgContract, EvalAssertion). The parser is JSON-in,
:class:`ParsedContract`-out. It is deliberately storage-shape preserving:
the ``raw`` field on the parsed document is byte-equal to the input
under JCS canonicalisation (VAL-W6-040).

Public API:

  - :func:`parse_contract` -- validate envelope shape, severity, lifecycle,
    schema_version. Returns a :class:`ParsedContract`. Raises
    :class:`ContractParseError` with a structured ``code`` + ``payload``.
  - :data:`KNOWN_SCHEMA_VERSIONS` -- the v1 allowlist (spec D.1-D.5).
  - :class:`ParsedContract` -- frozen dataclass with the parsed envelope
    plus the JCS-SHA-256 ``expression_digest`` for VAL-W6-044.

Spec anchors: D.1-D.6 (lines 3758-3888), B.7 (schema versioning).
Eng plan anchors: CQ1 lines 145-157.
CLAUDE.md anchors: keystone invariant 10 (schema versioning), banned
pattern #16 (UDF purity, enforced via the publish pipeline).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from relay_schemas.error_codes import RelayErrorCode

from .canonical import jcs_canonicalize

# Allowlist of schema_version strings accepted by v1 of the DSL.
# Per VAL-W6-041 + CLAUDE.md invariant 10, anything outside this set is
# rejected at parse time -- engines refuse unknown versions on write.
KNOWN_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({
    "relay.assertion.behavioral.v1",
    "relay.assertion.schema.v1",
    "relay.gate_policy.v1",
    "relay.assertion.tool_arg.v1",
    "relay.assertion.eval.v1",
})

# Severity vocabulary per VAL-W6-043 (spec D.1 line 3769; spec S P0/P1/P2/P3
# placement). Closed set; new severities require a schema_version bump.
VALID_SEVERITIES: Final[frozenset[str]] = frozenset({"p0", "p1", "p2", "p3"})

# Lifecycle vocabulary per VAL-W6-043 (spec D.6 line 3760).
VALID_LIFECYCLES: Final[frozenset[str]] = frozenset({
    "draft", "active", "deprecated", "retired",
})

# Schema-version -> required field set (envelope shape per spec D.1-D.5).
# Notes:
#   - GatePolicy is the only kind without ``assertion_id``.
#   - GatePolicy has no severity field; instead ``blocking_severity``
#     (still drawn from VALID_SEVERITIES via a "p<digit>_only" suffix).
_REQUIRED_FIELDS: Final[dict[str, frozenset[str]]] = {
    "relay.assertion.behavioral.v1": frozenset({
        "schema_version", "assertion_id", "kind", "severity", "expression",
        "owner_email", "lifecycle_state",
    }),
    "relay.assertion.schema.v1": frozenset({
        "schema_version", "assertion_id", "kind", "severity", "schema_json",
        "owner_email", "lifecycle_state",
    }),
    "relay.gate_policy.v1": frozenset({
        "schema_version", "policy_version", "conditions",
        "owner_email", "lifecycle_state",
    }),
    "relay.assertion.tool_arg.v1": frozenset({
        "schema_version", "assertion_id", "kind", "severity", "args_schema",
        "owner_email", "lifecycle_state",
    }),
    "relay.assertion.eval.v1": frozenset({
        "schema_version", "assertion_id", "kind", "severity", "evaluator",
        "owner_email", "lifecycle_state",
    }),
}


class ContractParseError(Exception):
    """Structured error raised by the contract DSL parser.

    Carries a canonical ``RELAY-CONTRACT-NNN`` ``code`` plus a ``payload``
    dict for caller-side rendering (auditor messages, gate runner JSON).
    The CLI surface formats ``payload`` as the user-visible body; the wire
    contract is the ``code`` token.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.payload: dict[str, Any] = dict(payload or {})


@dataclass(frozen=True)
class ParsedContract:
    """A validated DSL document.

    ``raw`` is the input dict unmodified -- callers can JCS-canonicalise
    it for round-trip equality (VAL-W6-040). ``expression_digest`` is
    the SHA-256 hex digest of the JCS-canonical representation of the
    body field that uniquely identifies the assertion's behavior:

      - behavioral: SHA-256(JCS(expression))
      - schema_contract: SHA-256(JCS(schema_json))
      - tool_arg: SHA-256(JCS(args_schema))
      - eval: SHA-256(JCS(evaluator))
      - gate_policy: SHA-256(JCS(conditions))

    For VAL-W6-044 the digest enables duplicate detection across active
    assertions (spec D.6 line 3885). The digest is byte-stable across
    Python and TypeScript because JCS is deterministic and SHA-256 is
    standardised.
    """

    schema_version: str
    raw: dict[str, Any]
    expression_digest: str
    assertion_id: str | None = None
    kind: str | None = None
    severity: str | None = None
    lifecycle_state: str | None = None
    owner_email: str | None = None
    expression: Any | None = None
    body_field_name: str | None = field(default=None)


def _check_envelope(doc: Mapping[str, Any]) -> str:
    """Return the validated schema_version. Raises on missing / unknown."""
    if not isinstance(doc, Mapping):
        raise ContractParseError(
            f"Contract document MUST be a JSON object; got {type(doc).__name__}",
            code=RelayErrorCode.RELAY_CONTRACT_001,
            payload={"json_path": "$"},
        )
    schema_version = doc.get("schema_version")
    if schema_version is None:
        raise ContractParseError(
            "Contract document missing required field 'schema_version'.",
            code=RelayErrorCode.RELAY_CONTRACT_001,
            payload={"json_path": "$.schema_version"},
        )
    if not isinstance(schema_version, str):
        raise ContractParseError(
            f"Field 'schema_version' MUST be a string; got "
            f"{type(schema_version).__name__}",
            code=RelayErrorCode.RELAY_CONTRACT_001,
            payload={"json_path": "$.schema_version"},
        )
    if schema_version not in KNOWN_SCHEMA_VERSIONS:
        raise ContractParseError(
            f"Unknown schema_version: {schema_version!r}. "
            f"Allowed: {sorted(KNOWN_SCHEMA_VERSIONS)}",
            code=RelayErrorCode.RELAY_CONTRACT_001,
            payload={
                "json_path": "$.schema_version",
                "schema_version": schema_version,
                "allowed": sorted(KNOWN_SCHEMA_VERSIONS),
            },
        )
    return schema_version


def _check_required_fields(doc: Mapping[str, Any], schema_version: str) -> None:
    required = _REQUIRED_FIELDS[schema_version]
    missing = [k for k in sorted(required) if k not in doc]
    if missing:
        raise ContractParseError(
            f"Contract document missing required fields: {missing}",
            code=RelayErrorCode.RELAY_CONTRACT_001,
            payload={"json_path": "$", "missing": missing},
        )


def _check_severity(doc: Mapping[str, Any]) -> str | None:
    """Validate and return ``severity`` if the kind has one."""
    if "severity" not in doc:
        return None
    severity = doc["severity"]
    if not isinstance(severity, str) or severity not in VALID_SEVERITIES:
        raise ContractParseError(
            f"Field 'severity' MUST be one of {sorted(VALID_SEVERITIES)}; "
            f"got {severity!r}",
            code=RelayErrorCode.RELAY_CONTRACT_002,
            payload={
                "json_path": "$.severity",
                "value": severity,
                "allowed": sorted(VALID_SEVERITIES),
            },
        )
    return severity


def _check_lifecycle(doc: Mapping[str, Any]) -> str | None:
    if "lifecycle_state" not in doc:
        return None
    state = doc["lifecycle_state"]
    if not isinstance(state, str) or state not in VALID_LIFECYCLES:
        raise ContractParseError(
            f"Field 'lifecycle_state' MUST be one of {sorted(VALID_LIFECYCLES)}; "
            f"got {state!r}",
            code=RelayErrorCode.RELAY_CONTRACT_003,
            payload={
                "json_path": "$.lifecycle_state",
                "value": state,
                "allowed": sorted(VALID_LIFECYCLES),
            },
        )
    return state


# Per-kind body field used for duplicate-detection digest (VAL-W6-044).
_DIGEST_FIELD: Final[dict[str, str]] = {
    "relay.assertion.behavioral.v1": "expression",
    "relay.assertion.schema.v1": "schema_json",
    "relay.assertion.tool_arg.v1": "args_schema",
    "relay.assertion.eval.v1": "evaluator",
    "relay.gate_policy.v1": "conditions",
}


def _compute_digest(doc: Mapping[str, Any], schema_version: str) -> tuple[str, str, Any]:
    """Return (digest_hex, body_field_name, body_value)."""
    body_field = _DIGEST_FIELD[schema_version]
    body_value = doc[body_field]
    canonical_bytes = jcs_canonicalize(body_value)
    digest_hex = hashlib.sha256(canonical_bytes).hexdigest()
    return digest_hex, body_field, body_value


def parse_contract(doc: Mapping[str, Any]) -> ParsedContract:
    """Parse and validate a contract DSL document.

    Returns a :class:`ParsedContract`. Raises :class:`ContractParseError`
    on any violation -- envelope shape, unknown ``schema_version``,
    invalid ``severity``, invalid ``lifecycle_state``, missing required
    fields. CEL profile compilation is NOT performed here -- it runs at
    publish time via :func:`relay_contracts.pipeline.publish_contract`
    so an offline parser pass remains side-effect-free and fast.
    """

    schema_version = _check_envelope(doc)
    _check_required_fields(doc, schema_version)
    severity = _check_severity(doc)
    lifecycle = _check_lifecycle(doc)
    digest, body_field, body_value = _compute_digest(doc, schema_version)

    return ParsedContract(
        schema_version=schema_version,
        raw=dict(doc),
        expression_digest=digest,
        assertion_id=doc.get("assertion_id"),
        kind=doc.get("kind"),
        severity=severity,
        lifecycle_state=lifecycle,
        owner_email=doc.get("owner_email"),
        expression=body_value if body_field == "expression" else None,
        body_field_name=body_field,
    )


__all__ = [
    "KNOWN_SCHEMA_VERSIONS",
    "VALID_LIFECYCLES",
    "VALID_SEVERITIES",
    "ContractParseError",
    "ParsedContract",
    "parse_contract",
]
