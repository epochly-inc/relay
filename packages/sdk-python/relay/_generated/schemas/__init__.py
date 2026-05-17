# GENERATED FILE - DO NOT EDIT BY HAND.
#
# Source: packages/schemas/raw/openapi.yaml (W1.5 OpenAPI 3.1 source-of-truth).
# Regenerate: uv run python packages/schemas/scripts/codegen.py
# Drift check: uv run python scripts/check-codegen-drift.py
#
# Per VAL-W1-033 every class is a Pydantic v2 BaseModel subclass with
# model_config = ConfigDict(extra='forbid').

"""Re-export surface for the W1.5 generated canonical envelopes.

VAL-W1-033 import path:

    from relay._generated.schemas import (
        RunResult, GateDecision, GateDecisionDraft, GateRound,
        ManifestVersion, ScopeState, IdempotencyRecord, EventLogEntry,
        EvidenceBundle, EvidenceClaim, ReplayCase, ReplayFixture,
        RedactionPolicy, ErrorEnvelope,
    )

VAL-W1-036 forward-compat: unknown ``schema_version`` values raise
``RelayUnknownSchemaVersionError`` via the Pydantic Literal pin combined with
the ``parse_envelope`` helper below. Use ``parse_envelope`` when the caller
needs a structured forward-compat error rather than a generic
``ValidationError``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ValidationError

from .. import _models as _schemas_module
from .._models import (
    Actor,
    AssertionDefinition,
    ContractResult,
    DataProvenanceRecord,
    DataQualityCheck,
    EmbeddingSpan,
    ErrorEnvelope,
    EventLogEntry,
    EvidenceBundle,
    EvidenceBundleRegistry,
    EvidenceBundleScopeState,
    EvidenceClaim,
    EvidenceLegalHold,
    EvidenceTimestamp,
    GateDecision,
    GateDecisionDraft,
    GatePolicy,
    GateRound,
    GateRoundScopeState,
    HumanOversightEvent,
    IdempotencyRecord,
    Incident,
    Manifest,
    ManifestVersion,
    ModelCallSpan,
    RedactionPolicy,
    RedactionPolicyMatcher,
    RedactionPolicyMatcherJsonPointer,
    RedactionPolicyMatcherRegex,
    RelayErrorCodeStr,
    ReplayCase,
    ReplayCaseScopeState,
    ReplayFixture,
    ReplayResult,
    RetrievalSpan,
    RootCauseHypothesis,
    RunResult,
    RunScopeState,
    ScopeState,
    Sha256Hash,
    Span,
    ToolCallSpan,
    TransparencyLogEntry,
    Ulid,
)

__all__ = [
    "Actor",
    "AssertionDefinition",
    "ContractResult",
    "DataProvenanceRecord",
    "DataQualityCheck",
    "EmbeddingSpan",
    "ErrorEnvelope",
    "EventLogEntry",
    "EvidenceBundle",
    "EvidenceBundleRegistry",
    "EvidenceBundleScopeState",
    "EvidenceClaim",
    "EvidenceLegalHold",
    "EvidenceTimestamp",
    "GateDecision",
    "GateDecisionDraft",
    "GatePolicy",
    "GateRound",
    "GateRoundScopeState",
    "HumanOversightEvent",
    "IdempotencyRecord",
    "Incident",
    "Manifest",
    "ManifestVersion",
    "ModelCallSpan",
    "RedactionPolicy",
    "RedactionPolicyMatcher",
    "RedactionPolicyMatcherJsonPointer",
    "RedactionPolicyMatcherRegex",
    "RelayErrorCodeStr",
    "ReplayCase",
    "ReplayCaseScopeState",
    "ReplayFixture",
    "ReplayResult",
    "RetrievalSpan",
    "RootCauseHypothesis",
    "RunResult",
    "RunScopeState",
    "ScopeState",
    "Sha256Hash",
    "Span",
    "ToolCallSpan",
    "TransparencyLogEntry",
    "Ulid",
    "RelayUnknownSchemaVersionError",
    "parse_envelope",
]


class RelayUnknownSchemaVersionError(ValueError):
    """Raised when a canonical envelope carries an unregistered ``schema_version``.

    Per CLAUDE.md keystone invariant #10 and spec B.7 (lines 3618-3621):
    engines refuse to write objects whose ``schema_version`` is unknown. The
    generated Pydantic models enforce this via ``Literal[...]`` pins on
    ``schema_version``; this helper surfaces the same rejection at parse time
    with a stable error type the SDK can attribute to a contract assertion.

    Attributes:
        envelope_kind: The model class name attempted (e.g. ``"RunResult"``).
        observed_version: The unknown version string from the input payload.
        expected_version: The Literal pin the model enforces.
    """

    def __init__(
        self,
        envelope_kind: str,
        observed_version: str,
        expected_version: str,
    ) -> None:
        super().__init__(
            f"unknown schema_version for {envelope_kind}: "
            f"observed={observed_version!r} expected={expected_version!r} "
            f"(VAL-W1-036, spec B.7)"
        )
        self.envelope_kind = envelope_kind
        self.observed_version = observed_version
        self.expected_version = expected_version


def parse_envelope(model: type[BaseModel], payload: Any) -> BaseModel:
    """Parse ``payload`` as ``model``; surface unknown schema_version cleanly.

    If validation fails with a ``schema_version`` Literal mismatch, raise
    ``RelayUnknownSchemaVersionError`` carrying the observed and expected
    versions. Any other validation error re-raises unchanged.

    VAL-W1-036 evidence: a payload with ``schema_version: relay.run_result.v99``
    (or any other unregistered version) raises ``RelayUnknownSchemaVersionError``;
    payloads with the correct version succeed.
    """
    try:
        return model.model_validate(payload)
    except ValidationError as e:
        for err in e.errors():
            loc = err.get("loc", ())
            if loc and loc[0] == "schema_version":
                # Pydantic emits ctx={"expected": "'relay.run_result.v1'"} for
                # literal_error. Walk the structure to extract.
                ctx = err.get("ctx", {}) or {}
                expected = str(ctx.get("expected", "<unknown>"))
                observed = err.get("input", "<missing>")
                # Normalise expected: pydantic renders as "'relay.run_result.v1'".
                expected_stripped = expected.strip().strip("'\"")
                raise RelayUnknownSchemaVersionError(
                    envelope_kind=model.__name__,
                    observed_version=str(observed),
                    expected_version=expected_stripped,
                ) from e
        raise


# Re-bind the schemas module so callers can introspect via
# ``relay._generated.schemas`` as both a module-with-symbols AND a package
# attribute.
_ = _schemas_module  # keep the import live for ``from relay._generated import schemas``
