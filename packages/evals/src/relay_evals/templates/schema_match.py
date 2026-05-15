"""``schema_match_assertion_template`` (W9.2 / VAL-W9-015).

Per VAL-W9-015 the schema_match template MUST resolve schemas BY ID
from ``packages/schemas/`` (the canonical schemas package); inline
schema bodies are forbidden in v0.1. An unknown id raises
:class:`RelaySchemaNotFoundError`. Schema ids outside the supported
``v1`` set are rejected per spec section B.7 (schema versioning rules).

Input shape (``relay.assertion.eval.schema_match.v1``):

    {
      "schema_version":   "relay.assertion.eval.schema_match.v1",
      "schema_id":        "<one of KNOWN_SCHEMA_IDS>",
      "input_label":      "<optional human label>"  (OPTIONAL)
    }

Failure surfacing:

  - shape failure -> ``RelayTemplateInputError`` with json_path
    (VAL-W9-010)
  - unknown schema_id (or schema_id outside the v1 supported set per
    spec B.7) -> ``RelaySchemaNotFoundError`` with the missing id
    and the sorted list of known ids

Returns on success: ``SchemaMatchTemplateResult`` with the canonical
deterministic ``assertion_id`` (VAL-W9-011) and the resolved schema id
echoed for downstream validator binding.

The list of known schema ids is sourced from the relay_schemas
package's :data:`KNOWN_SCHEMA_IDS` so this template stays in lockstep
with the canonical schema YAML at ``packages/schemas/raw/envelopes.yaml``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from relay_contracts.canonical import jcs_canonicalize

from .errors import RelaySchemaNotFoundError, RelayTemplateInputError
from .ids import derive_assertion_id

SCHEMA_MATCH_TEMPLATE_SCHEMA: Final[str] = "relay.assertion.eval.schema_match.v1"

SIGNED_BY: Final[str] = "relay-bundled-template-v1"

# Canonical schema ids the v0.1 template accepts. Sourced from the
# canonical envelope YAML at ``packages/schemas/raw/envelopes.yaml``;
# every id below has a corresponding generated Pydantic v2 model in
# :mod:`relay_schemas.envelopes` and a SQL migration under
# ``packages/schemas/sql/``. Anything outside this set is rejected per
# CLAUDE.md keystone invariant #10 (engines refuse unknown
# schema_versions on write).
KNOWN_SCHEMA_IDS: Final[frozenset[str]] = frozenset({
    "relay.run_result.v1",
    "relay.gate_decision.v1",
    "relay.gate_decision_draft.v1",
    "relay.gate_round.v1",
    "relay.manifest.v1",
    "relay.scope_state.v1",
    "relay.idempotency_record.v1",
    "relay.evidence_bundle.v1",
    "relay.evidence_claim.v1",
    "relay.replay_case.v1",
    "relay.replay_fixture.v1",
    "relay.event_log_entry.v1",
    "relay.redaction.v1",
    "relay.error.v1",
})

_REQUIRED_INPUT_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version",
    "schema_id",
})
_PERMITTED_INPUT_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version",
    "schema_id",
    "input_label",
})

# Disallowed keys that historically callers might attempt (inline schema
# bodies). Per VAL-W9-015 these are forbidden in v0.1: schemas resolve
# by id, never by inline body. The presence of either key is an
# additionalProperties violation but the explicit message is more
# auditor-friendly.
_FORBIDDEN_INLINE_KEYS: Final[frozenset[str]] = frozenset({
    "schema",
    "schema_body",
    "inline_schema",
    "schema_json",
})


@dataclass(frozen=True, slots=True)
class SchemaMatchTemplateResult:
    """Frozen success envelope returned by the schema_match template."""

    assertion_id: str
    schema_id: str
    resolved_schema_id: str
    input_digest: str
    signed_by: str


def _raise_input(message: str, *, json_path: str) -> None:
    raise RelayTemplateInputError(message, payload={"json_path": json_path})


def _validate_envelope(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        _raise_input(
            f"schema_match template input MUST be a JSON object; got "
            f"{type(payload).__name__}",
            json_path="$",
        )
    keys = set(payload.keys())

    # Catch inline-schema attempts BEFORE the generic
    # additionalProperties check so the error message is specific.
    forbidden = keys & _FORBIDDEN_INLINE_KEYS
    if forbidden:
        first = sorted(forbidden)[0]
        _raise_input(
            f"schema_match template REFUSES inline schema bodies in v0.1 "
            f"(forbidden field {first!r}); resolve by schema_id only.",
            json_path=f"$.{first}",
        )

    missing = _REQUIRED_INPUT_FIELDS - keys
    if missing:
        first = sorted(missing)[0]
        _raise_input(
            f"schema_match template input missing required field {first!r}.",
            json_path=f"$.{first}",
        )
    unknown = keys - _PERMITTED_INPUT_FIELDS
    if unknown:
        first = sorted(unknown)[0]
        _raise_input(
            f"schema_match template input has unknown field {first!r}; "
            f"permitted: {sorted(_PERMITTED_INPUT_FIELDS)}",
            json_path=f"$.{first}",
        )
    if payload["schema_version"] != SCHEMA_MATCH_TEMPLATE_SCHEMA:
        _raise_input(
            f"schema_match template requires schema_version "
            f"{SCHEMA_MATCH_TEMPLATE_SCHEMA!r}; got "
            f"{payload['schema_version']!r}",
            json_path="$.schema_version",
        )
    schema_id = payload["schema_id"]
    if not isinstance(schema_id, str) or not schema_id:
        _raise_input(
            "$.schema_id MUST be a non-empty string.",
            json_path="$.schema_id",
        )
    return payload


def schema_match_assertion_template(
    payload: Mapping[str, Any],
    *,
    _signed_by: str | None = None,
) -> SchemaMatchTemplateResult:
    """Resolve a canonical schema id and return a deterministic result.

    Per VAL-W9-015:
      - ``schema_id`` MUST be in :data:`KNOWN_SCHEMA_IDS` (the v0.1
        supported set; sourced from ``packages/schemas/raw/envelopes.yaml``).
      - Inline schema bodies (``schema``, ``schema_body``,
        ``inline_schema``, ``schema_json``) are REFUSED.
      - On unknown id: ``RelaySchemaNotFoundError`` carries
        ``missing_schema_id`` and the sorted ``known_schema_ids``.
    """
    envelope = _validate_envelope(payload)
    schema_id = envelope["schema_id"]
    if schema_id not in KNOWN_SCHEMA_IDS:
        raise RelaySchemaNotFoundError(
            f"schema_id {schema_id!r} is not a canonical relay schema id; "
            "see packages/schemas/raw/envelopes.yaml for the supported set.",
            payload={
                "json_path": "$.schema_id",
                "missing_schema_id": schema_id,
                "known_schema_ids": sorted(KNOWN_SCHEMA_IDS),
            },
        )
    seed_bytes = jcs_canonicalize(envelope)
    input_digest = hashlib.sha256(seed_bytes).hexdigest()
    assertion_id = derive_assertion_id(
        domain="SCHEMAMATCH",
        slug=schema_id,
        seed=seed_bytes,
    )
    return SchemaMatchTemplateResult(
        assertion_id=assertion_id,
        schema_id=SCHEMA_MATCH_TEMPLATE_SCHEMA,
        resolved_schema_id=schema_id,
        input_digest=input_digest,
        signed_by=_signed_by if _signed_by is not None else SIGNED_BY,
    )


__all__ = [
    "KNOWN_SCHEMA_IDS",
    "SCHEMA_MATCH_TEMPLATE_SCHEMA",
    "SIGNED_BY",
    "SchemaMatchTemplateResult",
    "schema_match_assertion_template",
]
