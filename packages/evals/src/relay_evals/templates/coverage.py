"""``coverage_assertion_template`` (W9.2 / VAL-W9-013).

Codifies the spec section D.6 line 3879 CoverageOwner constraint as a
template the eval runner can consume:

  - exactly one ``owner_email`` per assertion id
  - no two assertion ids share an ``expression`` digest (duplicate
    detection per spec D.6 line 3885)
  - every P0/P1 assertion has a non-null, non-empty ``owner_email``
  - ``owner_email`` is NOT a known group-alias (matches the canonical
    deny-prefix list shipped at
    ``packages/schemas/raw/owner-email-deny.yaml``; tested by
    VAL-W1-060)

Failure surfacing:

  - input shape failure (missing ``assertions`` field, wrong type, etc.)
    -> ``RelayTemplateInputError`` with ``json_path`` payload
    (VAL-W9-010)
  - any of the four coverage-invariant violations
    -> ``RelayTemplateInputError`` whose ``code`` is the matching
    ``RELAY-COVERAGE-NNN`` token (001 orphan, 002 duplicate-digest,
    003 missing-owner, 004 group-alias-owner). The ``message`` form is
    stable so audit-log greps remain valid.

Returns on success: a frozen ``CoverageTemplateResult`` carrying

  - ``assertion_id``  the canonical VAL-... id derived from the
    JCS-canonicalized inputs (VAL-W9-011)
  - ``schema_id``     the input schema id (``relay.assertion.eval.coverage.v1``)
  - ``input_digest``  SHA-256 of the JCS bytes (audit attribution)
  - ``checked_count`` number of assertions surveyed
  - ``signed_by``     the registry's signed-template marker
    (``relay-bundled-template-v1``); refused-load-from-disk per
    VAL-W9-012

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from relay_contracts.canonical import jcs_canonicalize
from relay_schemas.error_codes import RelayErrorCode

from .errors import RelayTemplateInputError
from .ids import derive_assertion_id

# Canonical input schema id. Templates carry their schema id so the
# gate engine can route per-template validators without sniffing the
# input shape.
COVERAGE_TEMPLATE_SCHEMA: Final[str] = "relay.assertion.eval.coverage.v1"

# Signed-bundled marker. The registry binds this string to the
# package-bundled template; a loader that tried to import a template
# from a custom disk path would fail at the registry boundary
# (VAL-W9-012, see registry.py).
SIGNED_BY: Final[str] = "relay-bundled-template-v1"

# Severities that REQUIRE owner_email per spec D.6 + VAL-W6-062.
_OWNER_REQUIRED_SEVERITIES: Final[frozenset[str]] = frozenset({"p0", "p1"})

# Group-alias deny-prefix set. Sourced from the canonical deny-prefix
# YAML registered in W1.4 (`owner-email-deny.yaml`) per spec D.6 line
# 3886. v0.1 v hard-codes the four canonical defaults; the full
# resolution logic with workspace overrides lives in the CLI publish
# pipeline (`packages/cli/src/relay_cli/commands/contract.py:159`).
_GROUP_ALIAS_DENY_PREFIXES: Final[tuple[str, ...]] = (
    "team-",
    "group-",
    "dl-",
    "all-",
)
# Mailbox-local alias deny-set (also from the contract publish CLI).
_GROUP_ALIAS_DENY_LOCAL_PARTS: Final[frozenset[str]] = frozenset({
    "team",
    "eng",
    "ops",
    "security",
    "support",
    "noreply",
    "no-reply",
    "info",
    "admin",
    "contact",
    "hello",
    "engineering",
})

# Minimal RFC-5322 sanity check (mirrors contract.py line 189).
_EMAIL_SHAPE_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)

# Required and optional fields on the input envelope.
_REQUIRED_INPUT_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version",
    "assertions",
})
# Per VAL-W9-010, ``additionalProperties: false`` semantics: unknown top-
# level keys raise ``RelayTemplateInputError``.
_PERMITTED_INPUT_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version",
    "assertions",
    # Optional, persisted into the result digest seed for VAL-W9-011
    # determinism but not required.
    "manifest_commit_hash",
    "input_label",
})

# Required fields on each entry of ``assertions[]``.
_REQUIRED_ASSERTION_FIELDS: Final[frozenset[str]] = frozenset({
    "assertion_id",
    "severity",
    "owner_email",
    "expression_digest",
    "lifecycle_state",
})


@dataclass(frozen=True, slots=True)
class CoverageTemplateResult:
    """Frozen success envelope returned by the coverage template."""

    assertion_id: str
    schema_id: str
    input_digest: str
    checked_count: int
    signed_by: str


def _raise_input(message: str, *, json_path: str, code: str | None = None) -> None:
    raise RelayTemplateInputError(
        message,
        payload={"json_path": json_path},
        code=code,
    )


def _validate_input_envelope(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        _raise_input(
            f"Coverage template input MUST be a JSON object; got "
            f"{type(payload).__name__}",
            json_path="$",
        )
    keys = set(payload.keys())
    missing = _REQUIRED_INPUT_FIELDS - keys
    if missing:
        first = sorted(missing)[0]
        _raise_input(
            f"Coverage template input missing required field {first!r}.",
            json_path=f"$.{first}",
        )
    unknown = keys - _PERMITTED_INPUT_FIELDS
    if unknown:
        first = sorted(unknown)[0]
        _raise_input(
            f"Coverage template input has unknown field {first!r}; "
            f"permitted: {sorted(_PERMITTED_INPUT_FIELDS)}",
            json_path=f"$.{first}",
        )
    if payload["schema_version"] != COVERAGE_TEMPLATE_SCHEMA:
        _raise_input(
            f"Coverage template requires schema_version "
            f"{COVERAGE_TEMPLATE_SCHEMA!r}; got "
            f"{payload['schema_version']!r}",
            json_path="$.schema_version",
        )
    assertions = payload["assertions"]
    if not isinstance(assertions, list):
        _raise_input(
            f"$.assertions MUST be a JSON array; got "
            f"{type(assertions).__name__}",
            json_path="$.assertions",
        )
    return payload


def _validate_assertion_envelope(item: Any, *, idx: int) -> Mapping[str, Any]:
    base_path = f"$.assertions[{idx}]"
    if not isinstance(item, Mapping):
        _raise_input(
            f"{base_path} MUST be a JSON object; got {type(item).__name__}",
            json_path=base_path,
        )
    keys = set(item.keys())
    missing = _REQUIRED_ASSERTION_FIELDS - keys
    if missing:
        first = sorted(missing)[0]
        _raise_input(
            f"{base_path} missing required field {first!r}.",
            json_path=f"{base_path}.{first}",
        )
    return item


def _check_group_alias(owner_email: str) -> bool:
    """Return True iff ``owner_email`` matches a group-alias deny pattern."""
    local_part, _, _domain = owner_email.partition("@")
    local_lower = local_part.lower()
    if local_lower in _GROUP_ALIAS_DENY_LOCAL_PARTS:
        return True
    return any(
        local_lower.startswith(prefix) for prefix in _GROUP_ALIAS_DENY_PREFIXES
    )


def coverage_assertion_template(
    payload: Mapping[str, Any],
    *,
    _signed_by: str | None = None,
) -> CoverageTemplateResult:
    """Validate coverage invariants over a contract assertion bundle.

    Per VAL-W9-013, rejects:

      - orphan assertions (asserted by the publish gate, not here, since
        a template cannot see the gate registry; the per-assertion-id
        uniqueness within the input is what THIS template enforces).
      - duplicate ``expression_digest`` across two ``active`` assertions
      - P0/P1 assertion with null/empty/absent ``owner_email``
      - ``owner_email`` matching a known group-alias deny pattern
      - same ``assertion_id`` appearing twice in ``assertions[]``
        (a structural duplication; raised as RELAY-COVERAGE-001 since
        it is the most specific way the input can be self-orphaning).

    The ``_signed_by`` keyword is internal: the registry passes the
    package-bundled marker; direct callers leave it None and the
    template falls back to :data:`SIGNED_BY`. This is the v0.1 v of
    the "no plugin loader" rule (VAL-W9-012); the public API does NOT
    accept a custom value.
    """
    envelope = _validate_input_envelope(payload)
    assertions = envelope["assertions"]
    seen_assertion_ids: dict[str, int] = {}
    digest_to_owner: dict[str, str] = {}

    for idx, item in enumerate(assertions):
        entry = _validate_assertion_envelope(item, idx=idx)
        base_path = f"$.assertions[{idx}]"
        assertion_id = entry["assertion_id"]
        severity = entry["severity"]
        owner_email = entry["owner_email"]
        expression_digest = entry["expression_digest"]
        lifecycle = entry["lifecycle_state"]

        if not isinstance(assertion_id, str) or not assertion_id:
            _raise_input(
                f"{base_path}.assertion_id MUST be a non-empty string.",
                json_path=f"{base_path}.assertion_id",
            )
        if assertion_id in seen_assertion_ids:
            raise RelayTemplateInputError(
                f"{base_path}.assertion_id {assertion_id!r} duplicates "
                f"$.assertions[{seen_assertion_ids[assertion_id]}].assertion_id "
                "(orphan-by-self-duplication).",
                payload={
                    "json_path": f"{base_path}.assertion_id",
                    "assertion_id": assertion_id,
                    "first_index": seen_assertion_ids[assertion_id],
                    "duplicate_index": idx,
                },
                code=RelayErrorCode.RELAY_COVERAGE_001,
            )
        seen_assertion_ids[assertion_id] = idx

        if not isinstance(severity, str) or severity not in {"p0", "p1", "p2", "p3"}:
            _raise_input(
                f"{base_path}.severity MUST be one of {{p0,p1,p2,p3}}; got "
                f"{severity!r}",
                json_path=f"{base_path}.severity",
            )
        if not isinstance(lifecycle, str) or lifecycle not in {
            "draft", "active", "deprecated", "retired",
        }:
            _raise_input(
                f"{base_path}.lifecycle_state MUST be one of "
                f"{{draft,active,deprecated,retired}}; got {lifecycle!r}",
                json_path=f"{base_path}.lifecycle_state",
            )

        # Owner-email checks ONLY apply to active assertions; deprecated /
        # retired assertions may have stale owners by design (spec D.6).
        if lifecycle == "active":
            if owner_email is None or owner_email == "":
                if severity in _OWNER_REQUIRED_SEVERITIES:
                    raise RelayTemplateInputError(
                        f"{base_path}: P0/P1 assertion missing owner_email.",
                        payload={
                            "json_path": f"{base_path}.owner_email",
                            "assertion_id": assertion_id,
                            "severity": severity,
                        },
                        code=RelayErrorCode.RELAY_COVERAGE_003,
                    )
            else:
                if not isinstance(owner_email, str):
                    _raise_input(
                        f"{base_path}.owner_email MUST be a string; got "
                        f"{type(owner_email).__name__}",
                        json_path=f"{base_path}.owner_email",
                    )
                if not _EMAIL_SHAPE_RE.match(owner_email):
                    _raise_input(
                        f"{base_path}.owner_email {owner_email!r} fails RFC-5322 "
                        "shape (local@domain.tld).",
                        json_path=f"{base_path}.owner_email",
                    )
                if _check_group_alias(owner_email):
                    raise RelayTemplateInputError(
                        f"{base_path}.owner_email {owner_email!r} is a "
                        "group-alias; assertion owners MUST be persons.",
                        payload={
                            "json_path": f"{base_path}.owner_email",
                            "assertion_id": assertion_id,
                            "owner_email": owner_email,
                        },
                        code=RelayErrorCode.RELAY_COVERAGE_004,
                    )

            if not isinstance(expression_digest, str) or not expression_digest:
                _raise_input(
                    f"{base_path}.expression_digest MUST be a non-empty string.",
                    json_path=f"{base_path}.expression_digest",
                )
            prior_owner = digest_to_owner.get(expression_digest)
            if prior_owner is not None and prior_owner != assertion_id:
                raise RelayTemplateInputError(
                    f"{base_path}.expression_digest collides with active "
                    f"assertion {prior_owner!r}: two active assertions cannot "
                    "share an expression digest.",
                    payload={
                        "json_path": f"{base_path}.expression_digest",
                        "expression_digest": expression_digest,
                        "first_assertion_id": prior_owner,
                        "duplicate_assertion_id": assertion_id,
                    },
                    code=RelayErrorCode.RELAY_COVERAGE_002,
                )
            digest_to_owner[expression_digest] = assertion_id

    seed_bytes = jcs_canonicalize(envelope)
    input_digest = hashlib.sha256(seed_bytes).hexdigest()
    label = envelope.get("input_label", "BUNDLE")
    if not isinstance(label, str):
        label = "BUNDLE"
    assertion_id = derive_assertion_id(
        domain="COVERAGE",
        slug=label,
        seed=seed_bytes,
    )

    return CoverageTemplateResult(
        assertion_id=assertion_id,
        schema_id=COVERAGE_TEMPLATE_SCHEMA,
        input_digest=input_digest,
        checked_count=len(assertions),
        signed_by=_signed_by if _signed_by is not None else SIGNED_BY,
    )


__all__ = [
    "COVERAGE_TEMPLATE_SCHEMA",
    "CoverageTemplateResult",
    "SIGNED_BY",
    "coverage_assertion_template",
]
