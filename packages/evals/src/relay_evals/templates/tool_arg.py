"""``tool_arg_assertion_template`` (W9.2 / VAL-W9-014).

Per VAL-W9-014, a tool_arg eval assertion declares the tool_name it
constrains; the template MUST refuse a tool_name that is not declared
in the active manifest tool registry. The template NEVER fabricates a
tool definition (per spec section F manifest source-of-truth and
CLAUDE.md keystone invariant #3).

Input shape (``relay.assertion.eval.tool_arg.v1``):

    {
      "schema_version": "relay.assertion.eval.tool_arg.v1",
      "tool_name":            "<declared tool name>",
      "args_schema":          {<JSON-Schema subset>},
      "manifest_commit_hash": "<sha256-...>",
      "tool_registry": {
        "<tool_name>": {
          "side_effect_class": "read_only|mutating|...",
          ...
        },
        ...
      },
      "input_label":          "<optional human label>"  (OPTIONAL)
    }

Failure surfacing:

  - shape failure -> ``RelayTemplateInputError`` with json_path
    (VAL-W9-010)
  - tool_name not in tool_registry ->
    ``RelayManifestUnknownToolError`` carrying ``tool_name``,
    ``manifest_commit_hash`` and the sorted ``known_tool_names``
    (VAL-W9-014)

Returns on success: ``ToolArgTemplateResult`` with the canonical
deterministic ``assertion_id`` (VAL-W9-011) and the tool's
``side_effect_class`` echoed for downstream replay-policy routing.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, NoReturn

from relay_contracts.canonical import jcs_canonicalize

from .errors import RelayManifestUnknownToolError, RelayTemplateInputError
from .ids import derive_assertion_id

TOOL_ARG_TEMPLATE_SCHEMA: Final[str] = "relay.assertion.eval.tool_arg.v1"

SIGNED_BY: Final[str] = "relay-bundled-template-v1"

# Canonical sha256 wire form (mirrors envelopes.py SHA256_HASH_PATTERN).
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^sha256-[0-9a-f]{64}$")

_REQUIRED_INPUT_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version",
    "tool_name",
    "args_schema",
    "manifest_commit_hash",
    "tool_registry",
})
_PERMITTED_INPUT_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version",
    "tool_name",
    "args_schema",
    "manifest_commit_hash",
    "tool_registry",
    "input_label",
})

# Manifest-side accepted side_effect_class vocabulary (spec section F /
# replay_fixtures table at spec line 3164). Mirrored on the manifest's
# command schema. v0.1 accepts the four canonical classes; anything else
# is treated as an unknown registry entry.
_VALID_SIDE_EFFECT_CLASSES: Final[frozenset[str]] = frozenset({
    "none",
    "read_only",
    "reversible",
    "mutating",
    "external_irreversible",
    "approval_required",
})


@dataclass(frozen=True, slots=True)
class ToolArgTemplateResult:
    """Frozen success envelope returned by the tool_arg template."""

    assertion_id: str
    schema_id: str
    input_digest: str
    tool_name: str
    side_effect_class: str
    manifest_commit_hash: str
    signed_by: str


def _raise_input(message: str, *, json_path: str) -> NoReturn:
    raise RelayTemplateInputError(message, payload={"json_path": json_path})


def _validate_envelope(payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        _raise_input(
            f"tool_arg template input MUST be a JSON object; got "
            f"{type(payload).__name__}",
            json_path="$",
        )
    keys = set(payload.keys())
    missing = _REQUIRED_INPUT_FIELDS - keys
    if missing:
        first = sorted(missing)[0]
        _raise_input(
            f"tool_arg template input missing required field {first!r}.",
            json_path=f"$.{first}",
        )
    unknown = keys - _PERMITTED_INPUT_FIELDS
    if unknown:
        first = sorted(unknown)[0]
        _raise_input(
            f"tool_arg template input has unknown field {first!r}; "
            f"permitted: {sorted(_PERMITTED_INPUT_FIELDS)}",
            json_path=f"$.{first}",
        )
    if payload["schema_version"] != TOOL_ARG_TEMPLATE_SCHEMA:
        _raise_input(
            f"tool_arg template requires schema_version "
            f"{TOOL_ARG_TEMPLATE_SCHEMA!r}; got "
            f"{payload['schema_version']!r}",
            json_path="$.schema_version",
        )
    if not isinstance(payload["tool_name"], str) or not payload["tool_name"]:
        _raise_input(
            "$.tool_name MUST be a non-empty string.",
            json_path="$.tool_name",
        )
    if not isinstance(payload["args_schema"], Mapping):
        _raise_input(
            f"$.args_schema MUST be a JSON object; got "
            f"{type(payload['args_schema']).__name__}",
            json_path="$.args_schema",
        )
    mch = payload["manifest_commit_hash"]
    if not isinstance(mch, str) or not _SHA256_RE.match(mch):
        _raise_input(
            f"$.manifest_commit_hash MUST match {_SHA256_RE.pattern}; got "
            f"{mch!r}",
            json_path="$.manifest_commit_hash",
        )
    registry = payload["tool_registry"]
    if not isinstance(registry, Mapping):
        _raise_input(
            f"$.tool_registry MUST be a JSON object keyed by tool_name; got "
            f"{type(registry).__name__}",
            json_path="$.tool_registry",
        )
    return payload


def tool_arg_assertion_template(
    payload: Mapping[str, Any],
    *,
    _signed_by: str | None = None,
) -> ToolArgTemplateResult:
    """Validate a tool_arg assertion against a manifest tool registry.

    Per VAL-W9-014:
      - the ``tool_name`` MUST be a key of ``tool_registry`` (Mapping
        derived from the active manifest's tool declarations).
      - on miss, raises :class:`RelayManifestUnknownToolError` with
        ``tool_name``, ``manifest_commit_hash`` and the sorted
        ``known_tool_names`` so the auditor can attribute the rejection.
      - the template MUST NOT fabricate a tool definition; the
        registry is consumed read-only.
    """
    envelope = _validate_envelope(payload)
    tool_name = envelope["tool_name"]
    registry = envelope["tool_registry"]
    manifest_commit_hash = envelope["manifest_commit_hash"]
    known = sorted(str(k) for k in registry)

    if tool_name not in registry:
        raise RelayManifestUnknownToolError(
            f"tool_name {tool_name!r} is not declared in the active manifest "
            "tool registry; templates MUST NOT fabricate tool definitions.",
            payload={
                "json_path": "$.tool_name",
                "tool_name": tool_name,
                "manifest_commit_hash": manifest_commit_hash,
                "known_tool_names": known,
            },
        )

    tool_def = registry[tool_name]
    if not isinstance(tool_def, Mapping):
        _raise_input(
            f"$.tool_registry[{tool_name!r}] MUST be a JSON object; got "
            f"{type(tool_def).__name__}",
            json_path=f"$.tool_registry.{tool_name}",
        )
    side_effect_class = tool_def.get("side_effect_class")
    if not isinstance(side_effect_class, str) or (
        side_effect_class not in _VALID_SIDE_EFFECT_CLASSES
    ):
        _raise_input(
            f"$.tool_registry[{tool_name!r}].side_effect_class MUST be one of "
            f"{sorted(_VALID_SIDE_EFFECT_CLASSES)}; got {side_effect_class!r}",
            json_path=f"$.tool_registry.{tool_name}.side_effect_class",
        )

    seed_bytes = jcs_canonicalize(envelope)
    input_digest = hashlib.sha256(seed_bytes).hexdigest()
    assertion_id = derive_assertion_id(
        domain="TOOLARG",
        slug=tool_name,
        seed=seed_bytes,
    )
    return ToolArgTemplateResult(
        assertion_id=assertion_id,
        schema_id=TOOL_ARG_TEMPLATE_SCHEMA,
        input_digest=input_digest,
        tool_name=tool_name,
        side_effect_class=side_effect_class,
        manifest_commit_hash=manifest_commit_hash,
        signed_by=_signed_by if _signed_by is not None else SIGNED_BY,
    )


__all__ = [
    "SIGNED_BY",
    "TOOL_ARG_TEMPLATE_SCHEMA",
    "ToolArgTemplateResult",
    "tool_arg_assertion_template",
]
