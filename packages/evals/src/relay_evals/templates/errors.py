"""Structured exception types for the W9.2 assertion-template library.

Per CLAUDE.md keystone invariant #2 (pass without evidence is not a pass)
and the W9.2 contract assertions VAL-W9-010, VAL-W9-012, VAL-W9-014,
VAL-W9-015: every template-side rejection MUST raise a structured
exception carrying the offending JSON-Schema path (when applicable), a
canonical wire-format ``code`` token, and a deterministic ``payload`` for
the gate-runner / CLI to render. Templates NEVER silently coerce inputs,
NEVER return a fake assertion id on input failure, and NEVER load
arbitrary code from disk paths outside the installed package.

Wire-code mapping:

  - ``RelayTemplateInputError``    -> RELAY-CONTRACT-002 (input shape /
    schema validation failure; reuses the existing CONTRACT namespace
    rather than minting RELAY-TEMPLATE-NNN since templates emit
    contract-shaped objects whose validation errors share the same
    audience)
  - ``RelayTemplateLoaderError``   -> RELAY-CONTRACT-003 (loader refused
    a path outside the installed package; v0.1 forbids dynamic plugin
    loading per spec section S "Malicious assertion template upload"
    mitigation, line 5668)
  - ``RelaySchemaNotFoundError``   -> RELAY-SCHEMA-014 (canonical schema
    id resolution miss; reuses existing schema-namespace code)
  - ``RelayManifestUnknownToolError`` -> RELAY-MANIFEST-021 (a tool_arg
    template referenced a tool_name not in the active manifest tool
    registry; per VAL-W9-014 the error payload carries the manifest
    commit hash so the auditor can attribute the rejection)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from relay_schemas.error_codes import RelayErrorCode


class RelayTemplateError(Exception):
    """Base class for every assertion-template runtime exception.

    All template-side errors carry ``code`` (canonical RELAY-AREA-NNN
    wire token) and ``payload`` (deterministic dict for renderer use).
    The base exception itself is never raised directly; subclasses pin
    the wire code via the ``CODE`` class attribute.
    """

    CODE: str = ""

    def __init__(
        self,
        message: str,
        *,
        payload: Mapping[str, Any] | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message: str = message
        self.code: str = code if code is not None else self.CODE
        self.payload: dict[str, Any] = dict(payload or {})

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(code={self.code!r}, "
            f"message={self.message!r}, payload={self.payload!r})"
        )


class RelayTemplateInputError(RelayTemplateError):
    """Raised when a template's structured input fails schema validation.

    Per VAL-W9-010 the exception MUST surface the JSON-Schema path of
    the failing field via ``payload["json_path"]`` (e.g. ``$.assertions[0]
    .owner_email``). Tests bind to this field directly; the CLI renders
    it as ``Input validation failed at <json_path>: <message>``.
    """

    CODE: Final[str] = RelayErrorCode.RELAY_CONTRACT_002


class RelayTemplateLoaderError(RelayTemplateError):
    """Raised when the runtime is asked to load a template from outside.

    Per VAL-W9-012 the v0.1 runtime refuses to load templates from
    arbitrary disk paths -- only the canonical signed registry of
    package-bundled templates is permitted. ``payload["disallowed_path"]``
    carries the path the caller attempted to load; ``payload["
    permitted_names"]`` lists the registered template names.
    """

    CODE: Final[str] = RelayErrorCode.RELAY_CONTRACT_003


class RelaySchemaNotFoundError(RelayTemplateError):
    """Raised when ``schema_match_assertion_template`` fails to resolve.

    Per VAL-W9-015 the schema_match template only accepts schema ids
    that resolve against ``packages/schemas/``; inline schema bodies are
    forbidden in v0.1. ``payload["missing_schema_id"]`` carries the id
    the caller asked for; ``payload["known_schema_ids"]`` lists the
    accepted v1 ids so the caller can correct the typo.
    """

    CODE: Final[str] = RelayErrorCode.RELAY_SCHEMA_014


class RelayManifestUnknownToolError(RelayTemplateError):
    """Raised when ``tool_arg_assertion_template`` references unknown tool.

    Per VAL-W9-014 the tool_name MUST be declared in the active manifest
    tool registry (spec section F). The error payload carries:

      - ``tool_name``             the offending name
      - ``manifest_commit_hash``  the active manifest commit hash
      - ``known_tool_names``      sorted list of registered tool names

    ``manifest_commit_hash`` is the SHA-256-over-JCS-canonicalized bytes
    of the manifest (per CLAUDE.md three-anchor handoff and contract
    preamble), NOT git's blob SHA-1.
    """

    CODE: Final[str] = RelayErrorCode.RELAY_MANIFEST_021


__all__ = [
    "RelayManifestUnknownToolError",
    "RelaySchemaNotFoundError",
    "RelayTemplateError",
    "RelayTemplateInputError",
    "RelayTemplateLoaderError",
]
