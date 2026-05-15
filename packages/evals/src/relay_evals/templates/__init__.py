"""Relay assertion template library (W9.2; VAL-W9-009..015).

Public re-exports for the three v0.1 assertion templates plus the
signed registry surface. Per VAL-W9-009 the three named templates
exposed at the package level are:

  - :func:`coverage_assertion_template`     (VAL-W9-013)
  - :func:`tool_arg_assertion_template`     (VAL-W9-014)
  - :func:`schema_match_assertion_template` (VAL-W9-015)

Loader surface (VAL-W9-012):

  - :func:`load_template_from_path`  -- ALWAYS raises in v0.1
  - :func:`get_template`             -- registry lookup
  - :func:`invoke_template`          -- registry-mediated invocation
  - :func:`list_template_names`      -- introspection

Structured errors (VAL-W9-010, 012, 014, 015):

  - :class:`RelayTemplateInputError`
  - :class:`RelayTemplateLoaderError`
  - :class:`RelayManifestUnknownToolError`
  - :class:`RelaySchemaNotFoundError`

Deterministic id derivation (VAL-W9-011):

  - :func:`derive_assertion_id`
  - :data:`ASSERTION_ID_PATTERN`

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from .coverage import (
    COVERAGE_TEMPLATE_SCHEMA,
    CoverageTemplateResult,
    coverage_assertion_template,
)
from .errors import (
    RelayManifestUnknownToolError,
    RelaySchemaNotFoundError,
    RelayTemplateError,
    RelayTemplateInputError,
    RelayTemplateLoaderError,
)
from .ids import (
    ASSERTION_ID_PATTERN,
    ASSERTION_ID_RE,
    derive_assertion_id,
)
from .registry import (
    COVERAGE_TEMPLATE_NAME,
    REGISTERED_TEMPLATES,
    SCHEMA_MATCH_TEMPLATE_NAME,
    SIGNED_BUNDLED_MARKER,
    TOOL_ARG_TEMPLATE_NAME,
    RegisteredTemplate,
    get_template,
    invoke_template,
    list_template_names,
    load_template_from_path,
)
from .schema_match import (
    KNOWN_SCHEMA_IDS,
    SCHEMA_MATCH_TEMPLATE_SCHEMA,
    SchemaMatchTemplateResult,
    schema_match_assertion_template,
)
from .tool_arg import (
    TOOL_ARG_TEMPLATE_SCHEMA,
    ToolArgTemplateResult,
    tool_arg_assertion_template,
)

__all__ = [
    # ids
    "ASSERTION_ID_PATTERN",
    "ASSERTION_ID_RE",
    "derive_assertion_id",
    # errors
    "RelayManifestUnknownToolError",
    "RelaySchemaNotFoundError",
    "RelayTemplateError",
    "RelayTemplateInputError",
    "RelayTemplateLoaderError",
    # coverage
    "COVERAGE_TEMPLATE_SCHEMA",
    "CoverageTemplateResult",
    "coverage_assertion_template",
    # tool_arg
    "TOOL_ARG_TEMPLATE_SCHEMA",
    "ToolArgTemplateResult",
    "tool_arg_assertion_template",
    # schema_match
    "KNOWN_SCHEMA_IDS",
    "SCHEMA_MATCH_TEMPLATE_SCHEMA",
    "SchemaMatchTemplateResult",
    "schema_match_assertion_template",
    # registry
    "COVERAGE_TEMPLATE_NAME",
    "REGISTERED_TEMPLATES",
    "RegisteredTemplate",
    "SCHEMA_MATCH_TEMPLATE_NAME",
    "SIGNED_BUNDLED_MARKER",
    "TOOL_ARG_TEMPLATE_NAME",
    "get_template",
    "invoke_template",
    "list_template_names",
    "load_template_from_path",
]
