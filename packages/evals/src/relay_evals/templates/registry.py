"""Signed assertion-template registry (W9.2 / VAL-W9-012).

Per VAL-W9-012, in v0.1 the runtime ships a fixed allow-list of
package-bundled assertion templates -- no plugin loader, no dynamic
import from a customer-supplied disk path, no eval()-of-expression at
publish time. The mitigation comes from spec section S row "Malicious
assertion template upload" (line 5668): templates are versioned in the
public `relay` repo, code-reviewed via PR, and shipped as part of the
signed package release.

This module is the choke point that enforces that policy:

  - :data:`REGISTERED_TEMPLATES` -- the closed allow-list.
  - :func:`get_template` -- look up a template by canonical name; raises
    :class:`RelayTemplateLoaderError` on miss.
  - :func:`load_template_from_path` -- the documented "loader" surface
    for v0.1 always raises :class:`RelayTemplateLoaderError`. The
    function exists so customers who wired a generic loader in a beta
    surface get a structured error instead of an opaque AttributeError
    or worse, a silent success.
  - :func:`list_template_names` -- introspectable name list returned by
    ``rly contract templates list`` per VAL-W9-009.

Each registered template is paired with its input ``schema_id`` and
the signed-bundled marker (``relay-bundled-template-v1``). The runtime
NEVER passes a different signed-by value through to a template; the
``_signed_by`` keyword on each template is reserved for the registry
to demonstrate the seal at the boundary.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

from .coverage import (
    COVERAGE_TEMPLATE_SCHEMA,
    coverage_assertion_template,
)
from .errors import RelayTemplateLoaderError
from .schema_match import (
    SCHEMA_MATCH_TEMPLATE_SCHEMA,
    schema_match_assertion_template,
)
from .tool_arg import (
    TOOL_ARG_TEMPLATE_SCHEMA,
    tool_arg_assertion_template,
)

# The v0.1 signed-bundled marker. The CI-reviewed package release is the
# trust anchor; spec section AO defers cryptographic transparency-log
# attestation of OSS templates to a later milestone.
SIGNED_BUNDLED_MARKER: Final[str] = "relay-bundled-template-v1"

# Canonical template names. ``rly contract templates list`` returns
# this set verbatim; tests bind to the exact strings so a rename here
# is a public-API change requiring a contract amendment.
COVERAGE_TEMPLATE_NAME: Final[str] = "coverage_assertion_template"
TOOL_ARG_TEMPLATE_NAME: Final[str] = "tool_arg_assertion_template"
SCHEMA_MATCH_TEMPLATE_NAME: Final[str] = "schema_match_assertion_template"


@runtime_checkable
class _TemplateCallable(Protocol):
    """Callable shape every registered template satisfies.

    Each template accepts a JSON-shape ``payload`` Mapping and returns
    a frozen result dataclass with at least ``assertion_id`` and
    ``schema_id``.
    """

    def __call__(
        self, payload: Mapping[str, Any], *, _signed_by: str | None = ...
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class RegisteredTemplate:
    """Frozen registry entry.

    ``call`` is invoked by the registry surface (never by callers
    directly via this attribute, by convention) so the seal-passing
    happens at the boundary.
    """

    name: str
    schema_id: str
    call: _TemplateCallable
    signed_by: str = SIGNED_BUNDLED_MARKER


REGISTERED_TEMPLATES: Final[Mapping[str, RegisteredTemplate]] = {
    COVERAGE_TEMPLATE_NAME: RegisteredTemplate(
        name=COVERAGE_TEMPLATE_NAME,
        schema_id=COVERAGE_TEMPLATE_SCHEMA,
        call=coverage_assertion_template,
    ),
    TOOL_ARG_TEMPLATE_NAME: RegisteredTemplate(
        name=TOOL_ARG_TEMPLATE_NAME,
        schema_id=TOOL_ARG_TEMPLATE_SCHEMA,
        call=tool_arg_assertion_template,
    ),
    SCHEMA_MATCH_TEMPLATE_NAME: RegisteredTemplate(
        name=SCHEMA_MATCH_TEMPLATE_NAME,
        schema_id=SCHEMA_MATCH_TEMPLATE_SCHEMA,
        call=schema_match_assertion_template,
    ),
}


def list_template_names() -> tuple[str, ...]:
    """Return the canonical template name set.

    Sorted lexicographically so ``rly contract templates list`` output
    is deterministic across runs (VAL-W9-009 evidence pairs to the CLI
    stdout JSON listing).
    """
    return tuple(sorted(REGISTERED_TEMPLATES.keys()))


def get_template(name: str) -> RegisteredTemplate:
    """Look up a registered template by canonical name.

    Raises :class:`RelayTemplateLoaderError` on miss. The error payload
    enumerates the permitted names so the caller can correct the typo
    or learn the v0.1 surface.
    """
    if not isinstance(name, str):
        raise RelayTemplateLoaderError(
            f"template name MUST be a string; got {type(name).__name__}",
            payload={
                "permitted_names": list(list_template_names()),
            },
        )
    entry = REGISTERED_TEMPLATES.get(name)
    if entry is None:
        raise RelayTemplateLoaderError(
            f"template name {name!r} is not in the v0.1 signed registry; "
            "v0.1 ships a fixed allow-list and does NOT support plugin "
            "loaders.",
            payload={
                "requested_name": name,
                "permitted_names": list(list_template_names()),
            },
        )
    return entry


def invoke_template(
    name: str,
    payload: Mapping[str, Any],
) -> Any:
    """Look up + invoke a registered template.

    The registry is the only call site that passes the signed-bundled
    marker through to the template's ``_signed_by`` keyword. Direct
    callers of the template functions get the default marker; passing a
    different value is reserved for this registry boundary so the seal
    cannot be forged from outside.
    """
    entry = get_template(name)
    return entry.call(payload, _signed_by=entry.signed_by)


def load_template_from_path(path: str) -> Any:
    """Documented loader surface; ALWAYS raises in v0.1.

    Per VAL-W9-012 the runtime refuses to load templates from disk
    paths outside the installed package. This function exists so any
    caller that wired a generic loader in a beta surface receives a
    structured :class:`RelayTemplateLoaderError` rather than an opaque
    import-time failure (or worse, a successful load of an attacker
    template). v0.2+ may relax this with signed plugin manifests; v0.1
    does not.
    """
    raise RelayTemplateLoaderError(
        f"v0.1 forbids loading templates from disk paths; refused {path!r}.",
        payload={
            "disallowed_path": path,
            "permitted_names": list(list_template_names()),
        },
    )


__all__ = [
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
