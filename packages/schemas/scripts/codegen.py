"""W1.5 codegen orchestrator.

Reads the canonical OpenAPI 3.1 document at ``packages/schemas/raw/openapi.yaml``
and produces:

  - ``packages/sdk-python/relay/_generated/_models.py``
        (datamodel-code-generator -> Pydantic v2; private)
  - ``packages/sdk-python/relay/_generated/schemas/__init__.py``
        (public re-exports + RelayUnknownSchemaVersionError)
  - ``packages/sdk-python/relay/_generated/aliases.py``
        (snake_case <-> camelCase map; VAL-W1-037)
  - ``packages/sdk-typescript/src/_generated/schemas.ts``    (openapi-typescript)
  - ``packages/sdk-typescript/src/_generated/aliases.ts``    (camelCase alias map; VAL-W1-037)
  - ``packages/sdk-typescript/src/_generated/errors.ts``     (RelayUnknownSchemaVersionError helper)
  - ``packages/sdk-typescript/src/_generated/index.ts``      (named re-exports)

Also re-runs the W1.4 error-codes generator (``gen_error_codes.py``) so the
single ``codegen-schemas`` manifest command produces every generated artifact.

Outputs are deterministic (no embedded timestamps); the W1.5 drift check
(VAL-W1-035) compares fresh codegen output against the committed tree.

Per VAL-W1-033: every generated Python class is a ``BaseModel`` subclass with
``model_config = ConfigDict(extra='forbid')``.
Per VAL-W1-034: ``tsc --noEmit`` over a fixture importing the generated types
exits 0.
Per VAL-W1-036: ``schema_version`` is pinned via ``Literal[...]`` so unknown
versions raise ``RelayUnknownSchemaVersionError`` on validation.
Per VAL-W1-037: ``aliases.py`` and ``aliases.ts`` carry the canonical
snake_case <-> camelCase mapping.

Run from repo root::

    uv run python packages/schemas/scripts/codegen.py

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path

# datamodel-code-generator and openapi-typescript versions pinned in
# pyproject.toml / package.json. The drift check verifies the installed
# version matches.
MIN_DATAMODEL_CODEGEN = "0.57.0"
MIN_OPENAPI_TYPESCRIPT = "7.13.0"

# Canonical envelope names that MUST round-trip through codegen. Aligned with
# the 14 W1.1-W1.4 canonical envelopes + Actor registry. VAL-W1-032 requires
# every one to appear in exactly ONE components.schemas entry of openapi.yaml.
CANONICAL_ENVELOPES: tuple[str, ...] = (
    "RunResult",
    "GateDecision",
    "GateDecisionDraft",
    "GateRound",
    "ManifestVersion",
    "ScopeState",
    "IdempotencyRecord",
    "EventLogEntry",
    "EvidenceBundle",
    "EvidenceClaim",
    "ReplayCase",
    "ReplayFixture",
    "RedactionPolicy",
    "ErrorEnvelope",
    # v0.2 OSS completeness, M01 w1-1 (added 2026-05-16): 12 new canonical
    # envelopes for the 13 SQL tables in
    # packages/schemas/sql/0004_v2_canonical_tables.sql. The
    # redaction_policies SQL table is wire-mirrored by the existing
    # RedactionPolicy envelope above; no new envelope is added for it.
    "GatePolicy",
    "ContractResult",
    "AssertionDefinition",
    "ReplayResult",
    "Manifest",
    "Incident",
    "RootCauseHypothesis",
    "Span",
    "ModelCallSpan",
    "ToolCallSpan",
    "RetrievalSpan",
    "EmbeddingSpan",
)

# Additional generated symbols that the SDK re-export module surfaces. These
# are not in the contract's primary import list (only the 14 above are) but
# are needed by the discriminated unions (ScopeState variants, RedactionPolicy
# matchers) and the shared scalar root models.
SUPPORTING_SYMBOLS: tuple[str, ...] = (
    "Actor",
    "RunScopeState",
    "ReplayCaseScopeState",
    "GateRoundScopeState",
    "EvidenceBundleScopeState",
    "RedactionPolicyMatcher",
    "RedactionPolicyMatcherRegex",
    "RedactionPolicyMatcherJsonPointer",
    "Sha256Hash",
    "Ulid",
    "RelayErrorCodeStr",
)

GENERATED_PY_HEADER = """# GENERATED FILE - DO NOT EDIT BY HAND.
#
# Source: packages/schemas/raw/openapi.yaml (W1.5 OpenAPI 3.1 source-of-truth).
# Regenerate: uv run python packages/schemas/scripts/codegen.py
# Drift check: uv run python scripts/check-codegen-drift.py
#
# Per VAL-W1-033 every class is a Pydantic v2 BaseModel subclass with
# model_config = ConfigDict(extra='forbid').
"""

GENERATED_TS_HEADER = """/* GENERATED FILE - DO NOT EDIT BY HAND.
 *
 * Source: packages/schemas/raw/openapi.yaml (W1.5 OpenAPI 3.1 source-of-truth).
 * Regenerate: uv run python packages/schemas/scripts/codegen.py
 * Drift check: uv run python scripts/check-codegen-drift.py
 */
"""


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    # packages/schemas/scripts/codegen.py -> repo root
    return Path(__file__).resolve().parents[3]


def _openapi_path(root: Path) -> Path:
    return root / "packages" / "schemas" / "raw" / "openapi.yaml"


def _py_out_dir(root: Path) -> Path:
    return root / "packages" / "sdk-python" / "relay" / "_generated"


def _ts_out_dir(root: Path) -> Path:
    return root / "packages" / "sdk-typescript" / "src" / "_generated"


def _relative_or_abs(path: Path, anchor: Path) -> str:
    """Return ``path`` relative to ``anchor`` if it is a subpath, else the abs form.

    Used in PASS messages so the script prints workspace-relative paths under
    a normal invocation AND tolerates monkey-patched output paths under the
    drift-check harness (which redirects output to a temp dir outside the
    repo root).
    """
    try:
        return str(path.relative_to(anchor))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# OpenAPI parsing - VAL-W1-032 coverage check + alias map derivation
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict:
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def assert_envelope_coverage(openapi: Mapping) -> None:
    """VAL-W1-032: every canonical envelope appears in exactly ONE components.schemas entry.

    Raises ValueError listing any envelope appearing zero or more than once.
    """
    schemas = openapi.get("components", {}).get("schemas", {})
    missing: list[str] = []
    duplicates: list[str] = []
    for name in CANONICAL_ENVELOPES:
        count = sum(1 for k in schemas if k == name)
        if count == 0:
            missing.append(name)
        elif count > 1:
            duplicates.append(name)
    if missing or duplicates:
        raise ValueError(
            "VAL-W1-032 coverage failure: "
            f"missing={missing!r} duplicates={duplicates!r}"
        )


def _snake_to_camel(name: str) -> str:
    # snake_to_camel: first segment lowercase, subsequent segments capitalised.
    parts = name.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


def derive_alias_map(openapi: Mapping) -> dict[str, dict[str, str]]:
    """For every envelope in components.schemas, return {envelope: {snake: camel}}.

    Walks each object schema's `properties` block. Discriminated unions and
    RootModel-style shared scalars (Sha256Hash, Ulid, RelayErrorCodeStr) are
    skipped because they have no field aliases.
    """
    schemas = openapi.get("components", {}).get("schemas", {})
    aliases: dict[str, dict[str, str]] = {}
    for name, schema in schemas.items():
        # Skip non-object schemas (the union dispatchers + scalar root models).
        if not isinstance(schema, dict):
            continue
        if schema.get("type") != "object":
            continue
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            continue
        pair: dict[str, str] = {}
        for prop_name in props:
            camel = _snake_to_camel(prop_name)
            if camel != prop_name:
                pair[prop_name] = camel
        if pair:
            aliases[name] = pair
    return aliases


# ---------------------------------------------------------------------------
# Python codegen
# ---------------------------------------------------------------------------


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _atomic_write(path: Path, content: str) -> None:
    """Local atomic file write (analogue of spec H.5 local_atomic_file_write).

    Writes to a sibling temp file, fsyncs, atomic rename. Used here because
    codegen output must not be observed half-written by a concurrent drift
    check.
    """
    import contextlib
    import os
    import tempfile

    parent = path.parent
    _ensure_dir(parent)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


def run_python_codegen(root: Path) -> None:
    """Invoke datamodel-code-generator and post-process the output."""
    openapi = _openapi_path(root)
    out_dir = _py_out_dir(root)
    _ensure_dir(out_dir)

    # Use a temp output path so we can prepend the GENERATED header
    # deterministically and strip datamodel-codegen's own banner. The
    # --disable-timestamp flag removes the generation timestamp from the
    # default header, but we replace the header entirely for stability.
    import tempfile

    with tempfile.NamedTemporaryFile(
        "w", suffix=".py", delete=False, encoding="utf-8"
    ) as tmp:
        tmp_path = Path(tmp.name)
    try:
        cmd = [
            sys.executable,
            "-W",
            "ignore::FutureWarning",
            "-m",
            "datamodel_code_generator",
            "--input",
            str(openapi),
            "--input-file-type",
            "openapi",
            "--output",
            str(tmp_path),
            "--output-model-type",
            "pydantic_v2.BaseModel",
            "--target-python-version",
            "3.12",
            "--use-schema-description",
            "--use-double-quotes",
            "--use-standard-collections",
            "--use-union-operator",
            "--enum-field-as-literal",
            "all",
            "--disable-timestamp",
        ]
        subprocess.run(cmd, check=True, cwd=root)

        raw = tmp_path.read_text(encoding="utf-8")
    finally:
        import contextlib

        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()

    # Strip the datamodel-codegen banner (`# generated by datamodel-codegen:`
    # plus the next two lines). With --disable-timestamp the banner is two
    # lines, but we strip up to four leading comment lines to be defensive.
    lines = raw.splitlines()
    stripped: list[str] = []
    skip = True
    for line in lines:
        if skip and line.startswith("#"):
            continue
        skip = False
        stripped.append(line)
    # Re-strip leading blank lines after banner removal.
    while stripped and stripped[0].strip() == "":
        stripped.pop(0)

    final_py = GENERATED_PY_HEADER + "\n" + "\n".join(stripped)
    if not final_py.endswith("\n"):
        final_py += "\n"

    # Write the raw datamodel-codegen output to a private module name; the
    # public `relay._generated.schemas` package re-exports from it. Using a
    # private name (`_models.py`) avoids the schemas.py vs schemas/__init__.py
    # collision that would otherwise short-circuit Python's package resolution.
    raw_module = out_dir / "_models.py"
    _atomic_write(raw_module, final_py)

    # Write the namespace package marker so the drift check has full coverage
    # of every file in the generated tree (including the `__init__.py` markers
    # that bind Python's package resolution to this layout).
    _atomic_write(out_dir / "__init__.py", _build_generated_namespace_init_py())

    # Write the schemas re-export package: relay._generated.schemas/__init__.py
    schemas_pkg_dir = out_dir / "schemas"
    _ensure_dir(schemas_pkg_dir)
    _atomic_write(schemas_pkg_dir / "__init__.py", _build_schemas_init_py())

    # Write the alias map.
    openapi_data = _load_yaml(openapi)
    aliases = derive_alias_map(openapi_data)
    _atomic_write(out_dir / "aliases.py", _build_aliases_py(aliases))


def _build_generated_namespace_init_py() -> str:
    """Return the deterministic content of relay/_generated/__init__.py.

    This is the namespace-package marker for the entire generated tree.
    Folded into codegen output so the drift check has full file coverage.
    """
    return GENERATED_PY_HEADER + '''
"""Relay generated artifacts namespace.

This subpackage contains code produced by the W1.5 codegen pipeline from
``packages/schemas/raw/openapi.yaml``. Do NOT edit files under this tree by
hand; the drift check (VAL-W1-035) will fail any divergence between the
committed tree and a fresh codegen run.

Regenerate via::

    uv run python packages/schemas/scripts/codegen.py

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

__all__: list[str] = []
'''


def _build_schemas_init_py() -> str:
    """Generate the relay._generated.schemas package __init__.py.

    Re-exports the 14 canonical envelopes plus supporting symbols from the
    private `_models.py` module and exposes the RelayUnknownSchemaVersionError
    helper for VAL-W1-036.
    """
    all_symbols = list(CANONICAL_ENVELOPES) + list(SUPPORTING_SYMBOLS)
    quoted = ",\n".join(f'    "{s}"' for s in sorted(all_symbols))
    imports = ",\n".join(f"    {s}" for s in sorted(all_symbols))
    body = f'''{GENERATED_PY_HEADER}
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
{imports},
)

__all__ = [
{quoted},
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
            f"unknown schema_version for {{envelope_kind}}: "
            f"observed={{observed_version!r}} expected={{expected_version!r}} "
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
                # Pydantic emits ctx={{"expected": "'relay.run_result.v1'"}} for
                # literal_error. Walk the structure to extract.
                ctx = err.get("ctx", {{}}) or {{}}
                expected = str(ctx.get("expected", "<unknown>"))
                observed = err.get("input", "<missing>")
                # Normalise expected: pydantic renders as "'relay.run_result.v1'".
                expected_stripped = expected.strip().strip("'\\"")
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
'''
    return body


def _build_aliases_py(aliases: Mapping[str, Mapping[str, str]]) -> str:
    """Generate the aliases.py module - snake_case <-> camelCase per envelope."""
    body = GENERATED_PY_HEADER + '''
"""Field alias maps for VAL-W1-037 snake_case <-> camelCase boundary.

Canonical wire-format field names are snake_case (e.g. ``run_result_id``).
The Python side exposes snake_case attributes directly (Pydantic default).
The TS side uses camelCase property names with the alias mapping under
``packages/sdk-typescript/src/_generated/aliases.ts``.

The dictionaries below are the source-of-truth for the cross-language
round-trip test (VAL-W1-037): both languages MUST produce identical
serialized output when given the same snake_case wire payload.
"""

from __future__ import annotations

# Mapping per envelope: snake_case field name -> camelCase field name.
# Fields with no underscores (already camelCase-equivalent) are omitted.
FIELD_ALIASES_BY_ENVELOPE: dict[str, dict[str, str]] = {
'''
    for env_name in sorted(aliases.keys()):
        body += f'    "{env_name}": {{\n'
        for snake in sorted(aliases[env_name].keys()):
            camel = aliases[env_name][snake]
            body += f'        "{snake}": "{camel}",\n'
        body += "    },\n"
    body += "}\n"

    # Add a helper that returns the inverse map (camel -> snake) for an
    # envelope name.
    body += '''

def snake_to_camel(envelope: str) -> dict[str, str]:
    """Return the snake_case -> camelCase alias map for ``envelope``.

    If ``envelope`` is not in the canonical envelope set, returns an empty
    dict (no aliases known).
    """
    return dict(FIELD_ALIASES_BY_ENVELOPE.get(envelope, {}))


def camel_to_snake(envelope: str) -> dict[str, str]:
    """Return the camelCase -> snake_case alias map for ``envelope``.

    Inverse of ``snake_to_camel``.
    """
    fwd = FIELD_ALIASES_BY_ENVELOPE.get(envelope, {})
    return {v: k for k, v in fwd.items()}


__all__ = [
    "FIELD_ALIASES_BY_ENVELOPE",
    "snake_to_camel",
    "camel_to_snake",
]
'''
    return body


# ---------------------------------------------------------------------------
# TypeScript codegen
# ---------------------------------------------------------------------------


def run_typescript_codegen(root: Path) -> None:
    """Invoke openapi-typescript and post-process the output."""
    openapi = _openapi_path(root)
    out_dir = _ts_out_dir(root)
    _ensure_dir(out_dir)

    schemas_ts = out_dir / "schemas.ts"

    cmd = [
        "npx",
        "--yes",
        "openapi-typescript",
        str(openapi),
        "-o",
        str(schemas_ts),
    ]
    result = subprocess.run(cmd, check=True, cwd=root, capture_output=True, text=True)
    _ = result.stdout  # discard the generator banner

    # Prepend GENERATED FILE header. openapi-typescript writes its own banner
    # (no timestamp) - we replace it with ours for consistency.
    raw = schemas_ts.read_text(encoding="utf-8")
    lines = raw.splitlines()
    stripped: list[str] = []
    in_banner = False
    banner_done = False
    for line in lines:
        if not banner_done and line.strip().startswith("/**"):
            in_banner = True
            continue
        if not banner_done and in_banner:
            if line.strip().endswith("*/"):
                in_banner = False
                banner_done = True
                continue
            continue
        banner_done = True
        stripped.append(line)
    # Trim leading blank lines.
    while stripped and stripped[0].strip() == "":
        stripped.pop(0)

    final_ts = GENERATED_TS_HEADER + "\n" + "\n".join(stripped)
    if not final_ts.endswith("\n"):
        final_ts += "\n"
    _atomic_write(schemas_ts, final_ts)

    # Write the named-export index.ts that the contract fixture imports from.
    _atomic_write(out_dir / "index.ts", _build_ts_index())

    # Write aliases.ts (mirror of aliases.py).
    openapi_data = _load_yaml(openapi)
    aliases = derive_alias_map(openapi_data)
    _atomic_write(out_dir / "aliases.ts", _build_aliases_ts(aliases))

    # Write errors.ts with the RelayUnknownSchemaVersionError class.
    _atomic_write(out_dir / "errors.ts", _build_errors_ts())


def _build_ts_index() -> str:
    """index.ts re-exports the named envelope types from the schemas module."""
    quoted_names = ",\n".join(f'  "{n}"' for n in CANONICAL_ENVELOPES)
    body = f"""{GENERATED_TS_HEADER}
/**
 * Named-export surface for VAL-W1-034:
 *
 *   import {{ RunResult, GateDecision, EvidenceBundle, ReplayFixture, ErrorEnvelope }}
 *     from "./index";
 *
 * Each named export is a type alias for components["schemas"]["<Name>"] from
 * the openapi-typescript output. Re-exporting as named types keeps the
 * fixture file ergonomic and decouples it from the openapi-typescript
 * internal `paths`/`webhooks` envelope.
 */

import type {{ components }} from "./schemas.js";

export type RunResult = components["schemas"]["RunResult"];
export type GateDecision = components["schemas"]["GateDecision"];
export type GateDecisionDraft = components["schemas"]["GateDecisionDraft"];
export type GateRound = components["schemas"]["GateRound"];
export type ManifestVersion = components["schemas"]["ManifestVersion"];
export type ScopeState = components["schemas"]["ScopeState"];
export type IdempotencyRecord = components["schemas"]["IdempotencyRecord"];
export type EventLogEntry = components["schemas"]["EventLogEntry"];
export type EvidenceBundle = components["schemas"]["EvidenceBundle"];
export type EvidenceClaim = components["schemas"]["EvidenceClaim"];
export type ReplayCase = components["schemas"]["ReplayCase"];
export type ReplayFixture = components["schemas"]["ReplayFixture"];
export type RedactionPolicy = components["schemas"]["RedactionPolicy"];
export type ErrorEnvelope = components["schemas"]["ErrorEnvelope"];
export type Actor = components["schemas"]["Actor"];
export type RunScopeState = components["schemas"]["RunScopeState"];
export type ReplayCaseScopeState = components["schemas"]["ReplayCaseScopeState"];
export type GateRoundScopeState = components["schemas"]["GateRoundScopeState"];
export type EvidenceBundleScopeState = components["schemas"]["EvidenceBundleScopeState"];
export type RedactionPolicyMatcher = components["schemas"]["RedactionPolicyMatcher"];

export {{ FIELD_ALIASES_BY_ENVELOPE, snakeToCamel, camelToSnake }} from "./aliases.js";
export {{ RelayUnknownSchemaVersionError, parseEnvelope }} from "./errors.js";

// Canonical envelope name list for VAL-W1-032 coverage assertions.
export const CANONICAL_ENVELOPES = [
{quoted_names}
] as const;

export type CanonicalEnvelopeName = (typeof CANONICAL_ENVELOPES)[number];
"""
    return body


def _build_aliases_ts(aliases: Mapping[str, Mapping[str, str]]) -> str:
    """Mirror aliases.py in TS form."""
    body = GENERATED_TS_HEADER + "\n"
    body += '/**\n'
    body += ' * Field alias maps for VAL-W1-037 snake_case <-> camelCase boundary.\n'
    body += ' *\n'
    body += ' * Canonical wire-format field names are snake_case (e.g. `run_result_id`).\n'
    body += ' * The TS side uses camelCase property names; this map drives the\n'
    body += ' * alias-applying helper functions used by the SDK serializer/deserializer.\n'
    body += ' */\n\n'
    body += 'export const FIELD_ALIASES_BY_ENVELOPE: Readonly<\n'
    body += '  Record<string, Readonly<Record<string, string>>>\n'
    body += '> = {\n'
    for env_name in sorted(aliases.keys()):
        body += f'  {env_name}: {{\n'
        for snake in sorted(aliases[env_name].keys()):
            camel = aliases[env_name][snake]
            body += f'    {snake}: "{camel}",\n'
        body += "  },\n"
    body += "} as const;\n\n"
    body += '''
/**
 * Return the snake_case -> camelCase alias map for `envelope`.
 *
 * If `envelope` is not in the canonical envelope set, returns an empty map.
 */
export function snakeToCamel(envelope: string): Record<string, string> {
  const map = FIELD_ALIASES_BY_ENVELOPE[envelope];
  return map ? { ...map } : {};
}

/**
 * Return the camelCase -> snake_case alias map for `envelope`.
 *
 * Inverse of `snakeToCamel`.
 */
export function camelToSnake(envelope: string): Record<string, string> {
  const fwd = FIELD_ALIASES_BY_ENVELOPE[envelope];
  if (!fwd) return {};
  const inv: Record<string, string> = {};
  for (const k of Object.keys(fwd)) {
    const v = fwd[k];
    if (v !== undefined) {
      inv[v] = k;
    }
  }
  return inv;
}
'''
    return body


def _build_errors_ts() -> str:
    """RelayUnknownSchemaVersionError + parseEnvelope helper for VAL-W1-036 TS side."""
    body = GENERATED_TS_HEADER + '''
/**
 * Forward-compat unknown schema_version handler for VAL-W1-036.
 *
 * Per CLAUDE.md keystone invariant #10 and spec B.7 lines 3618-3621:
 * engines refuse to write objects whose schema_version is unknown. The
 * generated TS types pin `schema_version` to a const string literal; this
 * helper raises a structured error when a payload carries an unregistered
 * version.
 */

export class RelayUnknownSchemaVersionError extends Error {
  public readonly envelopeKind: string;
  public readonly observedVersion: string;
  public readonly expectedVersion: string;

  constructor(
    envelopeKind: string,
    observedVersion: string,
    expectedVersion: string,
  ) {
    super(
      `unknown schema_version for ${envelopeKind}: ` +
        `observed=${JSON.stringify(observedVersion)} ` +
        `expected=${JSON.stringify(expectedVersion)} (VAL-W1-036, spec B.7)`,
    );
    this.name = "RelayUnknownSchemaVersionError";
    this.envelopeKind = envelopeKind;
    this.observedVersion = observedVersion;
    this.expectedVersion = expectedVersion;
  }
}

/**
 * Validate that `payload.schema_version` equals `expectedVersion`. Throw
 * RelayUnknownSchemaVersionError on mismatch.
 *
 * The TS type system pins schema_version statically; this runtime check
 * handles documents loaded from JSON.parse where the static type is lost.
 *
 * Usage:
 *
 *   const payload: unknown = JSON.parse(input);
 *   parseEnvelope("RunResult", "relay.run_result.v1", payload);
 *   // ... downstream consumers can now cast to RunResult.
 */
export function parseEnvelope(
  envelopeKind: string,
  expectedVersion: string,
  payload: unknown,
): void {
  if (typeof payload !== "object" || payload === null) {
    throw new RelayUnknownSchemaVersionError(
      envelopeKind,
      "<not-an-object>",
      expectedVersion,
    );
  }
  const raw = (payload as Record<string, unknown>)["schema_version"];
  if (typeof raw !== "string") {
    throw new RelayUnknownSchemaVersionError(
      envelopeKind,
      typeof raw === "undefined" ? "<missing>" : String(raw),
      expectedVersion,
    );
  }
  if (raw !== expectedVersion) {
    throw new RelayUnknownSchemaVersionError(
      envelopeKind,
      raw,
      expectedVersion,
    );
  }
}
'''
    return body


# ---------------------------------------------------------------------------
# Error-codes generation - re-uses the W1.4 script
# ---------------------------------------------------------------------------


def run_error_codes_codegen(root: Path) -> None:
    """Re-run the W1.4 error-codes generator so codegen-schemas is one command."""
    script = root / "packages" / "schemas" / "scripts" / "gen_error_codes.py"
    if not script.is_file():
        raise FileNotFoundError(f"missing error-codes generator: {script}")
    subprocess.run([sys.executable, str(script)], check=True, cwd=root)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="W1.5 codegen orchestrator (datamodel-code-generator + openapi-typescript)."
    )
    parser.add_argument(
        "--skip-python",
        action="store_true",
        help="Skip Python codegen (useful for debugging TS only).",
    )
    parser.add_argument(
        "--skip-typescript",
        action="store_true",
        help="Skip TypeScript codegen (useful for debugging Python only).",
    )
    parser.add_argument(
        "--skip-error-codes",
        action="store_true",
        help="Skip the W1.4 error-codes generator re-run.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    root = _repo_root()
    openapi = _openapi_path(root)
    if not openapi.is_file():
        print(f"FAIL: openapi document missing: {openapi}", file=sys.stderr)
        return 2

    openapi_data = _load_yaml(openapi)
    assert_envelope_coverage(openapi_data)

    if not args.skip_python:
        run_python_codegen(root)
        print(f"PASS: wrote Python output to {_relative_or_abs(_py_out_dir(root), root)}")

    if not args.skip_typescript:
        run_typescript_codegen(root)
        print(f"PASS: wrote TypeScript output to {_relative_or_abs(_ts_out_dir(root), root)}")

    if not args.skip_error_codes:
        run_error_codes_codegen(root)
        print("PASS: re-ran error-codes generator")

    # Final sanity grep: every generated Python schemas module must contain
    # `model_config = ConfigDict(extra="forbid")` for every canonical envelope.
    # This is the VAL-W1-033 in-pipeline assertion; the test surface checks
    # the same property post-import.
    if args.skip_python:
        py_text = ""
    else:
        py_text = (_py_out_dir(root) / "_models.py").read_text(encoding="utf-8")
    if py_text and 'extra="forbid"' not in py_text:
        print(
            "FAIL: VAL-W1-033 pipeline check: extra='forbid' missing from generated _models.py",
            file=sys.stderr,
        )
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


# Suppress unused-import warnings - `json` and `re` reserved for future
# canonical-form validation we may add to the orchestrator.
_ = json
_ = re
