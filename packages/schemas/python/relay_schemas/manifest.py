"""Canonical manifest.v1 validator + command_hash helpers.

Spec F lines 4007-4103: the manifest is the source of truth for what a
worker is allowed to run. Workers REFUSE to execute commands not declared
in the active manifest. Every event-log entry written by a worker carries
the ``manifest_commit_hash`` of the manifest under which it ran.

This module exposes:

* :data:`MANIFEST_SCHEMA_PATH` -- on-disk path to the canonical
  ``manifest.v1.schema.json`` file.
* :data:`MANIFEST_SCHEMA` -- the loaded canonical schema dict.
* :func:`load_manifest_schema` -- explicit loader (for callers who prefer
  to refresh the cached schema on disk).
* :func:`validate` -- structured validator returning :class:`ValidationResult`
  rather than raising; used by sidecar ingest paths that need a structured
  ``RELAY-GATE-021`` error envelope.
* :func:`compute_command_hash` -- canonical
  ``sha256_canonical(argv ++ cwd ++ env ++ container_image)`` per
  spec F line 4100. Deterministic + cross-language portable (the
  TypeScript SDK's ``computeCommandHash`` is byte-for-byte compatible).
* :func:`effective_grace_window_seconds` -- treat absent ``grace_window``
  as the spec-default 1800 seconds (spec F line 4095, VAL-V2M03-008).

CLAUDE.md keystone invariant 3 + CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

# ----------------------------------------------------------------------------
# YAML hardening (VAL-V3M5-011, VAL-V3M5-012).
# ----------------------------------------------------------------------------
#
# Spec section AI.1 line 5659 sets the structural defense against
# anchor-bomb / billion-laughs YAML payloads: ingest rejects spans whose
# canonical JSON exceeds 256 KiB OR whose nesting depth exceeds 16. This
# loader enforces the depth half of that contract for every manifest YAML
# read on the Python side.
#
# The loader walks PyYAML's event stream rather than constructing the full
# Python object first because (a) the event stream surfaces nesting
# entirely before any alias expansion executes, and (b) it lets us refuse
# pathological documents before pyyaml materialises them. Aliases are
# permitted (yaml.SafeLoader resolves them); the loader charges each alias
# the full expanded node-cost of the anchor it references and rejects any
# document whose total expansion exceeds the node budget, so a billion-laughs
# bomb is caught before materialisation. Legitimate bounded anchor reuse
# (including merge keys and nested anchor references) expands to a small
# node count and is accepted.

MAX_YAML_DEPTH: int = 16
"""Maximum YAML nesting depth permitted for manifest + DSL loaders.

Per spec AI.1 line 5659. Sequences and mappings each contribute one level
to the count; scalars are leaves. A flat scalar (e.g., ``"x"``) has depth 1.
A document like ``{a: 1}`` has depth 2 (mapping + scalar leaf). A document
like ``{a: [1, 2]}`` has depth 3.
"""

MAX_YAML_CANONICAL_BYTES: int = 256 * 1024
"""Maximum canonical-JSON size of a YAML document (spec AI.1 line 5659).

The 256 KiB half of the AI.1 structural constraint, enforced on the
*materialized* (post alias expansion) object so an alias bomb that expands
to a large canonical form is rejected even if its authored bytes are small.
"""

MAX_YAML_EXPANDED_NODES: int = 100_000
"""Maximum post-expansion node count (anchor/alias bomb resource cap).

An alias bomb (billion-laughs) authors few bytes but expands to an
exponential number of nodes. We compute the post-expansion node count from
the event stream (charging each ``AliasEvent`` the full node-cost of the
anchor it references) and reject documents whose expansion exceeds this
budget before materialising them. Generously above legitimate manifest
usage (the canonical manifest expands to <2000 nodes).
"""


class YamlDepthExceededError(ValueError):
    """Raised when a YAML document exceeds :data:`MAX_YAML_DEPTH`.

    Attributes:
        depth: Observed depth at the point of rejection (== limit + 1).
        limit: The configured cap, mirrored from :data:`MAX_YAML_DEPTH`.
    """

    def __init__(self, depth: int, limit: int = MAX_YAML_DEPTH) -> None:
        super().__init__(
            f"YAML nesting depth {depth} exceeds limit {limit} "
            f"(spec AI.1 line 5659)"
        )
        self.depth = depth
        self.limit = limit


class YamlAliasBombError(ValueError):
    """Raised when a YAML document is an anchor/alias (billion-laughs) bomb.

    The defense is a resource budget, not a structural heuristic: the loader
    computes the fully-expanded node count from the parse event stream
    (charging each ``AliasEvent`` the full node-cost of the anchor it
    references) and rejects any document whose expansion exceeds
    :data:`MAX_YAML_EXPANDED_NODES` -- before the object is materialised. A
    genuine billion-laughs amplifies exponentially (fanout^levels) and
    crosses the budget; legitimate bounded composition (anchor reuse, merge
    keys) expands to a small node count and is accepted, even when an
    anchored container's own subtree references another anchor.

    Attributes:
        reason: Machine-readable cause. Currently always ``"expanded_nodes"``.
        observed: The observed (real) expanded node count at the point of
            rejection. Always the actual accumulated count, never a constant.
    """

    def __init__(self, reason: str, observed: int) -> None:
        super().__init__(
            f"YAML anchor/alias bomb rejected ({reason}={observed}); "
            f"billion-laughs structural defense (spec AI.1 line 5659)"
        )
        self.reason = reason
        self.observed = observed


class YamlSizeExceededError(ValueError):
    """Raised when a YAML document's canonical JSON exceeds the byte budget.

    Attributes:
        size: Observed canonical-JSON byte length.
        limit: The configured cap, mirrored from
            :data:`MAX_YAML_CANONICAL_BYTES`.
    """

    def __init__(self, size: int, limit: int = MAX_YAML_CANONICAL_BYTES) -> None:
        super().__init__(
            f"YAML canonical-JSON size {size} bytes exceeds limit {limit} "
            f"(spec AI.1 line 5659)"
        )
        self.size = size
        self.limit = limit


def _scan_yaml_event_stream(
    stream: str | bytes, *, max_depth: int
) -> None:
    """Walk the parse event stream and enforce structural budgets.

    Enforces, before any alias expansion materialises the object:

    * Nesting depth <= ``max_depth`` (raises :class:`YamlDepthExceededError`).
    * A bounded post-expansion node count (raises :class:`YamlAliasBombError`
      with ``reason="expanded_nodes"`` and the REAL observed count).

    The walk is single-pass. For each container we track (a) its running
    nesting depth for the depth cap and (b) its fully-expanded node cost --
    charging each ``AliasEvent`` the full node-cost of the anchor it
    references -- for the node-budget cap. The node-budget cap is the
    principled defense against alias amplification: a billion-laughs bomb
    multiplies nodes exponentially (fanout^levels) and crosses
    :data:`MAX_YAML_EXPANDED_NODES` here, before the object is materialised,
    while legitimate bounded composition (anchor reuse, merge keys, nested
    anchor references) expands to a small node count and is accepted.

    Note: the mere presence of a nested anchor reference inside an anchored
    container is NOT amplification and is not rejected on its own -- only the
    accumulated expanded-node count gates acceptance.
    """
    container_depth = 0
    max_observed = 0
    saw_scalar = False
    # anchor name -> fully-expanded node cost of the anchored subtree.
    anchor_cost: dict[str, int] = {}
    # Stack of frames for open containers: [expanded_cost, anchor_name].
    frames: list[list[Any]] = [[0, None]]
    for event in yaml.parse(stream, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.MappingStartEvent | yaml.SequenceStartEvent):
            container_depth += 1
            if container_depth + 1 > max_observed:
                max_observed = container_depth + 1
            if max_observed > max_depth:
                raise YamlDepthExceededError(max_observed, limit=max_depth)
            frames.append([1, getattr(event, "anchor", None)])
        elif isinstance(event, yaml.MappingEndEvent | yaml.SequenceEndEvent):
            container_depth -= 1
            cost, anchor = frames.pop()
            if anchor is not None:
                anchor_cost[anchor] = cost
            parent = frames[-1]
            parent[0] += cost
            if parent[0] > MAX_YAML_EXPANDED_NODES:
                raise YamlAliasBombError("expanded_nodes", observed=parent[0])
        elif isinstance(event, yaml.ScalarEvent):
            saw_scalar = True
            level = container_depth + 1
            if level > max_observed:
                max_observed = level
            if max_observed > max_depth:
                raise YamlDepthExceededError(max_observed, limit=max_depth)
            anchor = getattr(event, "anchor", None)
            if anchor is not None:
                anchor_cost[anchor] = 1
            frames[-1][0] += 1
        elif isinstance(event, yaml.AliasEvent):
            frames[-1][0] += anchor_cost.get(event.anchor, 1)
            if frames[-1][0] > MAX_YAML_EXPANDED_NODES:
                raise YamlAliasBombError("expanded_nodes", observed=frames[-1][0])
    if not saw_scalar and max_observed == 0 and frames[0][0] == 0:
        return
    if frames[0][0] > MAX_YAML_EXPANDED_NODES:
        raise YamlAliasBombError("expanded_nodes", observed=frames[0][0])


def safe_load_yaml(stream: str | bytes, *, max_depth: int = MAX_YAML_DEPTH) -> Any:
    """Depth-, alias-, and size-bounded ``yaml.safe_load`` for manifests.

    Uses ``yaml.SafeLoader`` exclusively (never ``yaml.Loader``) so arbitrary
    Python object construction is impossible. Before materialising the
    object, walks the parse event stream to enforce the spec AI.1 structural
    budgets:

    * nesting depth <= ``max_depth`` (:class:`YamlDepthExceededError`);
    * no anchor/alias (billion-laughs) bomb -- a fully-expanded node count
      above :data:`MAX_YAML_EXPANDED_NODES` (:class:`YamlAliasBombError`).

    The event-stream alias accounting is required because aliases are
    represented as ``AliasEvent`` nodes that are NOT expanded in the parse
    stream: a depth-only walk over the unexpanded events is blind to a
    billion-laughs payload whose authored depth is shallow but whose
    expansion is exponential (VAL-ISO-016).

    After the structural checks pass the bytes are re-parsed via
    ``yaml.safe_load`` and the materialised object's canonical-JSON size is
    enforced against :data:`MAX_YAML_CANONICAL_BYTES`
    (:class:`YamlSizeExceededError`), the 256 KiB half of the AI.1 cap.

    Args:
        stream: YAML document body (str or bytes).
        max_depth: Per-call override for testing; production callers use
            the spec-default :data:`MAX_YAML_DEPTH`.

    Returns:
        Plain Python object (dict / list / scalar / None) per yaml.SafeLoader.

    Raises:
        YamlDepthExceededError: depth budget exceeded.
        YamlAliasBombError: anchor/alias bomb detected.
        YamlSizeExceededError: materialised canonical JSON exceeds the byte
            budget.
        yaml.YAMLError: any parse error (propagated verbatim from PyYAML).
    """
    _scan_yaml_event_stream(stream, max_depth=max_depth)
    result = yaml.safe_load(stream)
    if result is not None:
        # The cap is defined on CANONICAL (compact, key-sorted) JSON per spec
        # AI.1 / :data:`MAX_YAML_CANONICAL_BYTES`. Measure the canonical form:
        # default ``json.dumps`` separators are ``(', ', ': ')`` (with
        # whitespace), which OVER-COUNTS every key/element boundary and would
        # wrongly reject a payload whose canonical form is under the cap (e.g.
        # a flat list whose spaced dump straddles the limit). Compact
        # separators ``(',', ':')`` match the JCS canonical bytes the rest of
        # the package emits (relay_schemas.envelopes.canonical_bytes); key
        # sorting does not change the byte count but pins the canonical form.
        # ``allow_nan`` is left at its permissive default so a YAML doc with
        # ``.inf`` / ``.nan`` is size-measured rather than newly rejected here.
        size = len(
            json.dumps(
                result,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        )
        if size > MAX_YAML_CANONICAL_BYTES:
            raise YamlSizeExceededError(size)
    return result

# ----------------------------------------------------------------------------
# Canonical schema discovery.
# ----------------------------------------------------------------------------
#
# This module file lives at
# packages/schemas/python/relay_schemas/manifest.py; parents[3] resolves to
# the repo root, then catalogs/manifest.v1.schema.json is the canonical
# location alongside the other v1 catalog schemas (see prior w1-3 handoff
# placing relay.gate_metric_catalog.v1.schema.json under catalogs/).
#
# The CATALOG vs CATALOG_SCHEMA distinction does not apply here: the
# manifest schema has no separate "data file" -- the schema *is* the
# canonical document. Callers reference MANIFEST_SCHEMA_PATH so the
# on-disk location is opaque.

_THIS = Path(__file__).resolve()
# manifest.py lives at packages/schemas/python/relay_schemas/manifest.py;
# parents[0]=relay_schemas, [1]=python, [2]=schemas, [3]=packages, [4]=relay.
_REPO_ROOT = _THIS.parents[4]
MANIFEST_SCHEMA_PATH: Path = (
    _REPO_ROOT / "packages" / "schemas" / "catalogs" / "manifest.v1.schema.json"
)

# Top-level fields the body validator treats as required. Spec F line 4015
# names {schema_version, manifest_id, services, commands, validation_surfaces}
# as the JSON Schema-level required set. The body validator (VAL-V2M03-009)
# additionally treats network_policy.egress_allowlist, side_effect_tools,
# mutation_boundaries, grace_window, and artifacts as required at the
# manifest body level -- these are mandated by the M03 plan + keystone
# invariants 5 (default-deny everywhere) and 6 (side-effect classification).
_REQUIRED_BODY_FIELDS: tuple[str, ...] = (
    "schema_version",
    "manifest_id",
    "services",
    "commands",
    "validation_surfaces",
    "network_policy",
    "artifacts",
    "side_effect_tools",
    "mutation_boundaries",
    "grace_window",
)

# Per spec F line 4095: grace_window.seconds default = 1800. The JSON Schema
# carries `default: 1800` for documentation, but jsonschema-py does NOT
# inject defaults; callers must use this constant or
# effective_grace_window_seconds() to honor the spec default.
DEFAULT_GRACE_WINDOW_SECONDS: int = 1800


def load_manifest_schema() -> dict[str, Any]:
    """Load the canonical manifest schema fresh from disk."""
    return json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))


# Lazy module-level cache to avoid repeated disk reads from hot paths
# (sidecar ingest endpoints validate per-request).
_SCHEMA_CACHE: dict[str, Any] | None = None


def _schema() -> dict[str, Any]:
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        _SCHEMA_CACHE = load_manifest_schema()
    return _SCHEMA_CACHE


MANIFEST_SCHEMA: dict[str, Any] = _schema()


# ----------------------------------------------------------------------------
# Body validator.
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a manifest body validation.

    Attributes:
        ok: True only when all required fields are present AND the body
            validates cleanly against the canonical JSON Schema.
        missing_field: JSON pointer-style path to the first missing field
            ("services", "artifacts", "commands/0/argv", etc.) when
            ``ok=False``; empty string on success.
        schema_errors: Tuple of human-readable schema error messages from
            the canonical Draft 2020-12 validator. Empty on success.
    """

    ok: bool
    missing_field: str = ""
    schema_errors: tuple[str, ...] = ()


def validate(body: Mapping[str, Any]) -> ValidationResult:
    """Validate a manifest body. Returns structured result; never raises.

    Order of checks:

      1. Top-level required fields per :data:`_REQUIRED_BODY_FIELDS`. The
         FIRST missing field short-circuits with
         ``ValidationResult(ok=False, missing_field=<name>)``.
      2. JSON Schema validation via Draft 2020-12. Any error returns
         ``ValidationResult(ok=False, missing_field=<path>, schema_errors=...)``.

    Callers (sidecar ingest, contract publish) use ``missing_field`` to
    populate the ``RELAY-GATE-021`` envelope's ``invalid_anchor`` field
    (spec line 4686).
    """
    for field in _REQUIRED_BODY_FIELDS:
        if field not in body:
            return ValidationResult(ok=False, missing_field=field)

    validator = Draft202012Validator(_schema())
    errors = list(validator.iter_errors(dict(body)))
    if errors:
        # Surface the first error's path so the caller has a stable handle.
        first = errors[0]
        path = "/".join(str(p) for p in first.absolute_path)
        return ValidationResult(
            ok=False,
            missing_field=path,
            schema_errors=tuple(e.message for e in errors),
        )
    return ValidationResult(ok=True)


def effective_grace_window_seconds(body: Mapping[str, Any]) -> int:
    """Return the effective ``grace_window.seconds`` for a manifest body.

    Per spec F line 4095, absent ``grace_window`` defaults to 1800. An
    explicit ``grace_window.seconds=0`` is honored verbatim (zero-grace
    is a valid rotation discipline; the schema's ``minimum: 0`` permits it).
    """
    gw = body.get("grace_window")
    if not isinstance(gw, Mapping):
        return DEFAULT_GRACE_WINDOW_SECONDS
    seconds = gw.get("seconds")
    if seconds is None:
        return DEFAULT_GRACE_WINDOW_SECONDS
    if not isinstance(seconds, int) or isinstance(seconds, bool):
        # Defensive: schema validation should catch this, but if a caller
        # bypasses validate() and asks effective grace, fall back to the
        # spec default rather than propagating a bad type.
        return DEFAULT_GRACE_WINDOW_SECONDS
    if seconds < 0:
        return DEFAULT_GRACE_WINDOW_SECONDS
    return seconds


# ----------------------------------------------------------------------------
# command_hash.
# ----------------------------------------------------------------------------
#
# Spec F line 4100:
#   command_hash = sha256_canonical(argv ++ cwd ++ env ++ container_image)
#
# Canonical encoding rules (cross-language portable):
#
#   * argv             -> JSON array, UTF-8, no whitespace separators
#                         (json.dumps separators=(",", ":")).
#   * cwd              -> JSON string (json.dumps over the str), preserves
#                         leading/trailing whitespace + escapes.
#   * env              -> JSON object with sorted keys (sort_keys=True),
#                         no whitespace separators. Keys are strings; values
#                         are strings. None -> {}.
#   * container_image  -> JSON string. None -> JSON null (the literal
#                         "null", per json.dumps(None)). This distinguishes
#                         "explicitly absent" from "empty string".
#
# Concatenation: each encoded field is joined by a fixed ASCII NUL byte
# (b"\x00") separator. The result is a bytes payload; sha256 over the
# payload produces the hex digest; the wire form is "sha256-<hex>"
# (lowercase, matching the spec line 4083 pattern).
#
# This scheme is intentionally simpler than RFC 8785 JCS because the input
# space is fixed and small (argv, cwd, env, image). The TypeScript SDK
# implements the identical sequence so byte-equality is provable via the
# golden vector at packages/schemas/catalogs/command_hash.golden.json.
#
# Determinism guarantees:
#   * env-key insertion order does NOT affect output (sort_keys=True).
#   * argv reordering DOES affect output (positional list, not sorted).
#   * cwd whitespace DOES affect output (a single trailing space changes
#     the JSON string encoding).

_NUL: bytes = b"\x00"


def _encode_argv(argv: Sequence[str]) -> bytes:
    if not isinstance(argv, list | tuple):
        raise TypeError(f"argv must be a list/tuple of strings; got {type(argv).__name__}")
    for i, item in enumerate(argv):
        if not isinstance(item, str):
            raise TypeError(
                f"argv[{i}] must be str; got {type(item).__name__}"
            )
    return json.dumps(
        list(argv),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,
    ).encode("utf-8")


def _encode_cwd(cwd: str) -> bytes:
    if not isinstance(cwd, str):
        raise TypeError(f"cwd must be str; got {type(cwd).__name__}")
    return json.dumps(cwd, ensure_ascii=False).encode("utf-8")


def _encode_env(env: Mapping[str, str] | None) -> bytes:
    if env is None:
        env_dict: dict[str, str] = {}
    elif isinstance(env, Mapping):
        env_dict = {}
        for k, v in env.items():
            if not isinstance(k, str):
                raise TypeError(
                    f"env keys must be str; got key of type {type(k).__name__}"
                )
            if not isinstance(v, str):
                raise TypeError(
                    f"env values must be str; got value of type {type(v).__name__}"
                )
            env_dict[k] = v
    else:
        raise TypeError(f"env must be a Mapping or None; got {type(env).__name__}")
    return json.dumps(
        env_dict,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _encode_container_image(image: str | None) -> bytes:
    if image is None:
        return b"null"
    if not isinstance(image, str):
        raise TypeError(
            f"container_image must be str or None; got {type(image).__name__}"
        )
    return json.dumps(image, ensure_ascii=False).encode("utf-8")


def compute_command_hash(
    *,
    argv: Sequence[str],
    cwd: str,
    env: Mapping[str, str] | None,
    container_image: str | None,
) -> str:
    """Return ``sha256-<hex>`` for the canonical (argv, cwd, env, image) tuple.

    Args:
        argv: Argument vector. Non-empty list/tuple of strings.
        cwd: Working directory path string. Whitespace-sensitive.
        env: Environment mapping (str->str) or None (treated as empty {}).
            Keys are sorted in the canonical encoding so insertion order
            does not affect output (VAL-V2M03-011 case (a)).
        container_image: OCI image reference string or None.

    Returns:
        Wire-format hash matching pattern ``^sha256-[0-9a-f]{64}$``.

    Raises:
        TypeError: any input is of the wrong type.

    The output is byte-identical to the TypeScript SDK's
    ``computeCommandHash``; cross-language parity is exercised via the
    golden vector test (VAL-V2M03-011 evidence).
    """
    payload = _NUL.join(
        [
            _encode_argv(argv),
            _encode_cwd(cwd),
            _encode_env(env),
            _encode_container_image(container_image),
        ]
    )
    digest = hashlib.sha256(payload).hexdigest()
    return f"sha256-{digest}"


__all__ = [
    "DEFAULT_GRACE_WINDOW_SECONDS",
    "MANIFEST_SCHEMA",
    "MANIFEST_SCHEMA_PATH",
    "MAX_YAML_DEPTH",
    "ValidationResult",
    "YamlDepthExceededError",
    "compute_command_hash",
    "effective_grace_window_seconds",
    "load_manifest_schema",
    "safe_load_yaml",
    "validate",
]
