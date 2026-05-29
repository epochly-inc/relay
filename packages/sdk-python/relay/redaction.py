"""SDK-side redaction at the trace boundary (W3.3).

Per CLAUDE.md keystone invariant #7 (default-deny raw capture) and
spec G, the SDK redacts every trace-bound payload BEFORE the HTTP body
crosses localhost. Plaintext never leaves the calling process on the
default policy. Hosted Relay's ingest workers re-validate as defense in
depth, but the SDK is the first line of defense; a forged or
SDK-internal bug that emits raw bytes is treated as a P0 product
failure regardless of which side catches it.

Module surface:

  - :class:`RedactionPolicy` parses and validates a v1 redaction policy
    dict (spec G.2). Invalid policies raise
    :class:`relay.errors.RelayPolicyError` at load time. ``raw_capture:
    true`` policies without both ``dpa_ref`` and ``approver_user_id``
    are rejected (CLAUDE.md banned pattern #11, spec G.1).

  - :class:`RedactionEngine` walks a payload, applies matchers to every
    string in the configured ``applies_to_fields`` (and to every nested
    string in those subtrees), and emits a redacted copy. Strings are
    NFKC-normalised plus passed through a small confusables map for
    Cyrillic-and-friend homoglyph variants of ASCII letters. Bytes
    values are decoded with ``errors='replace'`` so mixed-encoding OCR
    output cannot smuggle a secret past the matcher.

  - :func:`redact_capture_payload` is the canonical SDK entry point:
    it accepts a payload dict, runs it through the engine, and returns
    the JSON-serialised bytes the SDK transport will hand to the HTTP
    client. The function is the only place a string flows from a
    user-supplied trace value into wire bytes.

Determinism guarantees (spec G.3): two engines built from the same
policy version + salt provider produce byte-identical output for the
same input. Hash matchers use HMAC-SHA-256 keyed by the policy's
``salt_ref`` (resolved by the caller-supplied ``salt_provider``); plain
SHA-256 is never used (VAL-W3-028).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Final

from .errors import RelayPolicyError

# The schema_version literal the policy MUST carry (spec G.2 + W1.4
# envelopes RedactionPolicy.schema_version). Anything else is refused.
#
# NOTE: the W4.1 type alias :type:`RedactionPolicyShape` (TS side) uses
# ``relay.redaction_policy.v1`` (the codegen-friendly form). The canonical
# wire schema is ``relay.redaction.v1``. Both literals are accepted by
# both engines so the same policy body loads identically across SDKs;
# this prevents a parity defect where a policy authored under the alias
# loads on TS but is rejected on Python.
_POLICY_SCHEMA_VERSION_PRIMARY: Final[str] = "relay.redaction.v1"
_POLICY_SCHEMA_VERSION_ALIAS: Final[str] = "relay.redaction_policy.v1"
_POLICY_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset(
    {_POLICY_SCHEMA_VERSION_PRIMARY, _POLICY_SCHEMA_VERSION_ALIAS}
)
# Backwards-compatible name retained for any in-tree reference that
# expected the legacy single-literal constant.
_POLICY_SCHEMA_VERSION: Final[str] = _POLICY_SCHEMA_VERSION_PRIMARY

# The closed set of matcher kinds the SDK supports. Spec G.3 lists
# "regex", "json_pointer", and "json_path"; v0.1 SDK implements
# "regex" end-to-end, "json_pointer" (RFC 6901), and "json_path"
# (RFC 9535 subset: ``$``, ``$.key`` dotted child access, ``$.key[N]``
# integer array index). An unknown ``kind`` fails closed at load.
# VAL-V3M5-018.
_KNOWN_MATCHER_KINDS: Final[frozenset[str]] = frozenset(
    {"regex", "json_pointer", "json_path"}
)

# The closed set of matcher actions. ``redact`` replaces the matched
# span with the action_policy.redact.placeholder. ``hash`` replaces it
# with the HMAC-SHA-256 digest hex of the matched substring (NOT plain
# SHA-256; VAL-W3-028). ``drop`` removes the matched span entirely (or
# emits an explicit null placeholder when configured).
_KNOWN_ACTIONS: Final[frozenset[str]] = frozenset({"redact", "hash", "drop"})

# The closed list of trace-payload fields the matcher set is applied to
# by default (spec G.2 ``applies_to_fields``). The engine walks the
# payload looking for these top-level keys (and any nested object
# beneath them); every reachable string leaf is normalised + matched.
DEFAULT_APPLIES_TO_FIELDS: Final[tuple[str, ...]] = (
    "model_call.input",
    "model_call.output",
    "tool_call.args",
    "tool_call.result",
    "retrieval.documents",
)

# Python named-group / named-backreference syntax (``(?P<name>...)`` and
# ``(?P=name)``). Per VAL-REDACT-003 the supported cross-language regex
# dialect rejects these on BOTH SDKs: Python's ``re`` accepts them while
# JavaScript ``RegExp`` does not (JS uses ``(?<name>...)``), so a policy that
# used them would match on Python and throw on TS. We reject them on the
# Python side too so the same policy body loads (or is rejected) identically.
_PYTHON_NAMED_GROUP_RE: Final[re.Pattern[str]] = re.compile(r"\(\?P[<=]")


def _compile_regex_pattern(raw_pattern: str) -> re.Pattern[str]:
    """Compile a policy regex matcher under the pinned cross-language dialect.

    Mirrors the TypeScript ``compileRegexPattern`` bridge (VAL-REDACT-003):
    Python's ``re`` natively understands leading inline flags such as
    ``(?i)password`` (the default policy uses them), so we let ``re.compile``
    handle flag translation. We additionally reject Python named groups
    ``(?P<name>...)`` / ``(?P=name)`` so the supported dialect is identical
    on both runtimes -- TS cannot compile that syntax, and a matcher must not
    silently match on one SDK while throwing on the other.

    Raises :class:`re.error` for invalid syntax (the caller maps it to a
    ``bad_regex`` policy error). Named-group rejection raises
    :class:`re.error` with a stable message so the caller can surface a
    ``named_group_unsupported`` reason.
    """
    if _PYTHON_NAMED_GROUP_RE.search(raw_pattern):
        raise re.error(
            "Python named groups '(?P<name>...)' / '(?P=name)' are not part "
            "of the supported cross-language regex dialect"
        )
    return re.compile(raw_pattern)


# ---------------------------------------------------------------------------
# Unicode confusables: a small explicit table.
# ---------------------------------------------------------------------------
# Per eng plan CQ2, NFKC alone is insufficient because canonical
# Cyrillic glyphs (e.g. U+0410 CYRILLIC CAPITAL LETTER A) do NOT
# decompose to ASCII under NFKC. We supplement NFKC with an explicit
# confusables map covering the highest-impact homoglyphs of ASCII
# letters: full uppercase + lowercase A-Z. The map is intentionally
# bounded -- we are not vendoring the full Unicode confusables table;
# the SDK ships a deterministic, ASCII-only confusables set the test
# corpus pins and the v0.2 work expands. Strings in the SDK source are
# ASCII per CLAUDE.md; the table is built from explicit code points.
def _build_confusables_map() -> dict[str, str]:
    table: dict[str, str] = {}
    # Cyrillic uppercase confusables that visually match ASCII A-Z.
    cyrillic_upper_pairs = [
        ("A", 0x0410),  # CYRILLIC CAPITAL LETTER A
        ("B", 0x0412),  # CYRILLIC CAPITAL LETTER VE
        ("C", 0x0421),  # CYRILLIC CAPITAL LETTER ES
        ("E", 0x0415),  # CYRILLIC CAPITAL LETTER IE
        ("H", 0x041D),  # CYRILLIC CAPITAL LETTER EN
        ("I", 0x0406),  # CYRILLIC CAPITAL LETTER I (Ukrainian)
        ("J", 0x0408),  # CYRILLIC CAPITAL LETTER JE
        ("K", 0x041A),  # CYRILLIC CAPITAL LETTER KA
        ("M", 0x041C),  # CYRILLIC CAPITAL LETTER EM
        ("N", 0x0418),  # CYRILLIC CAPITAL LETTER I (visually similar)
        ("O", 0x041E),  # CYRILLIC CAPITAL LETTER O
        ("P", 0x0420),  # CYRILLIC CAPITAL LETTER ER
        ("S", 0x0405),  # CYRILLIC CAPITAL LETTER DZE
        ("T", 0x0422),  # CYRILLIC CAPITAL LETTER TE
        ("X", 0x0425),  # CYRILLIC CAPITAL LETTER HA
        ("Y", 0x0423),  # CYRILLIC CAPITAL LETTER U
    ]
    for ascii_char, codepoint in cyrillic_upper_pairs:
        table[chr(codepoint)] = ascii_char
    # Cyrillic lowercase confusables.
    cyrillic_lower_pairs = [
        ("a", 0x0430),  # CYRILLIC SMALL LETTER A
        ("c", 0x0441),  # CYRILLIC SMALL LETTER ES
        ("e", 0x0435),  # CYRILLIC SMALL LETTER IE
        ("o", 0x043E),  # CYRILLIC SMALL LETTER O
        ("p", 0x0440),  # CYRILLIC SMALL LETTER ER
        ("x", 0x0445),  # CYRILLIC SMALL LETTER HA
        ("y", 0x0443),  # CYRILLIC SMALL LETTER U
    ]
    for ascii_char, codepoint in cyrillic_lower_pairs:
        table[chr(codepoint)] = ascii_char
    # Greek capital letters that visually match ASCII.
    greek_pairs = [
        ("A", 0x0391),  # GREEK CAPITAL LETTER ALPHA
        ("B", 0x0392),  # GREEK CAPITAL LETTER BETA
        ("E", 0x0395),  # GREEK CAPITAL LETTER EPSILON
        ("H", 0x0397),  # GREEK CAPITAL LETTER ETA
        ("I", 0x0399),  # GREEK CAPITAL LETTER IOTA
        ("K", 0x039A),  # GREEK CAPITAL LETTER KAPPA
        ("M", 0x039C),  # GREEK CAPITAL LETTER MU
        ("N", 0x039D),  # GREEK CAPITAL LETTER NU
        ("O", 0x039F),  # GREEK CAPITAL LETTER OMICRON
        ("P", 0x03A1),  # GREEK CAPITAL LETTER RHO
        ("T", 0x03A4),  # GREEK CAPITAL LETTER TAU
        ("X", 0x03A7),  # GREEK CAPITAL LETTER CHI
        ("Y", 0x03A5),  # GREEK CAPITAL LETTER UPSILON
        ("Z", 0x0396),  # GREEK CAPITAL LETTER ZETA
    ]
    for ascii_char, codepoint in greek_pairs:
        table[chr(codepoint)] = ascii_char
    return table


_CONFUSABLES_MAP: Final[dict[str, str]] = _build_confusables_map()


def _normalise_for_matching(value: str) -> str:
    """Return the NFKC + confusables-folded form of ``value``.

    The result is what the matcher regexes operate on. The original
    string positions are also tracked separately (see :class:`_Span`)
    so the engine can splice the placeholder back into the original
    bytes at the right offset.
    """
    # NFKC handles compatibility decomposition (full-width digits,
    # ligatures, presentation forms). It does NOT decompose Cyrillic
    # or Greek confusables to their ASCII look-alikes; the explicit
    # table below covers those.
    nfkc = unicodedata.normalize("NFKC", value)
    if not _CONFUSABLES_MAP:
        return nfkc
    return "".join(_CONFUSABLES_MAP.get(ch, ch) for ch in nfkc)


# ---------------------------------------------------------------------------
# Policy schema parsing
# ---------------------------------------------------------------------------


def _jsonpath_to_pointer(selector: str) -> str:
    """Compile a JSONPath (RFC 9535 subset) selector to an RFC 6901 pointer.

    Supported subset (VAL-V3M5-018):

      * ``$``                   -- the root document (returns ``""``).
      * ``$.<key>``             -- dotted child access; key chars are
        ``[A-Za-z_][A-Za-z0-9_-]*``. RFC 6901 escapes are applied to the
        key (``~`` -> ``~0``, ``/`` -> ``~1``).
      * ``$.<key>[N]``          -- non-negative integer array index.
      * Chained combinations:    ``$.a.b[0].c[1]`` etc.

    Out of scope (raises :class:`ValueError`):

      * ``..`` (recursive descent), ``*`` (wildcard), ``[?(expr)]``
        (filter), ``[start:end:step]`` (slice), bracket-notation string
        keys ``['key']`` (the spec G.3 fixtures use only dotted form).

    Returns the equivalent RFC 6901 pointer string. The empty pointer
    ``""`` represents the document root.

    Cross-runtime parity: the TypeScript redaction module ships an
    identically-shaped parser (``packages/sdk-typescript/src/redaction.ts``)
    so both runtimes resolve the same selector to the same pointer.
    """
    if not isinstance(selector, str) or not selector:
        raise ValueError("selector MUST be a non-empty string")
    if not selector.startswith("$"):
        raise ValueError(f"selector MUST start with '$': {selector!r}")
    rest = selector[1:]
    if not rest:
        return ""
    parts: list[str] = []
    i = 0
    n = len(rest)
    while i < n:
        ch = rest[i]
        if ch == ".":
            # Dotted child access: read the key up to the next '.' or '['.
            i += 1
            if i >= n or rest[i] in ".[":
                raise ValueError(
                    f"selector has empty key after '.': {selector!r}"
                )
            start = i
            while i < n and rest[i] not in ".[":
                key_ch = rest[i]
                # Validate the key character set up-front so we fail
                # closed on unsupported features like wildcards.
                if key_ch in "*?(":
                    raise ValueError(
                        f"selector uses unsupported feature {key_ch!r}: "
                        f"{selector!r}"
                    )
                i += 1
            key = rest[start:i]
            if not key:
                raise ValueError(
                    f"selector has empty key segment: {selector!r}"
                )
            # Reject recursive-descent (``..``) by detecting the empty
            # key that would result from two consecutive dots; the loop
            # already raises above on ``rest[i] == '.'`` immediately
            # after consuming the leading dot, so this is belt-and-
            # braces.
            parts.append(_escape_pointer_token(key))
        elif ch == "[":
            # Integer array index: ``[N]`` where N >= 0.
            i += 1
            start = i
            while i < n and rest[i].isdigit():
                i += 1
            if i == start or i >= n or rest[i] != "]":
                raise ValueError(
                    f"selector has malformed array index: {selector!r}"
                )
            index_token = rest[start:i]
            i += 1  # consume ']'
            parts.append(index_token)
        else:
            raise ValueError(
                f"selector has unexpected character {ch!r} at position "
                f"{i + 1}: {selector!r}"
            )
    return "/" + "/".join(parts) if parts else ""


def _json_pointer_matches(matcher_path: str, pointer: str) -> bool:
    """Return ``True`` if RFC 6901 ``pointer`` matches a ``json_pointer``
    matcher path, honoring a single-segment ``*`` wildcard (VAL-REDACT-001).

    Both arguments are RFC 6901 JSON Pointers built by the same
    convention used in :meth:`RedactionEngine._walk`: a leading ``/``
    then ``/``-separated reference tokens, each token escaped per RFC
    6901 sec 4 (``~`` -> ``~0``, ``/`` -> ``~1``). Splitting on ``/``
    therefore yields aligned, identically-escaped segments on both
    sides, so exact tokens compare correctly and a ``*`` token in the
    matcher path matches any single concrete segment.

    Wildcard semantics:

      * A matcher token equal to ``*`` matches exactly one concrete
        segment (any array index or object key) at that position.
      * Every other matcher token must equal the concrete token exactly.
      * The wildcard is single-segment, never a recursive-descent glob,
        so the matcher path and the concrete pointer MUST have the same
        number of segments to match. ``/messages/*/content/text`` does
        not match ``/messages/0/extra/content/text``.

    A matcher path with no ``*`` token reduces to exact string equality,
    preserving prior behavior (and cross-runtime parity) for every
    non-wildcard ``json_pointer`` matcher.
    """
    if "*" not in matcher_path:
        # Fast path: no wildcard -> exact membership, identical to the
        # pre-VAL-REDACT-001 behavior and to the TS exact-match compare.
        return matcher_path == pointer
    matcher_tokens = matcher_path.split("/")
    pointer_tokens = pointer.split("/")
    if len(matcher_tokens) != len(pointer_tokens):
        return False
    for matcher_token, pointer_token in zip(
        matcher_tokens, pointer_tokens, strict=True
    ):
        if matcher_token == "*":
            # Single-segment wildcard. The empty string only occurs as
            # the synthetic leading segment (both sides share it); a
            # leading-segment ``*`` would require the matcher path to
            # start with ``*`` rather than ``/``, which never occurs for
            # a well-formed RFC 6901 pointer, so an empty concrete token
            # here would be a malformed pointer -- reject it.
            if pointer_token == "":
                return False
            continue
        if matcher_token != pointer_token:
            return False
    return True


@dataclass(frozen=True)
class _CompiledMatcher:
    """A single matcher prepared for engine consumption.

    ``json_paths`` holds the raw selector strings as authored by the policy:
    RFC 6901 JSON Pointers for ``kind='json_pointer'`` (``/foo/bar``) or
    RFC 9535 JSONPath subset for ``kind='json_path'`` (``$.foo.bar``). The
    engine resolves the pointer form for the current leaf and compares it
    against the matcher's compiled pointer form (``json_pointers``) below.
    """

    id: str
    kind: str
    action: str
    pattern: re.Pattern[str] | None
    json_paths: tuple[str, ...]
    # JSONPath selectors compiled to their equivalent RFC 6901 JSON Pointer
    # form so leaf evaluation can reuse the same pointer-matching path used
    # by json_pointer matchers. Empty for non-pointer/non-path matcher kinds.
    json_pointers: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ActionPolicy:
    """Per-action behaviour from the policy's ``action_policy`` block."""

    hash_salt_ref: str
    hash_algorithm: str
    redact_placeholder: str
    drop_placeholder: str | None


@dataclass(frozen=True)
class RedactionPolicy:
    """A parsed, validated v1 redaction policy (spec G.2).

    Construct via :meth:`RedactionPolicy.load`. Direct construction
    bypasses validation and is reserved for engine internals.

    Attributes:
        policy_version: The opaque version string captured at policy
            publish time. Determinism keys off this value.
        raw_capture: Whether hosted Relay is permitted to persist raw
            text. ``True`` is only allowed when ``dpa_ref`` and
            ``approver_user_id`` are BOTH non-empty.
        dpa_ref: Reference to the signed Data Processing Agreement that
            authorises raw capture. Required when raw_capture is True.
        approver_user_id: User id of the org-admin who approved this
            policy version. Required when raw_capture is True.
        matchers: The compiled matcher list. Order is preserved; the
            engine applies matchers in declaration order on a per-leaf
            basis.
        action_policy: Per-action behaviour (placeholder, salt_ref).
        applies_to_fields: The list of top-level trace-payload fields
            the matchers run against. Defaults to
            :data:`DEFAULT_APPLIES_TO_FIELDS`.
    """

    policy_version: str
    raw_capture: bool
    dpa_ref: str | None
    approver_user_id: str | None
    matchers: tuple[_CompiledMatcher, ...]
    action_policy: _ActionPolicy
    applies_to_fields: tuple[str, ...] = field(default=DEFAULT_APPLIES_TO_FIELDS)

    @classmethod
    def load(cls, body: dict[str, Any]) -> RedactionPolicy:
        """Parse and validate a v1 redaction policy body.

        Raises:
            RelayPolicyError: The policy is structurally invalid.
                ``details['reason']`` names the specific failure
                ("schema_version", "raw_capture_dpa", "bad_regex",
                "unknown_kind", "unknown_action", etc.). No partially-
                applied policy is returned; the SDK fails closed
                (VAL-W3-025).
        """
        if not isinstance(body, dict):
            raise RelayPolicyError(
                "redaction policy body must be a dict",
                details={"reason": "wrong_type", "received": type(body).__name__},
            )
        # schema_version literal check. Both the canonical wire literal
        # and the W4.1 codegen-friendly alias are accepted; this matches
        # TS (redaction.ts:77-78, 282-296). Comparing against a tuple
        # (not a frozenset) tolerates unhashable received values such as
        # ``list`` without raising TypeError.
        received_schema_version = body.get("schema_version")
        if received_schema_version not in (
            _POLICY_SCHEMA_VERSION_PRIMARY,
            _POLICY_SCHEMA_VERSION_ALIAS,
        ):
            raise RelayPolicyError(
                f"redaction policy schema_version MUST be "
                f"{_POLICY_SCHEMA_VERSION_PRIMARY!r} (or v0.1 alias "
                f"{_POLICY_SCHEMA_VERSION_ALIAS!r})",
                details={
                    "reason": "schema_version",
                    "expected": _POLICY_SCHEMA_VERSION_PRIMARY,
                    "received": received_schema_version,
                },
            )
        # policy_version required + non-empty.
        policy_version = body.get("policy_version")
        if not isinstance(policy_version, str) or not policy_version.strip():
            raise RelayPolicyError(
                "redaction policy policy_version MUST be a non-empty string",
                details={"reason": "policy_version_missing"},
            )
        # raw_capture strict bool (default False).
        raw_capture = body.get("raw_capture", False)
        if not isinstance(raw_capture, bool):
            raise RelayPolicyError(
                "redaction policy raw_capture MUST be a strict bool",
                details={
                    "reason": "raw_capture_not_bool",
                    "received_type": type(raw_capture).__name__,
                },
            )
        dpa_ref = body.get("dpa_ref")
        if dpa_ref is not None and not isinstance(dpa_ref, str):
            raise RelayPolicyError(
                "redaction policy dpa_ref MUST be a string or null",
                details={"reason": "dpa_ref_wrong_type"},
            )
        approver_user_id = body.get("approver_user_id")
        if approver_user_id is not None and not isinstance(approver_user_id, str):
            raise RelayPolicyError(
                "redaction policy approver_user_id MUST be a string or null",
                details={"reason": "approver_wrong_type"},
            )
        # Cross-field: raw_capture=True requires BOTH dpa_ref and
        # approver_user_id (CLAUDE.md banned pattern #11; spec G.1).
        if raw_capture:
            missing: list[str] = []
            if not dpa_ref:
                missing.append("dpa_ref")
            if not approver_user_id:
                missing.append("approver_user_id")
            if missing:
                raise RelayPolicyError(
                    "redaction policy raw_capture=true requires dpa_ref AND "
                    "approver_user_id; refusing to load policy that would "
                    "permit raw plaintext capture without DPA + approver",
                    details={
                        "reason": "raw-capture-missing-dpa-or-approver",
                        "missing": missing,
                    },
                )
        # Matchers list.
        raw_matchers = body.get("matchers", [])
        if not isinstance(raw_matchers, list):
            raise RelayPolicyError(
                "redaction policy matchers MUST be a list",
                details={"reason": "matchers_wrong_type"},
            )
        compiled: list[_CompiledMatcher] = []
        for idx, raw in enumerate(raw_matchers):
            if not isinstance(raw, dict):
                raise RelayPolicyError(
                    f"matcher #{idx} MUST be a dict",
                    details={"reason": "matcher_wrong_type", "index": idx},
                )
            kind = raw.get("kind")
            if kind not in _KNOWN_MATCHER_KINDS:
                raise RelayPolicyError(
                    f"matcher #{idx} has unknown kind {kind!r}",
                    details={
                        "reason": "unknown_kind",
                        "index": idx,
                        "received": kind,
                    },
                )
            action = raw.get("action")
            if action not in _KNOWN_ACTIONS:
                raise RelayPolicyError(
                    f"matcher #{idx} has unknown action {action!r}",
                    details={
                        "reason": "unknown_action",
                        "index": idx,
                        "received": action,
                    },
                )
            matcher_id = raw.get("id")
            if not isinstance(matcher_id, str) or not matcher_id.strip():
                raise RelayPolicyError(
                    f"matcher #{idx} MUST have a non-empty id",
                    details={"reason": "matcher_id_missing", "index": idx},
                )
            pattern: re.Pattern[str] | None = None
            json_paths: tuple[str, ...] = ()
            json_pointers: tuple[str, ...] = ()
            if kind == "regex":
                raw_pattern = raw.get("pattern")
                if not isinstance(raw_pattern, str) or not raw_pattern:
                    raise RelayPolicyError(
                        f"regex matcher #{idx} MUST have a non-empty pattern",
                        details={"reason": "regex_pattern_missing", "index": idx},
                    )
                # Reject Python named groups consistently with the TS SDK so
                # the same policy body loads (or is rejected) identically on
                # both runtimes (VAL-REDACT-003).
                if _PYTHON_NAMED_GROUP_RE.search(raw_pattern):
                    raise RelayPolicyError(
                        f"regex matcher #{idx} pattern is invalid: "
                        "Python named groups '(?P<name>...)' / '(?P=name)' "
                        "are not part of the supported cross-language regex "
                        "dialect",
                        details={
                            "reason": "named_group_unsupported",
                            "index": idx,
                            "pattern": raw_pattern,
                            "error": "named groups are not supported",
                        },
                    )
                try:
                    pattern = _compile_regex_pattern(raw_pattern)
                except re.error as exc:
                    raise RelayPolicyError(
                        f"regex matcher #{idx} pattern is invalid: {exc}",
                        details={
                            "reason": "bad_regex",
                            "index": idx,
                            "pattern": raw_pattern,
                            "error": str(exc),
                        },
                    ) from exc
            elif kind == "json_pointer":
                raw_paths = raw.get("paths")
                if not isinstance(raw_paths, list) or not all(
                    isinstance(p, str) and p for p in raw_paths
                ):
                    raise RelayPolicyError(
                        f"json_pointer matcher #{idx} MUST have a non-empty "
                        "list of string paths",
                        details={"reason": "json_paths_missing", "index": idx},
                    )
                json_paths = tuple(raw_paths)
            elif kind == "json_path":
                # VAL-V3M5-018. JSONPath selectors (RFC 9535 subset). The
                # SDK ships a minimal native parser to keep the redaction
                # path dep-free and deterministic across both runtimes;
                # the supported subset is documented at
                # :func:`_jsonpath_to_pointer`.
                raw_paths = raw.get("paths")
                if (
                    not isinstance(raw_paths, list)
                    or not raw_paths
                    or not all(
                        isinstance(p, str) and p for p in raw_paths
                    )
                ):
                    raise RelayPolicyError(
                        f"json_path matcher #{idx} MUST have a non-empty "
                        "list of string paths",
                        details={"reason": "json_paths_missing", "index": idx},
                    )
                try:
                    pointers = tuple(
                        _jsonpath_to_pointer(p) for p in raw_paths
                    )
                except ValueError as exc:
                    raise RelayPolicyError(
                        f"json_path matcher #{idx} has an unsupported "
                        f"selector: {exc}",
                        details={
                            "reason": "json_path_unsupported",
                            "index": idx,
                            "error": str(exc),
                        },
                    ) from exc
                json_paths = tuple(raw_paths)
                json_pointers = pointers
            compiled.append(
                _CompiledMatcher(
                    id=matcher_id,
                    kind=str(kind),
                    action=str(action),
                    pattern=pattern,
                    json_paths=json_paths,
                    json_pointers=json_pointers,
                )
            )
        # action_policy block.
        raw_action_policy = body.get("action_policy", {})
        if not isinstance(raw_action_policy, dict):
            raise RelayPolicyError(
                "redaction policy action_policy MUST be a dict",
                details={"reason": "action_policy_wrong_type"},
            )
        hash_block = raw_action_policy.get("hash", {})
        if not isinstance(hash_block, dict):
            raise RelayPolicyError(
                "redaction policy action_policy.hash MUST be a dict",
                details={"reason": "hash_block_wrong_type"},
            )
        hash_algorithm = hash_block.get("algorithm", "hmac-sha256")
        if hash_algorithm != "hmac-sha256":
            raise RelayPolicyError(
                "redaction policy action_policy.hash.algorithm MUST be "
                "'hmac-sha256' (plain SHA-256 is forbidden, spec G.2)",
                details={
                    "reason": "hash_algorithm_unsupported",
                    "received": hash_algorithm,
                },
            )
        hash_salt_ref = hash_block.get("salt_ref")
        if not isinstance(hash_salt_ref, str) or not hash_salt_ref.strip():
            raise RelayPolicyError(
                "redaction policy action_policy.hash.salt_ref MUST be a "
                "non-empty string",
                details={"reason": "hash_salt_ref_missing"},
            )
        redact_block = raw_action_policy.get("redact", {})
        if not isinstance(redact_block, dict):
            raise RelayPolicyError(
                "redaction policy action_policy.redact MUST be a dict",
                details={"reason": "redact_block_wrong_type"},
            )
        redact_placeholder = redact_block.get("placeholder", "<redacted>")
        if not isinstance(redact_placeholder, str):
            raise RelayPolicyError(
                "redaction policy action_policy.redact.placeholder MUST be a string",
                details={"reason": "redact_placeholder_wrong_type"},
            )
        drop_block = raw_action_policy.get("drop", {})
        if not isinstance(drop_block, dict):
            raise RelayPolicyError(
                "redaction policy action_policy.drop MUST be a dict",
                details={"reason": "drop_block_wrong_type"},
            )
        drop_placeholder = drop_block.get("placeholder")
        if drop_placeholder is not None and not isinstance(drop_placeholder, str):
            raise RelayPolicyError(
                "redaction policy action_policy.drop.placeholder MUST be a "
                "string or null",
                details={"reason": "drop_placeholder_wrong_type"},
            )
        action_policy = _ActionPolicy(
            hash_salt_ref=hash_salt_ref,
            hash_algorithm=hash_algorithm,
            redact_placeholder=redact_placeholder,
            drop_placeholder=drop_placeholder,
        )
        # applies_to_fields list (optional override).
        raw_fields = body.get("applies_to_fields")
        if raw_fields is None:
            applies_to_fields: tuple[str, ...] = DEFAULT_APPLIES_TO_FIELDS
        else:
            if not isinstance(raw_fields, list) or not all(
                isinstance(f, str) and f for f in raw_fields
            ):
                raise RelayPolicyError(
                    "redaction policy applies_to_fields MUST be a list of "
                    "non-empty strings",
                    details={"reason": "applies_to_fields_wrong_type"},
                )
            applies_to_fields = tuple(raw_fields)
        return cls(
            policy_version=policy_version,
            raw_capture=raw_capture,
            dpa_ref=dpa_ref,
            approver_user_id=approver_user_id,
            matchers=tuple(compiled),
            action_policy=action_policy,
            applies_to_fields=applies_to_fields,
        )


# Caller-supplied salt resolution. Salts are tenant-scoped secrets; the
# SDK never bakes them in. Production callers wire this to the sidecar
# salt registry; tests pass a deterministic in-memory provider.
SaltProvider = Callable[[str], bytes]


def _hmac_sha256_hex(salt: bytes, plaintext: str) -> str:
    """Return the hex digest of HMAC-SHA-256(salt, plaintext utf-8)."""
    return hmac.new(salt, plaintext.encode("utf-8"), hashlib.sha256).hexdigest()


def _escape_pointer_token(token: Any) -> str:
    """Escape a single RFC 6901 JSON Pointer reference token.

    Per RFC 6901 sec 4: ``~`` -> ``~0``, ``/`` -> ``~1``. The escape
    of ``~`` MUST happen before the escape of ``/`` so the encoder is
    its own inverse on round-trip.

    Non-string keys (rare in trace payloads but legal in hand-built
    dicts used by tests) are coerced via :func:`str` first so the
    walker can compute a stable pointer for them.
    """
    raw = token if isinstance(token, str) else str(token)
    return raw.replace("~", "~0").replace("/", "~1")


def _to_string(value: Any) -> str:
    """Coerce a JSON-leaf value to a string for matcher consumption.

    JSON primitives are coerced to their canonical JSON literal form so
    cross-language redaction (Python vs TypeScript) produces byte-equal
    HMAC digests for the same wire input: ``None``->``"null"``,
    ``True``->``"true"``, ``False``->``"false"``. Numbers and strings
    pass through. Bytes are decoded with ``errors='replace'`` so
    mixed-encoding OCR output (VAL-W3-023) cannot smuggle a secret
    through an undecodable byte.

    Float coercion MUST match the TypeScript redaction engine
    (``packages/sdk-typescript/src/redaction.ts``: ``String(value)``)
    so the same wire input produces byte-equal HMAC digests across
    SDKs. Python's bare ``str(1.0)`` returns ``"1.0"`` while
    ECMA-262 ``String(1.0)`` returns ``"1"``; routing floats through
    the ECMA-262 number-to-string encoder (``_encode_number`` in
    ``relay_contracts.canonical``) closes that divergence.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", errors="replace")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        # Local import to keep ``relay_contracts`` an optional
        # dependency at module import time. The redaction hot path
        # is policy-publish + per-span walk, not the cold-start path.
        try:
            from relay_contracts.canonical import _encode_number
        except ImportError:
            # Fallback: hand-roll the ECMA-262 ToString(Number)
            # whole-integer shortcut to preserve TS parity for the
            # common case (``1.0`` -> ``"1"``).
            import math as _math
            if _math.isfinite(value) and value == int(value):
                return str(int(value))
            return str(value)
        # Non-finite floats: mirror ECMA-262 ToString(Number) exactly
        # so cross-language digests still match.
        import math as _math
        if _math.isnan(value):
            return "NaN"
        if _math.isinf(value):
            return "-Infinity" if value < 0 else "Infinity"
        try:
            return _encode_number(value)
        except Exception:
            # Out-of-range floats fall back to a TS-parity repr.
            # ECMA-262 ToString(Number) for finite values that
            # _encode_number cannot represent is exceedingly rare.
            return repr(value)
    return str(value)


class RedactionEngine:
    """A policy-bound redactor that walks a payload and emits a copy.

    The engine is stateless across calls: redacting the same payload
    twice produces byte-identical output (VAL-W3-024). The engine is
    thread-safe; the compiled regex patterns and HMAC primitives are
    re-entrant.
    """

    def __init__(
        self,
        *,
        policy: RedactionPolicy,
        salt_provider: SaltProvider,
    ) -> None:
        self._policy = policy
        self._salt_provider = salt_provider
        # Cache the resolved salt at construction time so the HMAC path
        # is deterministic across calls (and so a misconfigured
        # salt_ref surfaces eagerly rather than mid-trace).
        self._cached_salt: bytes | None = None

    @property
    def policy(self) -> RedactionPolicy:
        return self._policy

    def _resolve_salt(self) -> bytes:
        if self._cached_salt is None:
            self._cached_salt = self._salt_provider(
                self._policy.action_policy.hash_salt_ref
            )
            if not isinstance(self._cached_salt, bytes | bytearray):
                raise RelayPolicyError(
                    "salt_provider MUST return bytes",
                    details={
                        "reason": "salt_provider_wrong_type",
                        "salt_ref": self._policy.action_policy.hash_salt_ref,
                    },
                )
        return bytes(self._cached_salt)

    def _apply_matchers_to_string(self, value: str) -> str:
        """Return the redacted form of ``value`` after matcher application.

        Matchers run in declaration order on the NFKC + confusables-
        folded form of the string. Match spans are spliced back into
        that SAME normalized form (not the original), so the result is
        the normalized form with matched substrings replaced.

        Rationale (Bug 4 P1): NFKC is not length-preserving for
        combining marks (e.g. ``"u" + U+0308`` collapses to U+00FC).
        Splicing offsets computed against the normalized form into the
        ORIGINAL string left fragments of the matched plaintext behind
        when the two strings had different lengths. Matching and
        splicing MUST operate on the same string to be correct under
        the full Unicode input space the SDK accepts.

        Trade-off: for leaves that contained NFKC-decomposable code
        points outside any match, the output now contains the composed
        form instead of the original decomposed form. Since the leaf
        was traversed because it is a candidate for redaction, the
        composed-vs-decomposed distinction has no observable effect on
        downstream consumers (which compare strings via Unicode
        canonical equivalence or via raw byte SHA-256 of a downstream
        canonicalized envelope).
        """
        if not value:
            return value
        normalised = _normalise_for_matching(value)
        # Walk matchers, collecting (start, end, replacement) tuples.
        spans: list[tuple[int, int, str]] = []
        for matcher in self._policy.matchers:
            if matcher.kind != "regex" or matcher.pattern is None:
                # json_pointer matchers are applied at the leaf level
                # in :meth:`_walk`, not at the string level.
                continue
            for m in matcher.pattern.finditer(normalised):
                start, end = m.span()
                matched_text = normalised[start:end]
                replacement = self._build_replacement(matcher, matched_text)
                spans.append((start, end, replacement))
        if not spans:
            return normalised
        # Sort by start, then by end descending so the span that OPENS each
        # overlap group is the earliest-starting and (among equal starts)
        # longest match -- a deterministic, replacement-defining "highest
        # priority" span. Overlapping spans are then merged into their
        # INTERVAL UNION rather than dropped.
        #
        # VAL-REDACT-002 (HIGH / security): the prior logic skipped any span
        # that overlapped the kept span. When a later span started inside the
        # kept span but extended BEYOND its end, the tail between the two ends
        # was spliced back in as plaintext -- leaking the unredacted tail of a
        # matched secret. Proper interval merging extends the open interval's
        # end to max(end) so the entire union of matched ranges is redacted by
        # a single replacement and no matched byte is ever emitted in clear.
        spans.sort(key=lambda t: (t[0], -t[1]))
        merged: list[tuple[int, int, str]] = []
        for start, end, repl in spans:
            if merged and start < merged[-1][1]:
                # Overlap: extend the open interval to the union end, keeping
                # the replacement of the span that opened the interval (the
                # earliest-starting / longest-at-that-start match). The end is
                # max() because a fully-contained later span (end <= prev_end)
                # must not shrink the redacted range.
                prev_start, prev_end, prev_repl = merged[-1]
                if end > prev_end:
                    merged[-1] = (prev_start, end, prev_repl)
                continue
            merged.append((start, end, repl))
        # Splice replacements into the NORMALIZED string at the offsets
        # we computed against the normalized form. This is correct
        # under non-length-preserving normalization (Bug 4 fix).
        out_parts: list[str] = []
        cursor = 0
        for start, end, repl in merged:
            out_parts.append(normalised[cursor:start])
            out_parts.append(repl)
            cursor = end
        out_parts.append(normalised[cursor:])
        return "".join(out_parts)

    def _build_replacement(
        self, matcher: _CompiledMatcher, matched_text: str
    ) -> str:
        ap = self._policy.action_policy
        if matcher.action == "redact":
            return ap.redact_placeholder
        if matcher.action == "hash":
            salt = self._resolve_salt()
            return _hmac_sha256_hex(salt, matched_text)
        if matcher.action == "drop":
            return ap.drop_placeholder or ""
        # Unreachable: load() validates the action set.
        raise RelayPolicyError(
            f"matcher {matcher.id!r} has unsupported action {matcher.action!r}",
            details={"reason": "unsupported_action", "matcher_id": matcher.id},
        )

    def _walk(self, value: Any, *, pointer: str = "") -> Any:
        """Walk ``value``, redacting strings and digesting bytes in place.

        Behavior per leaf type (must mirror TS ``walk`` at
        ``packages/sdk-typescript/src/redaction.ts:784-821``):

          * ``str``: NFKC + confusables-fold, run matchers, return
            redacted string. If any ``json_pointer`` matcher declared
            ``pointer`` (the current leaf's JSON Pointer per RFC 6901,
            spec G.2 line 4132), the declared matcher's action wins
            over any regex matchers because the pointer match is the
            most specific selector (VAL-V2M08-025).
          * ``bytes`` / ``bytearray``: replace with a digest-only
            reference ``{"_digest_sha256": "<hex>"}`` (VAL-W4-025 /
            keystone invariant #7). Plaintext bytes MUST NOT survive
            into the wire body even when no matcher would fire on a
            decoded string; routing bytes through the string matcher
            was the Bug 2 P0 violation. A ``json_pointer`` matcher
            that targets the same path produces the matcher's
            placeholder instead (the caller asked for the path to be
            redacted; we honor that even when the leaf is binary).
          * ``memoryview``: refused. ``memoryview`` is Python's
            parallel of JS ``Blob`` -- a view that does not guarantee
            a contiguous underlying buffer the engine can hash
            atomically. The caller MUST pass resolved ``bytes`` (or a
            ``bytearray``).
          * ``dict`` / ``list`` / ``tuple``: descended.
          * Everything else (int, float, bool, None): passed through,
            unless a ``json_pointer`` matcher fires on the current
            ``pointer`` -- in which case the matcher's action applies
            after stringifying the value (mirrors regex behavior on
            non-string leaves at :meth:`_to_string`).

        ``pointer`` accumulates the RFC 6901 JSON Pointer path of the
        current node ("" for the root). Per RFC 6901 sec 4, the tokens
        "~" and "/" inside a key escape to "~0" and "~1" respectively;
        :func:`_escape_pointer_token` handles that. List indices are
        appended as decimal integer tokens.
        """
        # JSON Pointer leaf evaluation (VAL-V2M08-025): a json_pointer
        # matcher whose ``paths`` includes the current pointer wins
        # over any regex matcher for the same leaf. Apply at every
        # leaf type that can legitimately be a redaction target
        # (string, bytes, scalar). Containers (dict/list/tuple) are
        # descended unconditionally; the per-leaf evaluation happens
        # when the walk reaches a non-container.
        json_pointer_match = self._find_json_pointer_match(pointer)
        if isinstance(value, dict):
            return {
                k: self._walk(
                    v,
                    pointer=pointer + "/" + _escape_pointer_token(k),
                )
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [
                self._walk(v, pointer=pointer + "/" + str(idx))
                for idx, v in enumerate(value)
            ]
        if isinstance(value, tuple):
            return tuple(
                self._walk(v, pointer=pointer + "/" + str(idx))
                for idx, v in enumerate(value)
            )
        if isinstance(value, bytes | bytearray):
            if json_pointer_match is not None:
                # VAL-V2M08-025: an explicit json_pointer match at a
                # bytes leaf yields the matcher's placeholder. Hashing
                # path uses HMAC over the bytes (decoded utf-8 with
                # replace) so the digest still references the bytes
                # deterministically.
                return self._build_replacement(
                    json_pointer_match,
                    _to_string(value),
                )
            digest = hashlib.sha256(bytes(value)).hexdigest()
            return {"_digest_sha256": digest}
        if isinstance(value, memoryview):
            raise RelayPolicyError(
                "memoryview payloads MUST be resolved to bytes before "
                "redaction; refusing to include a raw memoryview",
                details={"reason": "unresolved_memoryview"},
            )
        if isinstance(value, str):
            if json_pointer_match is not None:
                # Pointer-match wins over regex (most specific
                # selector). Build the replacement on the original
                # string so the placeholder is deterministic; do NOT
                # run regex matchers on top, because the pointer
                # match already produced the canonical output.
                return self._build_replacement(json_pointer_match, value)
            return self._apply_matchers_to_string(value)
        # Non-string, non-bytes scalar (int/float/bool/None).
        if json_pointer_match is not None:
            return self._build_replacement(
                json_pointer_match,
                _to_string(value),
            )
        return value

    def _find_json_pointer_match(
        self, pointer: str
    ) -> _CompiledMatcher | None:
        """Return the first pointer-style matcher whose paths include ``pointer``.

        Two matcher kinds participate in pointer-level evaluation:

          * ``json_pointer`` (RFC 6901) -- raw pointers stored in
            ``matcher.json_paths``. A ``*`` reference token in a matcher
            path is a single-segment wildcard (VAL-REDACT-001): it
            matches any one array index or object key at that position.
            All other tokens must match exactly. The wildcard is
            single-segment, never a recursive-descent glob, so the
            matcher path and the concrete pointer must have the same
            segment count to match.
          * ``json_path`` (RFC 9535 subset, VAL-V3M5-018) -- selectors
            compiled to RFC 6901 pointer form at policy load and stored
            in ``matcher.json_pointers``. ``_jsonpath_to_pointer`` rejects
            ``*`` selectors, so these compiled pointers contain no
            wildcards and are compared by exact membership.

        Matchers are evaluated in declaration order; the first hit
        wins. ``pointer`` is the empty string at the root and never
        matches a matcher (matchers declare leaf paths like
        ``/user/email``, not the document root).
        """
        if not pointer:
            return None
        for matcher in self._policy.matchers:
            if matcher.kind == "json_pointer" and any(
                _json_pointer_matches(path, pointer)
                for path in matcher.json_paths
            ):
                return matcher
            if matcher.kind == "json_path" and pointer in matcher.json_pointers:
                return matcher
        return None

    def redact(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return a redacted deep-copy of ``payload``.

        The full payload tree is walked; the matcher set is global
        because real-world callers nest tool args + retrieval docs
        under many shapes. Strings outside ``applies_to_fields`` are
        also redacted in v0.1 -- the SDK errs on the side of more
        redaction, never less (CLAUDE.md keystone #7). The
        ``applies_to_fields`` field is retained on the policy for
        forward compatibility with v0.2 selective redaction.
        """
        if not isinstance(payload, dict):
            raise RelayPolicyError(
                "payload MUST be a dict",
                details={"reason": "payload_wrong_type"},
            )
        return self._walk(payload)


def redact_capture_payload(
    engine: RedactionEngine, payload: dict[str, Any]
) -> bytes:
    """Redact ``payload`` and serialise the result to JSON bytes.

    This is the canonical SDK entry point used by the trace-capture
    surface. The returned bytes are exactly what the SDK transport
    hands to the HTTP client; the bytes are what tests inspect to
    assert plaintext absence (VAL-W3-020 .. VAL-W3-024).

    Args:
        engine: A :class:`RedactionEngine` bound to the active policy.
        payload: The pre-redaction payload dict.

    Returns:
        UTF-8 JSON bytes of the redacted payload, with sorted keys for
        determinism.
    """
    redacted = engine.redact(payload)
    # JCS-compact separators (no whitespace) match the TS canonicalizer
    # at packages/sdk-typescript/src/redaction.ts:838-864
    # (``canonicalJsonStringify``). ``ensure_ascii=False`` matches TS
    # ``JSON.stringify`` which emits raw UTF-8 for BMP code points
    # rather than ``\uXXXX`` escapes. Together these guarantee
    # byte-equality with TS for the cross-language parity corpus
    # (VAL-W4-020).
    return json.dumps(
        redacted,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def iter_known_applies_to_fields() -> Iterable[str]:
    """Iterate over the default ``applies_to_fields`` list (helper)."""
    return iter(DEFAULT_APPLIES_TO_FIELDS)


# ---------------------------------------------------------------------------
# Hosted default policy (VAL-V3M5-019, spec G.8)
# ---------------------------------------------------------------------------
# The canonical default policy hosted Relay applies when a project does not
# author its own. The constant is byte-equal to the YAML fixture at
# ``packages/schemas/raw/redaction-policy.default.v1.yaml`` when serialised
# via ``yaml.safe_dump(HOSTED_DEFAULT_POLICY, sort_keys=False)``. Default-deny
# on raw_capture per CLAUDE.md keystone #7.
#
# Matcher set:
#   - json_pointer ``/messages/*/content/text``: prompt content path used by
#     chat-completion-style payloads. The ``*`` reference token is a
#     single-segment wildcard (VAL-REDACT-001) matching any one array index
#     or object key, so concrete leaf pointers like
#     ``/messages/0/content/text`` are redacted. See
#     :func:`_json_pointer_matches`.
#   - json_pointer ``/output/text``: agent output path.
#   - regex ``(?i)password``: field-value pattern.
#   - regex ``(?i)api[_-]?key``: field-value pattern.
#   - regex ``(?i)secret``: field-value pattern.
#   - regex ``(?i)token``: field-value pattern.
HOSTED_DEFAULT_POLICY: Final[dict[str, Any]] = {
    "schema_version": "relay.redaction.v1",
    "policy_version": "hosted-default.v1",
    "raw_capture": False,
    "dpa_ref": None,
    "approver_user_id": None,
    "matchers": [
        {
            "id": "prompt-content",
            "kind": "json_pointer",
            "paths": ["/messages/*/content/text"],
            "action": "redact",
        },
        {
            "id": "output-content",
            "kind": "json_pointer",
            "paths": ["/output/text"],
            "action": "redact",
        },
        {
            "id": "password-field",
            "kind": "regex",
            "pattern": "(?i)password",
            "action": "redact",
        },
        {
            "id": "api-key-field",
            "kind": "regex",
            "pattern": "(?i)api[_-]?key",
            "action": "redact",
        },
        {
            "id": "secret-field",
            "kind": "regex",
            "pattern": "(?i)secret",
            "action": "redact",
        },
        {
            "id": "token-field",
            "kind": "regex",
            "pattern": "(?i)token",
            "action": "redact",
        },
    ],
    "action_policy": {
        "hash": {
            "algorithm": "hmac-sha256",
            "salt_ref": "hosted_default_salt",
        },
        "redact": {
            "placeholder": "<redacted>",
        },
        "drop": {
            "placeholder": None,
        },
    },
}


__all__ = [
    "DEFAULT_APPLIES_TO_FIELDS",
    "HOSTED_DEFAULT_POLICY",
    "RedactionEngine",
    "RedactionPolicy",
    "SaltProvider",
    "iter_known_applies_to_fields",
    "redact_capture_payload",
]
