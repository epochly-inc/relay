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
import math
import re
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Final

from .errors import RELAY_SDK_REGEX_REDOS_CODE, RelayPolicyError

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
# VAL-REDACT-006: regex ReDoS / complexity guard.
# ---------------------------------------------------------------------------
# Two deterministic layers protect the matcher loop from a policy-supplied
# regex causing catastrophic backtracking against a long leaf:
#
#   (1) A static load-time heuristic (:func:`_check_regex_redos_safety`)
#       rejects the classic ReDoS shape -- a quantifier applied to a group
#       whose body itself contains a quantifier (``(a+)+``, ``(a*)*``,
#       ``(.*a){10,}``). Such a pattern is never compiled or executed;
#       :meth:`RedactionPolicy.load` raises ``RelayPolicyError`` with code
#       ``RELAY-SDK-017`` and ``details["reason"] == "redos_pattern"``.
#
#   (2) An input-length CLAMP: a leaf longer than ``MAX_REDACTION_LEAF_LENGTH``
#       code points is truncated to the cap before matching, with the removed
#       tail replaced by ``REDACTION_TRUNCATION_MARKER``. This bounds total
#       matcher work even for linear-but-slow patterns over very large inputs
#       (and keeps raw plaintext beyond the cap from ever crossing the wire).
#
# BOTH constants and the marker are identical on the TypeScript SDK
# (``MAX_REDACTION_LEAF_LENGTH`` / ``REDACTION_TRUNCATION_MARKER`` in
# packages/sdk-typescript/src/redaction.ts) so cross-language byte-equality
# holds for a clamped leaf (Pattern B/C parity).

#: Maximum length (in code points) of a single string leaf the matcher loop
#: will scan. Leaves longer than this are clamped before matching. Must stay
#: byte-for-byte equal to the TypeScript SDK constant.
MAX_REDACTION_LEAF_LENGTH: Final[int] = 1_048_576  # 1 MiB of code points.

#: Deterministic marker spliced in where a leaf was truncated at the cap.
#: ASCII per CLAUDE.md "ASCII-Safe Source"; identical to the TS marker.
REDACTION_TRUNCATION_MARKER: Final[str] = "[relay:truncated]"

#: Well-formed ``{n}`` / ``{n,}`` / ``{n,m}`` interval-quantifier body.
_INTERVAL_BODY_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]+(,[0-9]*)?$")

_REDOS_REASON: Final[str] = "redos_pattern"

#: Inline-flag letters permitted inside a ``(?flags)`` / ``(?flags:...)``
#: group prefix. A superset of the SDK's supported subset on purpose: the
#: ReDoS scanner only needs to STEP OVER the prefix without mis-reading its
#: ``?`` as a quantifier; whether the flag is ultimately supported is decided
#: by :func:`_compile_regex_pattern` (Python) / ``compileRegexPattern`` (TS).
#: MUST match the TypeScript ``_INLINE_FLAG_CHARS`` set.
_INLINE_FLAG_CHARS: Final[frozenset[str]] = frozenset("imsxauL")


def _group_open_prefix_end(raw_pattern: str, i: int) -> tuple[int, bool] | None:
    """Classify a group-open token at ``raw_pattern[i]`` (which MUST be ``(``).

    Recognizes the regex GROUP-PREFIX syntaxes whose leading ``?`` / flags /
    ``:`` / ``=`` / ``!`` / ``<`` are NOT quantifiers and must not be counted as
    such by the ReDoS scanner:

      * ``(?:``                 non-capturing group
      * ``(?i`` ``(?s`` ``(?m`` ``(?x`` ``(?a`` ``(?u`` and combinations,
        either bare ``(?flags)`` (a leading inline-flag directive with NO body)
        or scoped ``(?flags:...)`` (flags + a group body)
      * ``(?=`` ``(?!``         lookahead / negative lookahead
      * ``(?<=`` ``(?<!``       lookbehind / negative lookbehind
      * ``(?P<name>`` ``(?<name>``   named group
      * ``(?P=name)``          named backreference

    Returns ``None`` when the token is a PLAIN capturing group ``(`` (no
    prefix) -- the caller handles it with the ordinary push/scan path.

    Otherwise returns ``(end, opens_body)``:

      * ``end`` is the index just past the recognized prefix (or, for a
        self-terminating construct, just past its own ``)``).
      * ``opens_body`` is ``True`` when a group BODY follows the prefix and the
        caller must push a group frame and let the matching ``)`` close it
        (``(?:``, ``(?=``, ``(?!``, ``(?<=``, ``(?<!``, ``(?flags:``, and the
        named-group forms ``(?P<name>`` / ``(?<name>``). It is ``False`` for the
        self-terminating constructs that consume their own ``)`` and contribute
        no quantifiable body (``(?flags)`` bare inline-flag directive,
        ``(?P=name)`` named backreference); the caller advances to ``end`` and
        pushes NO frame.

    Mirrors the TypeScript ``groupOpenPrefixEnd`` byte-for-byte so both engines
    skip the identical prefix set.
    """
    n = len(raw_pattern)
    # A plain capturing group: not a prefixed group. Also covers a trailing
    # bare ``(`` (malformed) -- treated as a plain open by the caller.
    if i + 1 >= n or raw_pattern[i + 1] != "?":
        return None
    j = i + 2  # index just past ``(?``
    if j >= n:
        # ``(?`` at end of pattern: malformed; let the caller treat the ``(``
        # as a plain open so the engine compile-error path surfaces it.
        return None
    c = raw_pattern[j]
    if c == ":":
        # Non-capturing group ``(?:...)``: body follows.
        return (j + 1, True)
    if c in ("=", "!"):
        # Lookahead ``(?=...)`` / ``(?!...)``: body follows.
        return (j + 1, True)
    if c == "<":
        # ``(?<=`` / ``(?<!`` lookbehind, or ``(?<name>`` named group.
        if j + 1 < n and raw_pattern[j + 1] in ("=", "!"):
            return (j + 2, True)
        # Named group ``(?<name>``: consume through the closing ``>``; body
        # follows.
        k = j + 1
        while k < n and raw_pattern[k] != ">":
            k += 1
        if k < n:  # consumed ``>``
            return (k + 1, True)
        return None  # malformed; let the caller treat ``(`` as plain open
    if c == "P":
        # Python named group ``(?P<name>...)`` (body) or named backreference
        # ``(?P=name)`` (self-terminating). Note: these are rejected for the
        # cross-language dialect by ``_compile_regex_pattern``; the ReDoS
        # scanner must still parse the prefix so the rejection reason is
        # ``named_group_unsupported``, never a spurious ``redos_pattern``.
        if j + 1 < n and raw_pattern[j + 1] == "<":
            k = j + 2
            while k < n and raw_pattern[k] != ">":
                k += 1
            if k < n:  # consumed ``>``
                return (k + 1, True)
            return None
        if j + 1 < n and raw_pattern[j + 1] == "=":
            # Named backreference ``(?P=name)``: consume through ``)``; no body.
            k = j + 2
            while k < n and raw_pattern[k] != ")":
                k += 1
            if k < n:  # consumed ``)``
                return (k + 1, False)
            return None
        return None
    if c in _INLINE_FLAG_CHARS:
        # Inline-flag group: ``(?flags)`` (bare directive) or ``(?flags:...)``
        # (scoped, body follows). Consume the flag run first.
        k = j
        while k < n and raw_pattern[k] in _INLINE_FLAG_CHARS:
            k += 1
        if k < n and raw_pattern[k] == ":":
            # Scoped flags ``(?flags:...)``: body follows the colon.
            return (k + 1, True)
        if k < n and raw_pattern[k] == ")":
            # Bare inline-flag directive ``(?flags)``: self-terminating, no
            # quantifiable body. Consume through its own ``)``.
            return (k + 1, False)
        return None  # malformed flag group; let the caller treat as plain open
    # ``(?`` followed by something we do not recognize (e.g. ``(?#comment)``
    # or an atomic group ``(?>...)``): do not special-case it here. Return
    # None so the caller treats ``(`` as a plain open; the body scan and the
    # final compile step decide its fate. Returning None never UNDER-detects:
    # an unrecognized prefix is scanned as an ordinary group body, so a genuine
    # nested quantifier inside it is still caught.
    return None


def _interval_quantifier_end(raw_pattern: str, start: int) -> int | None:
    """Return the index just past a well-formed ``{...}`` interval quantifier.

    ``raw_pattern[start]`` MUST be ``{``. Returns the index after the closing
    ``}`` for a well-formed ``{n}`` / ``{n,}`` / ``{n,m}`` interval, else
    ``None`` (a bare ``{`` is a literal). Mirrors the TS ``intervalQuantifierEnd``.
    """
    if start >= len(raw_pattern) or raw_pattern[start] != "{":
        return None
    j = start + 1
    n = len(raw_pattern)
    body_chars: list[str] = []
    while j < n and raw_pattern[j] != "}":
        body_chars.append(raw_pattern[j])
        j += 1
    if j < n and _INTERVAL_BODY_RE.match("".join(body_chars)):
        return j + 1
    return None


def _check_regex_redos_safety(raw_pattern: str) -> dict[str, str] | None:
    """Reject a catastrophic-backtracking (ReDoS) regex BEFORE compilation.

    Deterministic static scan of the raw pattern -- no compilation, no
    execution, no wall clock. The dangerous class is a quantifier applied to a
    GROUP whose body itself CONTAINS a quantifier (nested quantifiers), e.g.
    ``(a+)+``, ``(a*)*``, ``(a+)*``, ``(\\w+\\s?)*``, ``(.*a){2,}``. A single
    quantifier (``a+``, ``[A-Za-z0-9]{20,}``) or an optional inside a group with
    no OUTER quantifier (``(?i)api[_-]?key``) is linear and accepted.

    Returns ``None`` when the pattern is accepted, else a structured
    ``{"reason": ..., "error": ...}`` dict. Mirrors the TypeScript
    ``checkRegexRedosSafety`` byte-for-byte so the same policy is rejected (or
    accepted) identically on both runtimes.
    """
    redos = {
        "reason": _REDOS_REASON,
        "error": (
            "regex pattern has nested quantifiers (a quantifier applied to a "
            "group whose body itself contains a quantifier), e.g. '(a+)+'; "
            "this is a catastrophic-backtracking (ReDoS) risk and is rejected "
            "before compilation"
        ),
    }
    # Per open group: does its body (so far) contain a quantifier?
    group_body_has_quantifier: list[bool] = []

    def mark_current_group_quantifier() -> None:
        if group_body_has_quantifier:
            group_body_has_quantifier[-1] = True

    i = 0
    n = len(raw_pattern)
    while i < n:
        ch = raw_pattern[i]
        if ch == "\\":
            # Escaped metacharacter: one literal token; not a quantifier.
            i += 2
            continue
        if ch == "[":
            # Character class: one atom; skip to ``]`` respecting escapes.
            i += 1
            while i < n and raw_pattern[i] != "]":
                if raw_pattern[i] == "\\":
                    i += 1
                i += 1
            i += 1  # consume ']'
            continue
        if ch == "(":
            # Recognize a GROUP-PREFIX (``(?:``, ``(?i``/inline flags,
            # ``(?=``/``(?!``/``(?<=``/``(?<!`` lookaround, ``(?P<name>`` /
            # ``(?<name>`` named group, ``(?P=name)`` backref) and SKIP it so
            # its leading ``?`` / flags / ``:`` / ``=`` / ``!`` / ``<`` are
            # never counted as a quantifier in the group body (the Gate-2
            # mis-scan). A plain capturing ``(`` returns None and uses the
            # ordinary push path below.
            prefix = _group_open_prefix_end(raw_pattern, i)
            if prefix is not None:
                end, opens_body = prefix
                if opens_body:
                    # A group body follows the prefix; push a frame and let the
                    # matching ``)`` close it normally so a genuine nested
                    # quantifier in the BODY (``(?:a+)+``) is still detected.
                    group_body_has_quantifier.append(False)
                else:
                    # Self-terminating directive (``(?flags)`` / ``(?P=name)``):
                    # no quantifiable body and it consumes its own ``)``. Skip
                    # the whole construct without pushing a frame.
                    pass
                i = end
                continue
            group_body_has_quantifier.append(False)
            i += 1
            continue
        if ch == ")":
            inner_had_quantifier = (
                group_body_has_quantifier.pop()
                if group_body_has_quantifier
                else False
            )
            nxt = raw_pattern[i + 1] if i + 1 < n else None
            group_immediately_quantified = nxt in ("*", "+", "?", "{")
            group_is_quantified = group_immediately_quantified and (
                nxt != "{" or _interval_quantifier_end(raw_pattern, i + 1) is not None
            )
            if inner_had_quantifier and group_is_quantified:
                return redos
            # Propagate the "contains a quantifier" signal to the ENCLOSING
            # group when either the inner body had a quantifier OR the group
            # itself is quantified, so a deeper nesting (e.g. ``((a+))+``) is
            # still detected when an outer quantifier applies.
            if inner_had_quantifier or group_is_quantified:
                mark_current_group_quantifier()
            i += 1
            continue
        if ch in ("*", "+", "?"):
            mark_current_group_quantifier()
            i += 1
            continue
        if ch == "{":
            end = _interval_quantifier_end(raw_pattern, i)
            if end is not None:
                mark_current_group_quantifier()
                i = end  # consume through '}'
                continue
            # Literal '{': a normal token.
            i += 1
            continue
        # Any other literal/metacharacter is a plain token.
        i += 1
    return None


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

# Unicode general categories treated as "combining marks" for segment grouping
# in :func:`_fold_with_origin` (VAL-REDACT-007). MUST match the TypeScript SDK's
# ``foldWithOrigin`` predicate ``/\p{Mn}|\p{Mc}|\p{Me}/u`` exactly so the two
# engines group the identical set of code points and emit byte-equal output:
#   Mn  Mark, Nonspacing       (e.g. U+0308 COMBINING DIAERESIS, ccc 230)
#   Mc  Mark, Spacing Combining (e.g. U+0903 DEVANAGARI SIGN VISARGA, ccc 0)
#   Me  Mark, Enclosing        (e.g. U+20DD COMBINING ENCLOSING CIRCLE)
# This is deliberately NOT a canonical-combining-class test: U+0903 (Mc) has
# combining class 0, so ``unicodedata.combining(ch) != 0`` would exclude it
# while ``\p{Mc}`` (TS) includes it -- a Python<->TS parity divergence.
_COMBINING_MARK_CATEGORIES: Final[frozenset[str]] = frozenset({"Mn", "Mc", "Me"})


def _normalise_for_matching(value: str) -> str:
    """Return the NFKC + confusables-folded form of ``value``.

    The result is what the matcher regexes operate on. This is the
    DETECTION surface only; the engine never emits it directly. Output
    for any unmatched region is reconstructed from the ORIGINAL code
    points via :func:`_fold_with_origin` (VAL-REDACT-007), so legitimate
    non-secret Cyrillic/Greek text round-trips unchanged.
    """
    # NFKC handles compatibility decomposition (full-width digits,
    # ligatures, presentation forms). It does NOT decompose Cyrillic
    # or Greek confusables to their ASCII look-alikes; the explicit
    # table below covers those.
    nfkc = unicodedata.normalize("NFKC", value)
    if not _CONFUSABLES_MAP:
        return nfkc
    return "".join(_CONFUSABLES_MAP.get(ch, ch) for ch in nfkc)


def _fold_with_origin(value: str) -> tuple[str, list[int], list[int]]:
    """Return ``(folded, origin_starts, origin_ends)`` for ``value``.

    ``folded`` is the NFKC + confusables-folded DETECTION surface,
    byte-identical to :func:`_normalise_for_matching` for every input
    (verified by an assertion in the engine and by the parity corpus).

    ``origin_starts[i]`` / ``origin_ends[i]`` give the half-open slice
    ``value[origin_starts[i]:origin_ends[i]]`` of the ORIGINAL string
    that produced ``folded[i]``. This lets the engine map a matched span
    detected on ``folded`` back onto the original code points, then
    splice the placeholder over the original slice while every UNMATCHED
    original code point is reproduced verbatim (VAL-REDACT-007).

    NFKC is not per-character: a base character followed by combining
    marks may compose into a single (or differently shaped) sequence
    (e.g. ``"u" + U+0308`` -> ``U+00FC``). To keep a faithful
    original-offset mapping under that non-length-preserving transform,
    the input is split into segments of one base code point plus any
    trailing combining marks; each segment is NFKC-normalised and folded
    as a unit, and every folded code point it yields maps to the
    segment's FULL original span. A matched folded span therefore always
    maps to an original span that fully covers each contributing original
    code point -- no plaintext fragment of a matched secret can survive
    (the VAL-REDACT-002 / Bug 4 guarantee), while unmatched code points
    are reproduced from the original string.

    Combining-mark grouping rule (VAL-REDACT-007 parity): a trailing
    code point is absorbed into the current segment when its Unicode
    GENERAL CATEGORY is one of ``Mn`` (nonspacing mark), ``Mc`` (spacing
    combining mark), or ``Me`` (enclosing mark). This MUST match the
    TypeScript SDK's ``foldWithOrigin`` predicate
    (``/\\p{Mn}|\\p{Mc}|\\p{Me}/u`` in
    ``packages/sdk-typescript/src/redaction.ts``) EXACTLY so the two
    engines group the identical set of code points and emit byte-equal
    redaction output. A canonical-combining-class test
    (``unicodedata.combining(ch) != 0``) would NOT suffice: a class-0
    SPACING combining mark such as U+0903 (DEVANAGARI SIGN VISARGA,
    category ``Mc``, canonical combining class 0) has combining class 0,
    so ``combining`` would EXCLUDE it while ``\\p{Mc}`` (TS) INCLUDES it
    -- the segment boundaries would diverge and the two SDKs could emit
    different redaction output for the same input.
    """
    folded_parts: list[str] = []
    origin_starts: list[int] = []
    origin_ends: list[int] = []
    n = len(value)
    i = 0
    while i < n:
        seg_start = i
        i += 1
        # Absorb trailing combining marks into the same segment so the
        # base+marks NFKC composition is computed as a unit. The predicate
        # is Unicode MARK CATEGORY (Mn/Mc/Me), matching the TS SDK's
        # ``\p{Mn}|\p{Mc}|\p{Me}`` test byte-for-byte (VAL-REDACT-007). This
        # is NOT ``combining(ch) != 0``: a class-0 spacing mark like U+0903
        # (category Mc) must be grouped here too for Python<->TS parity.
        while i < n and unicodedata.category(value[i]) in _COMBINING_MARK_CATEGORIES:
            i += 1
        seg_end = i
        segment = value[seg_start:seg_end]
        nfkc_seg = unicodedata.normalize("NFKC", segment)
        for ch in nfkc_seg:
            folded_parts.append(_CONFUSABLES_MAP.get(ch, ch))
            origin_starts.append(seg_start)
            origin_ends.append(seg_end)
    return "".join(folded_parts), origin_starts, origin_ends


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
                # VAL-REDACT-006: reject catastrophic-backtracking (ReDoS)
                # structure BEFORE compiling, with the dedicated code
                # RELAY-SDK-017. The TS SDK surfaces the identical code +
                # reason for cross-language parity (Pattern B/C).
                redos = _check_regex_redos_safety(raw_pattern)
                if redos is not None:
                    raise RelayPolicyError(
                        f"regex matcher #{idx} pattern is invalid: "
                        f"{redos['error']}",
                        code=RELAY_SDK_REGEX_REDOS_CODE,
                        details={
                            "reason": redos["reason"],
                            "index": idx,
                            "pattern": raw_pattern,
                            "error": redos["error"],
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


# ---------------------------------------------------------------------------
# ECMA-262 / RFC 8785 JCS Number-to-String (capture-payload serialization)
# ---------------------------------------------------------------------------
# Keystone invariant #10 (cross-runtime byte equality): the redacted capture
# payload MUST serialise numeric leaves identically on the Python and the
# TypeScript SDKs. The TS canonicalizer emits numbers via ``String(value)``,
# which is the ECMA-262 7.1.12.1 Number-to-String form mandated by RFC 8785
# JCS. Python's ``json.dumps`` instead uses the float ``repr`` (``1.0``,
# ``1e+16``, ``1e+20``) which DIVERGES from JCS for any integral float or
# magnitude >= 1e16 -- breaking byte-equality (EMPIRICALLY CONFIRMED Gate-2
# REAL_DEFECT). We replicate the JCS number formatter here rather than import
# ``relay_contracts.canonical``: ``epochly-relay-contracts`` is NOT a declared
# dependency of this SDK package (see ``pyproject.toml``), so a hard import
# would be an inappropriate cross-package dependency. The replicated formatter
# is pinned byte-identical to ``relay_contracts.canonical._encode_number`` by
# ``test_redaction_parity.py::test_redact_number_leaf_byte_identical_to_contracts_encoder``
# across a value table, so the two implementations cannot drift.


def _es6_to_string_positive(n: float) -> str:
    """ECMA-262 7.1.12.1 Number.toString for a strictly positive finite
    double; mirrors JS ``String(n)`` byte-for-byte.

    Replicated from ``relay_contracts.canonical._es6_to_string_positive``
    (the authoritative implementation; the contracts package owns the JCS
    encoder for CEL evaluation). Kept byte-identical via the parity test.
    """
    s = repr(n)
    if "e" in s:
        mantissa, exp_str = s.split("e")
        exp = int(exp_str)
    else:
        mantissa, exp = s, 0
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
    else:
        int_part, frac_part = mantissa, ""
    raw_digits = int_part + frac_part
    stripped_lead = raw_digits.lstrip("0")
    leading_zero_count = len(raw_digits) - len(stripped_lead)
    if not stripped_lead:
        return "0"
    stripped = stripped_lead.rstrip("0")
    n_dec = len(int_part) - leading_zero_count + exp
    k = len(stripped)
    if k <= n_dec <= 21:
        return stripped + ("0" * (n_dec - k))
    if 0 < n_dec <= 21:
        return stripped[:n_dec] + "." + stripped[n_dec:]
    if -6 < n_dec <= 0:
        return "0." + ("0" * (-n_dec)) + stripped
    sign = "+" if n_dec - 1 >= 0 else "-"
    abs_exp = str(abs(n_dec - 1))
    if k == 1:
        return stripped + "e" + sign + abs_exp
    return stripped[0] + "." + stripped[1:] + "e" + sign + abs_exp


def _encode_jcs_number(n: int | float) -> str:
    """Return the ECMA-262/RFC-8785 JCS Number-to-String form of ``n``.

    Integers are emitted as their EXACT decimal (no float coercion, so
    values past 2**53 stay precise). Floats use the ECMA-262 ToString
    algorithm; ``-0.0`` collapses to ``"0"``. Non-finite floats
    (``NaN``/``Inf``) are forbidden by JCS and raise ``ValueError`` so the
    caller can fail closed identically to the TS SDK (RELAY-SDK-010).

    Byte-identical to ``relay_contracts.canonical._encode_number`` across
    the parity value table (pinned by ``test_redaction_parity.py``).
    """
    # ``bool`` subclasses ``int`` in Python; the caller dispatches bools to
    # the ``true``/``false`` branch before reaching here. Guard defensively.
    if isinstance(n, bool):  # pragma: no cover -- caller dispatches first
        raise TypeError("bool is not a number for JCS encoding")
    if isinstance(n, int):
        return str(n)
    if math.isnan(n) or math.isinf(n):
        raise ValueError(f"JCS cannot encode non-finite number: {n!r}")
    if n == 0.0:
        # Collapses -0.0 to "0" per ECMA-262 ToString.
        return "0"
    if n < 0:
        return "-" + _es6_to_string_positive(-n)
    return _es6_to_string_positive(n)


def _canonical_json_stringify(value: Any) -> str:
    """Serialise ``value`` to RFC 8785 JCS-compatible canonical JSON text.

    Mirrors the TypeScript ``canonicalJsonStringify``
    (``packages/sdk-typescript/src/redaction.ts``) token-for-token so the
    two SDKs emit byte-identical wire bytes for the same redacted payload
    (keystone invariant #10):

      * keys sorted (BMP ordering -- Python codepoint sort matches JS for the
        BMP keys the redaction surface produces; supplementary-plane keys are
        a documented non-BMP limitation upstream in the fold path);
      * compact separators (``,`` / ``:`` with no whitespace);
      * strings emitted via ``json.dumps(..., ensure_ascii=False)`` which is
        byte-identical to JS ``JSON.stringify`` for the supported inputs
        (both escape only ``"``/``\\``/U+0000..U+001F and emit other code
        points as literal UTF-8) -- this preserves the existing corpus bytes;
      * numbers emitted via :func:`_encode_jcs_number` (the JCS fix);
      * non-finite numbers raise ``ValueError`` (caller maps to RELAY-SDK-010,
        byte-identical fail-closed with the TS guard -- VAL-REDACT-005).
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return _encode_jcs_number(value)
    if isinstance(value, str):
        # ``ensure_ascii=False`` + the default escaper is byte-identical to
        # JS ``JSON.stringify`` for the supported inputs (verified above);
        # reusing it keeps the existing string-corpus bytes unchanged.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list | tuple):
        return "[" + ",".join(_canonical_json_stringify(v) for v in value) + "]"
    if isinstance(value, dict):
        parts: list[str] = []
        for k in sorted(value.keys(), key=str):
            v = value[k]
            key_text = json.dumps(k if isinstance(k, str) else str(k), ensure_ascii=False)
            parts.append(key_text + ":" + _canonical_json_stringify(v))
        return "{" + ",".join(parts) + "}"
    raise TypeError(
        f"canonical_json_stringify: unsupported type {type(value).__name__} "
        f"for value {value!r}"
    )


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
        folded DETECTION surface of the string so homograph-disguised
        secrets are still caught (VAL-W3-022). The EMITTED output is
        reconstructed from the ORIGINAL code points: only the original
        spans corresponding to matched folded spans are replaced by the
        placeholder, and every unmatched original code point is
        reproduced verbatim.

        Rationale (VAL-REDACT-007 LOW / correctness): the engine
        previously emitted the folded form itself -- even when NO matcher
        fired -- silently transliterating legitimate non-secret
        Cyrillic/Greek content (e.g. a Russian sentence) into ASCII
        look-alikes via ``_CONFUSABLES_MAP``. The fold must remain a
        DETECTION aid only; non-secret content round-trips unchanged.

        The non-length-preserving NFKC obstacle (Bug 4 P1: ``"u" +
        U+0308`` collapses to U+00FC) is handled by
        :func:`_fold_with_origin`, which maps each folded code point back
        to the half-open slice of the ORIGINAL string that produced it.
        A matched folded span maps to an original span that fully covers
        every contributing original code point, so no plaintext fragment
        of a matched secret can survive (the VAL-REDACT-002 guarantee)
        while unmatched original code points are emitted verbatim.
        """
        if not value:
            return value
        # VAL-REDACT-006: clamp an over-cap leaf BEFORE matching. A leaf longer
        # than MAX_REDACTION_LEAF_LENGTH code points is truncated to the cap;
        # the removed tail is replaced by REDACTION_TRUNCATION_MARKER, appended
        # AFTER matching so the marker is never scanned or redacted. This bounds
        # total matcher work (defense against ReDoS via huge inputs as well as
        # linear-but-slow patterns) and guarantees raw plaintext beyond the cap
        # never crosses the wire. Byte-identical to the TS SDK clamp (the TS
        # side clamps by UTF-16 code units; for ASCII/BMP leaves -- the parity
        # surface -- code points and code units coincide).
        if len(value) > MAX_REDACTION_LEAF_LENGTH:
            clamped = value[:MAX_REDACTION_LEAF_LENGTH]
            return (
                self._apply_matchers_to_clamped_string(clamped)
                + REDACTION_TRUNCATION_MARKER
            )
        return self._apply_matchers_to_clamped_string(value)

    def _apply_matchers_to_clamped_string(self, value: str) -> str:
        """Run matchers on an already length-clamped string (see
        :meth:`_apply_matchers_to_string`).

        Matching runs on the NFKC + confusables-folded DETECTION surface so
        homograph-disguised secrets are still caught (VAL-W3-022). The
        EMITTED output, however, is reconstructed from the ORIGINAL code
        points: only the original spans that correspond to matched folded
        spans are replaced by the placeholder; every unmatched original code
        point is reproduced verbatim. This fixes VAL-REDACT-007 (the engine
        previously emitted the folded string, silently transliterating
        legitimate non-secret Cyrillic/Greek content into ASCII look-alikes)
        WITHOUT weakening detection.

        :func:`_fold_with_origin` supplies, for each folded code point, the
        half-open slice of the ORIGINAL string that produced it. A matched
        folded span ``[fs, fe)`` therefore maps to the original span
        ``[origin_starts[fs], origin_ends[fe - 1])``. Because the origin map
        is built over base+combining-mark segments, this span fully covers
        every original code point that contributed to the match -- so no
        plaintext fragment of a matched secret can survive even when NFKC is
        not length-preserving (the VAL-REDACT-002 / Bug 4 guarantee).
        """
        folded, origin_starts, origin_ends = _fold_with_origin(value)
        # Detection surface MUST equal _normalise_for_matching exactly so the
        # match behavior (and Python<->TS parity) is unchanged by the origin
        # tracking. If a pathological input made the per-segment fold diverge
        # from the whole-string fold, fail closed by redacting the WHOLE leaf
        # rather than risk a wrong-offset splice (no plaintext leak, no silent
        # transliteration of a partial result).
        if folded != _normalise_for_matching(value):
            return self._policy.action_policy.redact_placeholder
        # Walk matchers, collecting (orig_start, orig_end, replacement) tuples
        # in ORIGINAL-string coordinates (mapped from folded match spans).
        spans: list[tuple[int, int, str]] = []
        for matcher in self._policy.matchers:
            if matcher.kind != "regex" or matcher.pattern is None:
                # json_pointer matchers are applied at the leaf level
                # in :meth:`_walk`, not at the string level.
                continue
            for m in matcher.pattern.finditer(folded):
                fstart, fend = m.span()
                matched_text = folded[fstart:fend]
                replacement = self._build_replacement(matcher, matched_text)
                # Map folded span -> original span. A zero-width folded match
                # (fend == fstart) maps to the zero-width original point at
                # that folded index's origin start.
                if fend > fstart:
                    ostart = origin_starts[fstart]
                    oend = origin_ends[fend - 1]
                else:
                    ostart = origin_starts[fstart] if fstart < len(origin_starts) else len(value)
                    oend = ostart
                spans.append((ostart, oend, replacement))
        if not spans:
            # No matcher fired: emit the ORIGINAL string verbatim (the fix --
            # the folded/transliterated form is never emitted). VAL-REDACT-007.
            return value
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
        # Merging now happens in ORIGINAL coordinates; the mapping above
        # guarantees each match span fully covers its contributing original
        # code points, so the union still contains no clear matched byte.
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
        # Splice replacements into the ORIGINAL string at the mapped offsets.
        # Unmatched runs are copied from the original verbatim, so non-secret
        # Cyrillic/Greek content round-trips unchanged (VAL-REDACT-007); matched
        # secret spans are replaced by the placeholder.
        out_parts: list[str] = []
        cursor = 0
        for start, end, repl in merged:
            out_parts.append(value[cursor:start])
            out_parts.append(repl)
            cursor = end
        out_parts.append(value[cursor:])
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
    # Serialise via the RFC 8785 JCS-compatible canonicalizer that mirrors the
    # TS ``canonicalJsonStringify`` (packages/sdk-typescript/src/redaction.ts)
    # token-for-token. Sorted keys + compact ``,``/``:`` separators match the
    # TS canonicalizer; string leaves use ``json.dumps(..., ensure_ascii=False)``
    # which is byte-identical to TS ``JSON.stringify`` (both emit raw UTF-8 for
    # BMP code points rather than ``\uXXXX`` escapes), preserving the
    # cross-language parity corpus (VAL-W4-020).
    #
    # Numeric leaves are emitted via the ECMA-262/RFC-8785 JCS Number-to-String
    # encoder (:func:`_encode_jcs_number`) instead of ``json.dumps``' float
    # repr. ``json.dumps`` emitted ``1.0`` / ``1e+16`` / ``1e+20`` for integral
    # floats and large magnitudes while TS ``String(value)`` (the JCS-correct
    # form) emitted ``1`` / ``10000000000000000`` / ``100000000000000000000`` --
    # breaking Py<->TS byte-equality (keystone invariant #10) for any captured
    # payload containing such a numeric leaf. Routing numbers through the JCS
    # encoder closes that divergence; integers stay exact decimals.
    #
    # VAL-REDACT-005 (MEDIUM / determinism; byte-identical fail-closed with the
    # TS ``canonicalJsonStringify`` non-finite guard): RFC 8785 JCS forbids
    # non-finite numbers (Infinity/-Infinity/NaN). :func:`_encode_jcs_number`
    # raises ``ValueError`` on a non-finite leaf (matching the old
    # ``allow_nan=False`` behaviour); we map it to a typed ``RelayPolicyError``
    # (code RELAY-SDK-010, ``reason="non_finite_number"``) so both runtimes
    # report the rejection identically and fail closed.
    try:
        return _canonical_json_stringify(redacted).encode("utf-8")
    except ValueError as exc:
        raise RelayPolicyError(
            "non-finite number (Infinity/-Infinity/NaN) is not permitted in a "
            "capture payload; RFC 8785 JCS forbids non-finite numbers",
            details={"reason": "non_finite_number"},
        ) from exc


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
