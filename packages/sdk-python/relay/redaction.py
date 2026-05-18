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

# The closed set of matcher kinds the SDK supports. Spec G.2 lists
# "regex" and "json_pointer"; v0.1 SDK implements "regex" end-to-end
# and accepts "json_pointer" entries only when ``paths`` is supplied
# (the engine walks JSON pointers in addition to regex matching on
# string leaves). An unknown ``kind`` fails closed at load.
_KNOWN_MATCHER_KINDS: Final[frozenset[str]] = frozenset({"regex", "json_pointer"})

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


@dataclass(frozen=True)
class _CompiledMatcher:
    """A single matcher prepared for engine consumption."""

    id: str
    kind: str
    action: str
    pattern: re.Pattern[str] | None
    json_paths: tuple[str, ...]


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
            if kind == "regex":
                raw_pattern = raw.get("pattern")
                if not isinstance(raw_pattern, str) or not raw_pattern:
                    raise RelayPolicyError(
                        f"regex matcher #{idx} MUST have a non-empty pattern",
                        details={"reason": "regex_pattern_missing", "index": idx},
                    )
                try:
                    pattern = re.compile(raw_pattern)
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
            compiled.append(
                _CompiledMatcher(
                    id=matcher_id,
                    kind=str(kind),
                    action=str(action),
                    pattern=pattern,
                    json_paths=json_paths,
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
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", errors="replace")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
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
        # Sort by start, then by end descending so longer overlapping
        # spans win; collapse overlaps deterministically.
        spans.sort(key=lambda t: (t[0], -t[1]))
        merged: list[tuple[int, int, str]] = []
        for start, end, repl in spans:
            if merged and start < merged[-1][1]:
                # Overlap: keep the earlier-starting span; skip this.
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
        """Return the first json_pointer matcher whose paths include ``pointer``.

        Matchers are evaluated in declaration order; the first hit
        wins. ``pointer`` is the empty string at the root and never
        matches a matcher (matchers declare leaf paths like
        ``/user/email``, not the document root).
        """
        if not pointer:
            return None
        for matcher in self._policy.matchers:
            if matcher.kind != "json_pointer":
                continue
            if pointer in matcher.json_paths:
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


__all__ = [
    "DEFAULT_APPLIES_TO_FIELDS",
    "RedactionEngine",
    "RedactionPolicy",
    "SaltProvider",
    "iter_known_applies_to_fields",
    "redact_capture_payload",
]
