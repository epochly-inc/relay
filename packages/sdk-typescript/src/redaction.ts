/**
 * SDK-side redaction at the trace boundary (W4.3).
 *
 * Per CLAUDE.md keystone invariant #7 (default-deny raw capture) and spec
 * G, the SDK redacts every trace-bound payload BEFORE the HTTP body crosses
 * localhost. Plaintext never leaves the calling process on the default
 * policy. The hosted Relay ingest workers re-validate as defense in depth,
 * but the SDK is the first line of defense; a forged or SDK-internal bug
 * that emits raw bytes is treated as a P0 product failure regardless of
 * which side catches it.
 *
 * This module is the TypeScript parity counterpart of
 * ``packages/sdk-python/relay/redaction.py``. For the same
 * ``(policy_version, salt_ref, input)`` triple the two engines emit
 * structurally-identical redacted objects: identical key ordering after
 * RFC 8785 JCS canonicalization, identical placeholder strings, identical
 * HMAC-SHA-256 hex digests. Cross-language parity is enforced by the
 * conformance corpus at ``tests/conformance/redaction/`` (VAL-W4-020).
 *
 * Module surface:
 *
 *   * :class:`RedactionPolicyImpl` parses and validates a v1 redaction
 *     policy dict (spec G.2). Invalid policies raise
 *     :class:`RelayRedactionPolicyError` synchronously at load time.
 *     ``raw_capture: true`` policies without both ``dpa_ref`` and
 *     ``approver_user_id`` raise
 *     :class:`RelayRedactionRawCaptureDeniedError` (CLAUDE.md banned
 *     pattern #11; spec G.1).
 *
 *   * :class:`RedactionEngine` walks a payload, applies matchers to every
 *     string in the configured ``applies_to_fields`` (and to every nested
 *     string in those subtrees), and emits a redacted copy. Strings are
 *     NFKC-normalised plus passed through a small confusables map for
 *     Cyrillic / Greek / Latin homoglyph variants of ASCII letters. Bytes
 *     and binary buffer fields are replaced by ``{_digest_sha256: "<hex>"}``
 *     references (VAL-W4-025); raw bytes never appear in the wire body.
 *
 *   * :func:`redactCapturePayload` is the canonical SDK entry point: it
 *     accepts a payload object, runs it through the engine, and returns
 *     the JSON-serialised bytes the SDK transport hands to the HTTP
 *     client.
 *
 * Determinism guarantees (spec G.3): two engines built from the same
 * policy version + salt provider produce byte-identical output for the
 * same input. Hash matchers use HMAC-SHA-256 keyed by the policy's
 * ``salt_ref`` (resolved by the caller-supplied ``saltProvider``); plain
 * SHA-256 is never used (VAL-W4-021).
 *
 * Unicode handling (BMP only): the matcher operates on the UTF-16 code
 * units of the NFKC + confusables-folded form. The engine assumes
 * length-preserving normalisation for the inputs it supports
 * (BMP code points): this is true for ASCII, Cyrillic A-Z look-alikes,
 * Greek capital look-alikes, full-width digits, and zero-width joiners
 * (which are stripped to zero width). Supplementary-plane code points
 * (emoji, CJK extension B+) are passed through unchanged but counted
 * verbatim. The Python and TS engines both make this restriction so
 * cross-language parity holds.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";

import {
  RelayRedactionPolicyError,
  RelayRedactionRawCaptureDeniedError,
  RELAY_SDK_POLICY_INVALID_CODE,
  RELAY_SDK_RAW_CAPTURE_DENIED_CODE,
  RELAY_SDK_REGEX_REDOS_CODE,
} from "./errors.js";

// The schema_version literal the policy MUST carry (spec G.2). Anything
// else is refused. NOTE: the W4.1 type alias :type:`RedactionPolicyShape`
// uses ``relay.redaction_policy.v1`` (the codegen-friendly form). The
// canonical wire schema (and the Python parity) is ``relay.redaction.v1``.
// Both are accepted here so the W4.1 type-alias stub continues to satisfy
// the schema check.
const POLICY_SCHEMA_VERSION_PRIMARY = "relay.redaction.v1";
const POLICY_SCHEMA_VERSION_ALIAS = "relay.redaction_policy.v1";

// Spec G.3 lists "regex", "json_pointer", and "json_path"; v0.1 SDK
// implements "regex" end-to-end, "json_pointer" (RFC 6901), and
// "json_path" (RFC 9535 subset: ``$``, ``$.key`` dotted child access,
// ``$.key[N]`` integer array index). An unknown ``kind`` fails closed
// at load. VAL-V3M5-018.
const KNOWN_MATCHER_KINDS: ReadonlySet<string> = new Set([
  "regex",
  "json_pointer",
  "json_path",
]);
const KNOWN_ACTIONS: ReadonlySet<string> = new Set(["redact", "hash", "drop"]);

// ---------------------------------------------------------------------------
// VAL-REDACT-006: regex ReDoS / complexity guard.
// ---------------------------------------------------------------------------
// Two deterministic layers protect the matcher loop from a policy-supplied
// regex causing catastrophic backtracking against a long leaf:
//
//   (1) A static load-time heuristic (``assertSafeRegexPattern``) rejects the
//       classic ReDoS shape -- a quantifier applied to a group that itself
//       ends in a quantifier (``(a+)+``, ``(a*)*``, ``(.*a){10,}``). Such a
//       pattern is never compiled or executed; ``loadRedactionPolicy`` raises
//       with code ``RELAY-SDK-017`` and ``details.reason == "redos_pattern"``.
//
//   (2) An input-length CLAMP: a leaf longer than ``MAX_REDACTION_LEAF_LENGTH``
//       UTF-16 code units is truncated to the cap before matching, with the
//       removed tail replaced by ``REDACTION_TRUNCATION_MARKER``. This bounds
//       total matcher work even for linear-but-slow patterns over very large
//       inputs (and keeps raw plaintext beyond the cap from ever crossing the
//       wire). Trace leaves are bounded in practice; payloads larger than the
//       cap are a denial-of-service vector, not a legitimate redaction target.
//
// BOTH constants and the marker are identical on the Python SDK
// (``relay.redaction.MAX_REDACTION_LEAF_LENGTH`` /
// ``REDACTION_TRUNCATION_MARKER``) so cross-language byte-equality holds for a
// clamped leaf (Pattern B/C parity).

/**
 * Maximum length (in UTF-16 code units) of a single string leaf the matcher
 * loop will scan. Leaves longer than this are clamped before matching. Must
 * stay byte-for-byte equal to the Python SDK constant.
 */
export const MAX_REDACTION_LEAF_LENGTH = 1_048_576; // 1 MiB of UTF-16 code units.

/**
 * Deterministic marker spliced in where a leaf was truncated at the cap.
 * ASCII per CLAUDE.md "ASCII-Safe Source"; identical to the Python marker.
 */
export const REDACTION_TRUNCATION_MARKER = "[relay:truncated]";

/**
 * Reject a policy-supplied regex whose structure is a catastrophic-backtracking
 * (ReDoS) risk, BEFORE it is compiled. The check is a deterministic static
 * scan of the raw pattern -- no compilation, no execution, no wall clock.
 *
 * Two dangerous classes are rejected:
 *   1. A quantifier applied to a GROUP whose body itself CONTAINS a quantifier
 *      (nested quantifiers), e.g. ``(a+)+``, ``(a*)*``, ``(a+)*``,
 *      ``(\\w+\\s?)*``, ``(.*a){2,}``.
 *   2. (REDACT cluster Bug B) A top-level alternation of OVERLAPPING branches
 *      under an UNBOUNDED quantifier (``*`` / ``+`` / ``{n,}``), e.g.
 *      ``(a|a)*``, ``(a|a)+``, ``(\\w|a)+``. The branches share a possible
 *      first character, so a run of that character has exponentially many
 *      branch partitions. A DISJOINT alternation (``(?:sk-|key_)+``: first
 *      chars ``s`` vs ``k``) is linear and accepted.
 *
 * A single quantifier (``a+``, ``[A-Za-z0-9]{20,}``), an optional inside a
 * group with no OUTER quantifier (``(?i)api[_-]?key``), or an alternation under
 * a BOUNDED quantifier (``(a|a){2,4}``) is linear and accepted.
 *
 * Returns ``null`` when the pattern is accepted, or a structured rejection
 * ``reason``/``error`` consumed by :func:`loadRedactionPolicy`. Mirrors
 * :func:`relay.redaction._check_regex_redos_safety` (Python) byte-for-byte so
 * the same policy is rejected (or accepted) identically on both runtimes.
 */
function checkRegexRedosSafety(
  rawPattern: string,
): { readonly reason: string; readonly error: string } | null {
  // Walk the pattern token by token. For each currently-open group, track
  // whether its body so far CONTAINS any quantifier. When a group closes, if
  // its body contains a quantifier AND the group itself is then immediately
  // quantified, that is the nested-quantifier (ReDoS) shape. A quantified
  // inner group also counts as a quantifier for its enclosing group.
  const REDOS = {
    reason: "redos_pattern",
    error:
      "regex pattern has nested quantifiers (a quantifier applied to a group " +
      "whose body itself contains a quantifier), e.g. '(a+)+'; this is a " +
      "catastrophic-backtracking (ReDoS) risk and is rejected before compilation",
  } as const;
  // REDACT cluster Bug B: an OVERLAPPING top-level alternation under an
  // UNBOUNDED quantifier ((a|a)* / (a|a)+ / (a|a){2,}) is also catastrophic
  // backtracking even though no inner quantifier is present.
  const REDOS_OVERLAP_ALTERNATION = {
    reason: "redos_pattern",
    error:
      "regex pattern has an overlapping alternation under an unbounded " +
      "quantifier (a group of overlapping branches followed by '*', '+', or " +
      "'{n,}'), e.g. '(a|a)*'; this is a catastrophic-backtracking (ReDoS) " +
      "risk and is rejected before compilation",
  } as const;
  // Per open group: does its body (so far) contain a quantifier?
  const groupBodyHasQuantifier: boolean[] = [];
  // Per open group: does its body (so far) contain a TOP-LEVEL `|`?
  const groupBodyHasAlternation: boolean[] = [];
  // Per open group: index of the first body character (just past the open
  // token). Used to slice the body for overlap analysis when the group closes.
  const groupBodyStart: number[] = [];

  const markCurrentGroupQuantifier = (): void => {
    if (groupBodyHasQuantifier.length > 0) {
      groupBodyHasQuantifier[groupBodyHasQuantifier.length - 1] = true;
    }
  };

  let i = 0;
  const n = rawPattern.length;
  while (i < n) {
    const ch = rawPattern[i];
    if (ch === "\\") {
      // Escaped metacharacter: one literal token; not a quantifier.
      i += 2;
      continue;
    }
    if (ch === "[") {
      // Character class: one atom; skip to ``]`` respecting escapes. A class is
      // not itself a quantifier (any quantifier AFTER it is handled below).
      i += 1;
      while (i < n && rawPattern[i] !== "]") {
        if (rawPattern[i] === "\\") i += 1;
        i += 1;
      }
      i += 1; // consume ']'
      continue;
    }
    if (ch === "(") {
      // Recognize a GROUP-PREFIX ((?:, (?i / inline flags, (?=/(?!/(?<=/(?<!
      // lookaround, (?P<name> / (?<name> named group, (?P=name) backref) and
      // SKIP it so its leading `?` / flags / `:` / `=` / `!` / `<` are never
      // counted as a quantifier in the group body (the Gate-2 mis-scan). A
      // plain capturing `(` returns null and uses the ordinary push path.
      const prefix = groupOpenPrefixEnd(rawPattern, i);
      if (prefix !== null) {
        if (prefix.opensBody) {
          // A group body follows the prefix; push a frame and let the matching
          // `)` close it normally so a genuine nested quantifier in the BODY
          // ((?:a+)+) is still detected. `prefix.end` is the first body char.
          groupBodyHasQuantifier.push(false);
          groupBodyHasAlternation.push(false);
          groupBodyStart.push(prefix.end);
        }
        // Else: self-terminating directive ((?flags) / (?P=name)) -- no
        // quantifiable body and it consumes its own `)`; push NO frame.
        i = prefix.end;
        continue;
      }
      groupBodyHasQuantifier.push(false);
      groupBodyHasAlternation.push(false);
      groupBodyStart.push(i + 1);
      i += 1;
      continue;
    }
    if (ch === "|") {
      // A TOP-LEVEL `|` for the innermost open group (the alternation
      // separator). A `|` at the very top of the pattern (no open group) is not
      // a quantifiable-group body, so it is ignored here.
      if (groupBodyHasAlternation.length > 0) {
        groupBodyHasAlternation[groupBodyHasAlternation.length - 1] = true;
      }
      i += 1;
      continue;
    }
    if (ch === ")") {
      const innerHadQuantifier =
        groupBodyHasQuantifier.length > 0
          ? (groupBodyHasQuantifier.pop() ?? false)
          : false;
      const innerHadAlternation =
        groupBodyHasAlternation.length > 0
          ? (groupBodyHasAlternation.pop() ?? false)
          : false;
      const bodyStart =
        groupBodyStart.length > 0 ? (groupBodyStart.pop() ?? i) : i;
      const next = i + 1 < n ? rawPattern[i + 1] : undefined;
      const groupImmediatelyQuantified =
        next === "*" || next === "+" || next === "?" || next === "{";
      const groupIsQuantified =
        groupImmediatelyQuantified &&
        (next !== "{" || isIntervalQuantifierAt(rawPattern, i + 1));
      // An UNBOUNDED quantifier is `*`, `+`, or an open-ended interval `{n,}`.
      // A bounded quantifier (`?` or `{n,m}`) caps the repetition count, so it
      // cannot drive exponential backtracking.
      const groupIsUnboundedQuantified =
        groupIsQuantified &&
        (next === "*" ||
          next === "+" ||
          (next === "{" && intervalQuantifierIsUnbounded(rawPattern, i + 1)));
      if (innerHadQuantifier && groupIsQuantified) {
        return REDOS;
      }
      // REDACT cluster Bug B: a top-level alternation of OVERLAPPING branches
      // under an UNBOUNDED quantifier is catastrophic even with no inner
      // quantifier. Slice the just-closed body and test overlap.
      if (
        innerHadAlternation &&
        groupIsUnboundedQuantified &&
        alternationOverlaps(rawPattern.slice(bodyStart, i))
      ) {
        return REDOS_OVERLAP_ALTERNATION;
      }
      // The closed group is part of its ENCLOSING group's body. Propagate the
      // "contains a quantifier" signal upward when EITHER the inner body had a
      // quantifier OR the group itself is quantified -- so a deeper nesting
      // (e.g. ``((a+))+``) is still detected when an outer quantifier applies.
      if (innerHadQuantifier || groupIsQuantified) {
        markCurrentGroupQuantifier();
      }
      i += 1;
      continue;
    }
    if (ch === "*" || ch === "+" || ch === "?") {
      markCurrentGroupQuantifier();
      i += 1;
      continue;
    }
    if (ch === "{") {
      const end = intervalQuantifierEnd(rawPattern, i);
      if (end !== null) {
        markCurrentGroupQuantifier();
        i = end; // consume through '}'
        continue;
      }
      // Literal '{': a normal token.
      i += 1;
      continue;
    }
    // Any other literal/metacharacter is a plain token.
    i += 1;
  }
  return null;
}

/**
 * If a well-formed ``{n}`` / ``{n,}`` / ``{n,m}`` interval quantifier starts at
 * ``rawPattern[start]`` (which must be ``{``), return the index just past the
 * closing ``}``; otherwise ``null``. Shared by :func:`checkRegexRedosSafety`.
 */
function intervalQuantifierEnd(rawPattern: string, start: number): number | null {
  if (rawPattern[start] !== "{") return null;
  let j = start + 1;
  let body = "";
  const n = rawPattern.length;
  while (j < n && rawPattern[j] !== "}") {
    body += rawPattern[j];
    j += 1;
  }
  if (j < n && /^[0-9]+(,[0-9]*)?$/.test(body)) {
    return j + 1;
  }
  return null;
}

/** True iff a well-formed interval quantifier begins at ``rawPattern[start]``. */
function isIntervalQuantifierAt(rawPattern: string, start: number): boolean {
  return intervalQuantifierEnd(rawPattern, start) !== null;
}

/**
 * True iff a well-formed interval quantifier at ``start`` is OPEN-ENDED
 * (``{n,}``) -- it permits an unbounded number of repetitions. A closed
 * interval ``{n}`` / ``{n,m}`` is bounded. ``rawPattern[start]`` MUST be ``{``.
 * Mirrors :func:`relay.redaction._interval_quantifier_is_unbounded` (Python).
 */
function intervalQuantifierIsUnbounded(rawPattern: string, start: number): boolean {
  if (intervalQuantifierEnd(rawPattern, start) === null) return false;
  let j = start + 1;
  let body = "";
  const n = rawPattern.length;
  while (j < n && rawPattern[j] !== "}") {
    body += rawPattern[j];
    j += 1;
  }
  // ``{n,}`` is open-ended: a comma present AND nothing after it.
  return body.includes(",") && body.endsWith(",");
}

/**
 * Class-style escapes ``\\w \\W \\d \\D \\s \\S`` and zero-width escapes
 * ``\\b \\B \\A \\Z`` that match a SET of characters (or no character) and are
 * therefore BROAD/NULLABLE first tokens for alternation-overlap analysis. MUST
 * match the Python set in :func:`relay.redaction._branch_first_chars`.
 */
const BROAD_ESCAPE_CHARS: ReadonlySet<string> = new Set([
  "w",
  "W",
  "d",
  "D",
  "s",
  "S",
  "b",
  "B",
  "A",
  "Z",
]);

/**
 * Return the set of literal characters a top-level alternation BRANCH can begin
 * with, or ``null`` when the branch's first matchable token is BROAD or the
 * branch is NULLABLE (so it overlaps any other branch). Used only by
 * :func:`alternationOverlaps`.
 *
 * Deterministic, conservative (fail-closed): a leading literal yields that
 * char; a class-style escape (``\\w``...), ``.``, ``[...]``, group ``(``,
 * anchor (``^``/``$``), a stray leading quantifier, or an empty branch is
 * BROAD/NULLABLE -> ``null`` (forces overlap -> REJECT, the safe direction).
 * Mirrors :func:`relay.redaction._branch_first_chars` (Python).
 */
function branchFirstChars(branch: string): ReadonlySet<string> | null {
  if (branch === "") {
    // Empty branch (e.g. ``(a|)*``): matches the empty string -> nullable.
    return null;
  }
  const ch = branch[0] as string;
  if (ch === "\\") {
    if (branch.length < 2) {
      // Trailing backslash: malformed; treat as broad (fail-closed).
      return null;
    }
    const esc = branch[1] as string;
    if (BROAD_ESCAPE_CHARS.has(esc)) {
      // Class-style escape matches a SET of characters -> broad.
      return null;
    }
    // Ordinary escaped literal (``\\.``, ``\\+``, ``\\\\`` ...): the literal char.
    return new Set([esc]);
  }
  if (ch === "." || ch === "[" || ch === "(") {
    // Wildcard, character class, or a nested group: a broad first token.
    return null;
  }
  if (ch === "^" || ch === "$") {
    // Zero-width anchor leads the branch: treat as nullable (broad).
    return null;
  }
  if (ch === "*" || ch === "+" || ch === "?" || ch === "{") {
    // A quantifier with no preceding atom is malformed; fail-closed broad.
    return null;
  }
  // Plain literal first character.
  return new Set([ch]);
}

/**
 * Split a group BODY on its TOP-LEVEL ``|`` alternation separators. Nested
 * groups ``(...)``, character classes ``[...]``, and escapes ``\\x`` are
 * skipped so a ``|`` inside them is NOT a top-level separator. Returns the
 * branch substrings (a single-element array when there is no top-level ``|``).
 * Mirrors :func:`relay.redaction._split_top_level_alternation` (Python).
 */
function splitTopLevelAlternation(body: string): string[] {
  const branches: string[] = [];
  let depth = 0;
  let i = 0;
  const n = body.length;
  let start = 0;
  while (i < n) {
    const c = body[i];
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "[") {
      i += 1;
      while (i < n && body[i] !== "]") {
        if (body[i] === "\\") i += 1;
        i += 1;
      }
      i += 1; // consume ']'
      continue;
    }
    if (c === "(") {
      depth += 1;
      i += 1;
      continue;
    }
    if (c === ")") {
      if (depth > 0) depth -= 1;
      i += 1;
      continue;
    }
    if (c === "|" && depth === 0) {
      branches.push(body.slice(start, i));
      start = i + 1;
      i += 1;
      continue;
    }
    i += 1;
  }
  branches.push(body.slice(start));
  return branches;
}

/**
 * Return ``true`` iff a group BODY is a top-level alternation whose branches can
 * match OVERLAPPING input -- the catastrophic-backtracking shape when the group
 * carries an UNBOUNDED quantifier (REDACT cluster Bug B). Two branches overlap
 * when they share a possible first character, or when any branch is BROAD /
 * NULLABLE. A body with no top-level ``|`` (one branch) never overlaps; a
 * DISJOINT alternation (``sk-`` vs ``key_``) has empty intersections.
 * Mirrors :func:`relay.redaction._alternation_overlaps` (Python).
 */
function alternationOverlaps(body: string): boolean {
  const branches = splitTopLevelAlternation(body);
  if (branches.length < 2) return false;
  const seen = new Set<string>();
  for (const branch of branches) {
    const first = branchFirstChars(branch);
    if (first === null) {
      // A broad / nullable branch overlaps with every other branch.
      return true;
    }
    for (const c of first) {
      if (seen.has(c)) return true;
    }
    for (const c of first) seen.add(c);
  }
  return false;
}

/**
 * Inline-flag letters permitted inside a ``(?flags)`` / ``(?flags:...)`` group
 * prefix. A superset of the SDK's supported subset on purpose: the ReDoS
 * scanner only needs to STEP OVER the prefix without mis-reading its ``?`` as a
 * quantifier; whether the flag is ultimately supported is decided by
 * :func:`compileRegexPattern`. MUST match the Python ``_INLINE_FLAG_CHARS`` set.
 */
const INLINE_FLAG_CHARS: ReadonlySet<string> = new Set([
  "i",
  "m",
  "s",
  "x",
  "a",
  "u",
  "L",
]);

/**
 * Classify a group-open token at ``rawPattern[i]`` (which MUST be ``(``).
 *
 * Recognizes the regex GROUP-PREFIX syntaxes whose leading ``?`` / flags /
 * ``:`` / ``=`` / ``!`` / ``<`` are NOT quantifiers and must not be counted as
 * such by the ReDoS scanner:
 *
 *   * ``(?:``                 non-capturing group
 *   * ``(?i`` ``(?s`` ``(?m`` ``(?x`` ``(?a`` ``(?u`` and combinations, either
 *     bare ``(?flags)`` (a leading inline-flag directive with NO body) or
 *     scoped ``(?flags:...)`` (flags + a group body)
 *   * ``(?=`` ``(?!``         lookahead / negative lookahead
 *   * ``(?<=`` ``(?<!``       lookbehind / negative lookbehind
 *   * ``(?P<name>`` ``(?<name>``   named group
 *   * ``(?P=name)``          named backreference
 *
 * Returns ``null`` when the token is a PLAIN capturing group ``(`` (no prefix)
 * -- the caller handles it with the ordinary push/scan path.
 *
 * Otherwise returns ``{ end, opensBody }``:
 *
 *   * ``end`` is the index just past the recognized prefix (or, for a
 *     self-terminating construct, just past its own ``)``).
 *   * ``opensBody`` is ``true`` when a group BODY follows the prefix and the
 *     caller must push a group frame and let the matching ``)`` close it
 *     (``(?:``, ``(?=``, ``(?!``, ``(?<=``, ``(?<!``, ``(?flags:``, and the
 *     named-group forms ``(?P<name>`` / ``(?<name>``). It is ``false`` for the
 *     self-terminating constructs that consume their own ``)`` and contribute
 *     no quantifiable body (``(?flags)`` bare inline-flag directive,
 *     ``(?P=name)`` named backreference); the caller advances to ``end`` and
 *     pushes NO frame.
 *
 * Mirrors :func:`relay.redaction._group_open_prefix_end` (Python) byte-for-byte
 * so both engines skip the identical prefix set.
 */
function groupOpenPrefixEnd(
  rawPattern: string,
  i: number,
): { readonly end: number; readonly opensBody: boolean } | null {
  const n = rawPattern.length;
  // A plain capturing group: not a prefixed group. Also covers a trailing bare
  // ``(`` (malformed) -- treated as a plain open by the caller.
  if (i + 1 >= n || rawPattern[i + 1] !== "?") {
    return null;
  }
  let j = i + 2; // index just past ``(?``
  if (j >= n) {
    // ``(?`` at end of pattern: malformed; let the caller treat the ``(`` as a
    // plain open so the engine compile-error path surfaces it.
    return null;
  }
  // ``j < n`` is guaranteed above; the cast pins the type for the Set lookup
  // below under ``noUncheckedIndexedAccess`` (the equality compares are fine
  // either way). Mirrors the existing ``as string`` style in this module.
  const c = rawPattern[j] as string;
  if (c === ":") {
    // Non-capturing group ``(?:...)``: body follows.
    return { end: j + 1, opensBody: true };
  }
  if (c === "=" || c === "!") {
    // Lookahead ``(?=...)`` / ``(?!...)``: body follows.
    return { end: j + 1, opensBody: true };
  }
  if (c === "<") {
    // ``(?<=`` / ``(?<!`` lookbehind, or ``(?<name>`` named group.
    if (j + 1 < n && (rawPattern[j + 1] === "=" || rawPattern[j + 1] === "!")) {
      return { end: j + 2, opensBody: true };
    }
    // Named group ``(?<name>``: consume through the closing ``>``; body follows.
    let k = j + 1;
    while (k < n && rawPattern[k] !== ">") k += 1;
    if (k < n) {
      // consumed ``>``
      return { end: k + 1, opensBody: true };
    }
    return null; // malformed; let the caller treat ``(`` as a plain open
  }
  if (c === "P") {
    // Python named group ``(?P<name>...)`` (body) or named backreference
    // ``(?P=name)`` (self-terminating). Note: these are rejected for the
    // cross-language dialect by ``compileRegexPattern``; the ReDoS scanner must
    // still parse the prefix so the rejection reason is ``named_group_unsupported``,
    // never a spurious ``redos_pattern``.
    if (j + 1 < n && rawPattern[j + 1] === "<") {
      let k = j + 2;
      while (k < n && rawPattern[k] !== ">") k += 1;
      if (k < n) {
        // consumed ``>``
        return { end: k + 1, opensBody: true };
      }
      return null;
    }
    if (j + 1 < n && rawPattern[j + 1] === "=") {
      // Named backreference ``(?P=name)``: consume through ``)``; no body.
      let k = j + 2;
      while (k < n && rawPattern[k] !== ")") k += 1;
      if (k < n) {
        // consumed ``)``
        return { end: k + 1, opensBody: false };
      }
      return null;
    }
    return null;
  }
  if (INLINE_FLAG_CHARS.has(c)) {
    // Inline-flag group: ``(?flags)`` (bare directive) or ``(?flags:...)``
    // (scoped, body follows). Consume the flag run first.
    let k = j;
    while (k < n && INLINE_FLAG_CHARS.has(rawPattern[k] as string)) k += 1;
    if (k < n && rawPattern[k] === ":") {
      // Scoped flags ``(?flags:...)``: body follows the colon.
      return { end: k + 1, opensBody: true };
    }
    if (k < n && rawPattern[k] === ")") {
      // Bare inline-flag directive ``(?flags)``: self-terminating, no
      // quantifiable body. Consume through its own ``)``.
      return { end: k + 1, opensBody: false };
    }
    return null; // malformed flag group; let the caller treat as a plain open
  }
  // ``(?`` followed by something we do not recognize (e.g. ``(?#comment)`` or
  // an atomic group ``(?>...)``): do not special-case it here. Return null so
  // the caller treats ``(`` as a plain open; the body scan and the final
  // compile step decide its fate. Returning null never UNDER-detects: an
  // unrecognized prefix is scanned as an ordinary group body, so a genuine
  // nested quantifier inside it is still caught.
  return null;
}

/**
 * Default ``applies_to_fields`` (spec G.2). Matches Python
 * :data:`relay.redaction.DEFAULT_APPLIES_TO_FIELDS`.
 */
export const DEFAULT_APPLIES_TO_FIELDS: ReadonlyArray<string> = Object.freeze([
  "model_call.input",
  "model_call.output",
  "tool_call.args",
  "tool_call.result",
  "retrieval.documents",
]);

// ---------------------------------------------------------------------------
// Unicode confusables: a small explicit table.
// ---------------------------------------------------------------------------
// Per eng plan CQ2, NFKC alone is insufficient because canonical Cyrillic
// glyphs (e.g. U+0410 CYRILLIC CAPITAL LETTER A) do NOT decompose to ASCII
// under NFKC. We supplement NFKC with an explicit confusables map covering
// the highest-impact homoglyphs of ASCII letters: full uppercase + lowercase
// A-Z. The map is intentionally bounded -- we are not vendoring the full
// Unicode confusables table; the SDK ships a deterministic, ASCII-only
// confusables set the test corpus pins. Strings in the SDK source are ASCII
// per CLAUDE.md; the table is built from explicit code points.
function buildConfusablesMap(): Map<number, string> {
  const table = new Map<number, string>();
  // Cyrillic uppercase confusables that visually match ASCII A-Z.
  const cyrillicUpper: Array<[string, number]> = [
    ["A", 0x0410], // CYRILLIC CAPITAL LETTER A
    ["B", 0x0412], // CYRILLIC CAPITAL LETTER VE
    ["C", 0x0421], // CYRILLIC CAPITAL LETTER ES
    ["E", 0x0415], // CYRILLIC CAPITAL LETTER IE
    ["H", 0x041d], // CYRILLIC CAPITAL LETTER EN
    ["I", 0x0406], // CYRILLIC CAPITAL LETTER I (Ukrainian)
    ["J", 0x0408], // CYRILLIC CAPITAL LETTER JE
    ["K", 0x041a], // CYRILLIC CAPITAL LETTER KA
    ["M", 0x041c], // CYRILLIC CAPITAL LETTER EM
    ["N", 0x0418], // CYRILLIC CAPITAL LETTER I
    ["O", 0x041e], // CYRILLIC CAPITAL LETTER O
    ["P", 0x0420], // CYRILLIC CAPITAL LETTER ER
    ["S", 0x0405], // CYRILLIC CAPITAL LETTER DZE
    ["T", 0x0422], // CYRILLIC CAPITAL LETTER TE
    ["X", 0x0425], // CYRILLIC CAPITAL LETTER HA
    ["Y", 0x0423], // CYRILLIC CAPITAL LETTER U
  ];
  for (const [ascii, codepoint] of cyrillicUpper) {
    table.set(codepoint, ascii);
  }
  // Cyrillic lowercase confusables.
  const cyrillicLower: Array<[string, number]> = [
    ["a", 0x0430],
    ["c", 0x0441],
    ["e", 0x0435],
    ["o", 0x043e],
    ["p", 0x0440],
    ["x", 0x0445],
    ["y", 0x0443],
  ];
  for (const [ascii, codepoint] of cyrillicLower) {
    table.set(codepoint, ascii);
  }
  // Greek capital letters that visually match ASCII.
  const greekUpper: Array<[string, number]> = [
    ["A", 0x0391],
    ["B", 0x0392],
    ["E", 0x0395],
    ["H", 0x0397],
    ["I", 0x0399],
    ["K", 0x039a],
    ["M", 0x039c],
    ["N", 0x039d],
    ["O", 0x039f],
    ["P", 0x03a1],
    ["T", 0x03a4],
    ["X", 0x03a7],
    ["Y", 0x03a5],
    ["Z", 0x0396],
  ];
  for (const [ascii, codepoint] of greekUpper) {
    table.set(codepoint, ascii);
  }
  return table;
}

const CONFUSABLES_MAP = buildConfusablesMap();

/**
 * Return the NFKC + confusables-folded form of ``value``.
 *
 * The result is the DETECTION surface only; the engine never emits it
 * directly. Output for any unmatched region is reconstructed from the
 * ORIGINAL code points via :func:`foldWithOrigin` (VAL-REDACT-007), so
 * legitimate non-secret Cyrillic/Greek text round-trips unchanged.
 *
 * NFKC handles compatibility decomposition (full-width digits, ligatures,
 * presentation forms). It does NOT decompose Cyrillic or Greek confusables
 * to their ASCII look-alikes; the explicit table above covers those.
 */
function normaliseForMatching(value: string): string {
  const nfkc = value.normalize("NFKC");
  if (CONFUSABLES_MAP.size === 0) return nfkc;
  // Walk code units; substitute confusables one-for-one. All entries in
  // the map are BMP code points so each matches exactly one UTF-16 code
  // unit; replacement is also a single ASCII code unit. Length-preserving.
  let result = "";
  for (let i = 0; i < nfkc.length; i++) {
    const code = nfkc.charCodeAt(i);
    const replacement = CONFUSABLES_MAP.get(code);
    result += replacement ?? nfkc.charAt(i);
  }
  return result;
}

// A combining mark (Unicode general categories Mn/Mc/Me). NFKC may compose
// a base code point + trailing combining marks into a single (or differently
// shaped) code point, so a faithful original-offset map must group them.
const COMBINING_MARK_RE = /\p{Mn}|\p{Mc}|\p{Me}/u;

/**
 * Return ``{ folded, originStarts, originEnds }`` for ``value``.
 *
 * ``folded`` is the NFKC + confusables-folded DETECTION surface,
 * byte-identical to :func:`normaliseForMatching` for every input (verified
 * by an assertion in the engine and by the parity corpus).
 *
 * ``originStarts[i]`` / ``originEnds[i]`` give the half-open UTF-16
 * code-unit slice ``value.slice(originStarts[i], originEnds[i])`` of the
 * ORIGINAL string that produced ``folded[i]``. This lets the engine map a
 * matched span detected on ``folded`` back onto the original code units,
 * then splice the placeholder over the original slice while every UNMATCHED
 * original code unit is reproduced verbatim (VAL-REDACT-007).
 *
 * NFKC is not per-character: a base code point followed by combining marks
 * may compose (e.g. ``"u" + U+0308`` -> ``U+00FC``). The input is therefore
 * split into segments of one base code point plus any trailing combining
 * marks; each segment is NFKC-normalised and folded as a unit, and every
 * folded code unit it yields maps to the segment's FULL original span. A
 * matched folded span thus maps to an original span that fully covers each
 * contributing original code point -- no plaintext fragment of a matched
 * secret can survive (the VAL-REDACT-004 / Bug 4 guarantee), while unmatched
 * code points are reproduced from the original string. Mirrors the Python
 * ``_fold_with_origin``.
 */
function foldWithOrigin(value: string): {
  folded: string;
  originStarts: number[];
  originEnds: number[];
} {
  let folded = "";
  const originStarts: number[] = [];
  const originEnds: number[] = [];
  const n = value.length;
  let i = 0;
  while (i < n) {
    const segStart = i;
    // Advance one code point (surrogate pair counts as one base unit).
    const cp = value.codePointAt(i);
    i += cp !== undefined && cp > 0xffff ? 2 : 1;
    // Absorb trailing combining marks into the same segment.
    while (i < n) {
      const markCp = value.codePointAt(i);
      if (markCp === undefined) break;
      const mark = String.fromCodePoint(markCp);
      if (!COMBINING_MARK_RE.test(mark)) break;
      i += markCp > 0xffff ? 2 : 1;
    }
    const segEnd = i;
    const segment = value.slice(segStart, segEnd);
    const nfkcSeg = segment.normalize("NFKC");
    // Fold per UTF-16 code unit; map every produced unit to the segment span.
    for (let k = 0; k < nfkcSeg.length; k++) {
      const code = nfkcSeg.charCodeAt(k);
      folded += CONFUSABLES_MAP.get(code) ?? nfkcSeg.charAt(k);
      originStarts.push(segStart);
      originEnds.push(segEnd);
    }
  }
  return { folded, originStarts, originEnds };
}

// ---------------------------------------------------------------------------
// Regex dialect bridge (VAL-REDACT-003)
// ---------------------------------------------------------------------------

/**
 * Result of compiling a policy regex matcher. Either a ready ``RegExp`` or a
 * structured rejection ``reason`` consumed by :func:`loadRedactionPolicy`.
 */
type RegexCompileResult =
  | { readonly ok: true; readonly pattern: RegExp }
  | { readonly ok: false; readonly reason: string; readonly error: string };

// Supported leading inline-flag prefix, mirroring the Python ``re`` subset
// we pin: a single ``(?flags)`` group at the very START of the expression,
// with flags drawn from {i, s, m}. Python (>=3.11) requires global flags to
// appear at the start of the pattern; we enforce the same so the two SDKs
// accept the identical dialect.
const INLINE_FLAG_PREFIX_RE = /^\(\?([a-zA-Z]+)\)/;
const SUPPORTED_INLINE_FLAGS: ReadonlyMap<string, string> = new Map([
  ["i", "i"], // IGNORECASE
  ["s", "s"], // DOTALL  -> JS 's' (dotAll)
  ["m", "m"], // MULTILINE
]);

/**
 * Compile a policy-authored regex pattern into a JavaScript ``RegExp`` whose
 * behaviour matches the Python SDK's ``re.compile(raw_pattern)`` for the
 * pinned, cross-language dialect.
 *
 * The Python SDK compiles matcher patterns with ``re.compile`` and the
 * default policy authors leading inline flags (e.g. ``(?i)password``).
 * JavaScript ``RegExp`` does not understand Python's leading inline scoped
 * flags and never sets the case-insensitive flag, so a raw
 * ``new RegExp(rawPattern, "g")`` THREW on every default-policy regex while
 * Python loaded and matched (VAL-REDACT-003). This bridge:
 *
 *   - Detects a leading ``(?flags)`` prefix (flags subset of {i, s, m}),
 *     maps it to the JS flags string (always including ``g`` for the
 *     finditer-style scan), and strips the prefix from the pattern body.
 *   - Rejects Python named groups ``(?P<name>...)`` and named backreferences
 *     ``(?P=name)`` with ``reason: "named_group_unsupported"`` so BOTH SDKs
 *     reject them identically (Python's ``re`` would otherwise accept them).
 *   - Rejects a mid-pattern global-flag group (``foo(?i)bar``) with
 *     ``reason: "inline_flags_not_at_start"``, matching Python's "global
 *     flags not at the start of the expression" error.
 *   - Defers every other syntax decision to the JS engine (``bad_regex``).
 *
 * Mirrors :func:`relay.redaction._compile_regex_pattern` (Python).
 */
function compileRegexPattern(rawPattern: string): RegexCompileResult {
  // Reject Python named-group syntax up front and consistently with the
  // Python SDK. JS supports ``(?<name>...)`` but NOT Python's ``(?P<...>)``
  // form; we reject the Python form on both runtimes so a policy that uses
  // it fails the same way everywhere rather than silently matching on one
  // runtime and throwing on the other.
  if (/\(\?P[<=]/.test(rawPattern)) {
    return {
      ok: false,
      reason: "named_group_unsupported",
      error:
        "Python named groups '(?P<name>...)' / '(?P=name)' are not part of " +
        "the supported cross-language regex dialect",
    };
  }

  // VAL-REDACT-006: reject catastrophic-backtracking (ReDoS) structure BEFORE
  // compiling. Runs on the RAW pattern so both SDKs analyze the identical
  // string (Python ``re`` keeps the leading inline-flag prefix; analyzing the
  // raw form keeps the heuristic byte-identical across runtimes).
  const redos = checkRegexRedosSafety(rawPattern);
  if (redos !== null) {
    return { ok: false, reason: redos.reason, error: redos.error };
  }

  let body = rawPattern;
  let jsFlags = "g";
  const prefixMatch = INLINE_FLAG_PREFIX_RE.exec(rawPattern);
  if (prefixMatch !== null) {
    const declared = prefixMatch[1] ?? "";
    const seen = new Set<string>();
    for (const ch of declared) {
      const mapped = SUPPORTED_INLINE_FLAGS.get(ch);
      if (mapped === undefined) {
        return {
          ok: false,
          reason: "unsupported_inline_flag",
          error:
            `unsupported inline regex flag '(?${declared})': only ` +
            "(?i), (?s), (?m) and combinations are supported",
        };
      }
      seen.add(mapped);
    }
    for (const f of seen) jsFlags += f;
    body = rawPattern.slice(prefixMatch[0].length);
  }

  // A global-flag group anywhere other than the start is a Python error
  // ("global flags not at the start of the expression"). Reject the same
  // way so the dialect is pinned identically on both SDKs.
  if (/\(\?[ismLuxa]+\)/.test(body)) {
    return {
      ok: false,
      reason: "inline_flags_not_at_start",
      error: "inline global flags must appear at the start of the expression",
    };
  }

  try {
    return { ok: true, pattern: new RegExp(body, jsFlags) };
  } catch (exc) {
    return {
      ok: false,
      reason: "bad_regex",
      error: exc instanceof Error ? exc.message : String(exc),
    };
  }
}

// ---------------------------------------------------------------------------
// Policy schema parsing
// ---------------------------------------------------------------------------

/**
 * A single matcher prepared for engine consumption. Internal type; kept
 * un-exported to avoid widening the public surface (snapshot-controlled).
 */
interface CompiledMatcher {
  readonly id: string;
  readonly kind: "regex" | "json_pointer" | "json_path";
  readonly action: "redact" | "hash" | "drop";
  readonly pattern: RegExp | null;
  // Raw pointer / selector strings as authored in the policy. For
  // ``json_pointer`` matchers these are RFC 6901 pointers; for
  // ``json_path`` matchers these are the JSONPath selectors before
  // compilation. Empty for ``regex``.
  readonly jsonPaths: ReadonlyArray<string>;
  // JSONPath selectors compiled to their equivalent RFC 6901 JSON
  // Pointer form so leaf evaluation can reuse the same pointer-matching
  // path used by json_pointer matchers. Empty for non-pointer/non-path
  // matcher kinds. VAL-V3M5-018.
  readonly jsonPointers: ReadonlyArray<string>;
}

/**
 * Per-action behaviour from the policy's ``action_policy`` block. Internal
 * type; not exported.
 */
interface ActionPolicy {
  readonly hashSaltRef: string;
  readonly hashAlgorithm: "hmac-sha256";
  readonly redactPlaceholder: string;
  readonly dropPlaceholder: string | null;
}

/**
 * A parsed, validated v1 redaction policy. Construct via
 * :func:`loadRedactionPolicy`; direct instantiation bypasses validation
 * and is reserved for engine internals.
 *
 * Mirrors :class:`relay.redaction.RedactionPolicy` (Python). Public field
 * names use camelCase per TS conventions; the wire policy schema uses
 * snake_case.
 */
export class RedactionPolicyImpl {
  readonly policyVersion: string;
  readonly rawCapture: boolean;
  readonly dpaRef: string | null;
  readonly approverUserId: string | null;
  readonly matchers: ReadonlyArray<CompiledMatcher>;
  readonly actionPolicy: ActionPolicy;
  readonly appliesToFields: ReadonlyArray<string>;

  /** @internal */
  constructor(args: {
    policyVersion: string;
    rawCapture: boolean;
    dpaRef: string | null;
    approverUserId: string | null;
    matchers: ReadonlyArray<CompiledMatcher>;
    actionPolicy: ActionPolicy;
    appliesToFields: ReadonlyArray<string>;
  }) {
    this.policyVersion = args.policyVersion;
    this.rawCapture = args.rawCapture;
    this.dpaRef = args.dpaRef;
    this.approverUserId = args.approverUserId;
    this.matchers = args.matchers;
    this.actionPolicy = args.actionPolicy;
    this.appliesToFields = args.appliesToFields;
  }
}

/**
 * Parse and validate a v1 redaction policy body.
 *
 * Throws :class:`RelayRedactionPolicyError` if the body is structurally
 * invalid. Throws :class:`RelayRedactionRawCaptureDeniedError` if
 * ``raw_capture: true`` is requested without both ``dpa_ref`` and
 * ``approver_user_id``. The SDK fails closed (VAL-W4-024); no
 * partially-applied policy is returned.
 */
export function loadRedactionPolicy(body: unknown): RedactionPolicyImpl {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new RelayRedactionPolicyError("redaction policy body must be an object", {
      code: RELAY_SDK_POLICY_INVALID_CODE,
      details: {
        reason: "wrong_type",
        received: body === null ? "null" : Array.isArray(body) ? "array" : typeof body,
      },
    });
  }
  const obj = body as Record<string, unknown>;

  // schema_version literal check.
  const schemaVersion = obj["schema_version"];
  if (
    schemaVersion !== POLICY_SCHEMA_VERSION_PRIMARY &&
    schemaVersion !== POLICY_SCHEMA_VERSION_ALIAS
  ) {
    throw new RelayRedactionPolicyError(
      `redaction policy schema_version MUST be '${POLICY_SCHEMA_VERSION_PRIMARY}' (or v0.1 alias '${POLICY_SCHEMA_VERSION_ALIAS}')`,
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: {
          reason: "schema_version",
          expected: POLICY_SCHEMA_VERSION_PRIMARY,
          received: schemaVersion === undefined ? null : schemaVersion,
        },
      },
    );
  }

  // policy_version required + non-empty.
  const policyVersion = obj["policy_version"];
  if (typeof policyVersion !== "string" || policyVersion.trim() === "") {
    throw new RelayRedactionPolicyError(
      "redaction policy policy_version MUST be a non-empty string",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "policy_version_missing" },
      },
    );
  }

  // raw_capture strict bool (default false).
  const rawCaptureRaw = obj["raw_capture"];
  let rawCapture: boolean;
  if (rawCaptureRaw === undefined) {
    rawCapture = false;
  } else if (typeof rawCaptureRaw === "boolean") {
    rawCapture = rawCaptureRaw;
  } else {
    throw new RelayRedactionPolicyError(
      "redaction policy raw_capture MUST be a strict boolean",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: {
          reason: "raw_capture_not_bool",
          received_type: typeof rawCaptureRaw,
        },
      },
    );
  }

  const dpaRefRaw = obj["dpa_ref"];
  if (dpaRefRaw !== undefined && dpaRefRaw !== null && typeof dpaRefRaw !== "string") {
    throw new RelayRedactionPolicyError(
      "redaction policy dpa_ref MUST be a string or null",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "dpa_ref_wrong_type" },
      },
    );
  }
  const dpaRef: string | null = typeof dpaRefRaw === "string" ? dpaRefRaw : null;

  const approverRaw = obj["approver_user_id"];
  if (approverRaw !== undefined && approverRaw !== null && typeof approverRaw !== "string") {
    throw new RelayRedactionPolicyError(
      "redaction policy approver_user_id MUST be a string or null",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "approver_wrong_type" },
      },
    );
  }
  const approverUserId: string | null = typeof approverRaw === "string" ? approverRaw : null;

  // Cross-field: raw_capture=true requires BOTH dpa_ref and
  // approver_user_id (CLAUDE.md banned pattern #11; spec G.1).
  if (rawCapture) {
    const missing: string[] = [];
    if (dpaRef === null || dpaRef === "") missing.push("dpa_ref");
    if (approverUserId === null || approverUserId === "") missing.push("approver_user_id");
    if (missing.length > 0) {
      throw new RelayRedactionRawCaptureDeniedError(
        "redaction policy raw_capture=true requires dpa_ref AND approver_user_id; refusing to load policy that would permit raw plaintext capture without DPA + approver",
        {
          code: RELAY_SDK_RAW_CAPTURE_DENIED_CODE,
          details: {
            reason: "raw-capture-missing-dpa-or-approver",
            missing,
          },
        },
      );
    }
  }

  // Matchers list.
  const rawMatchers = obj["matchers"] ?? [];
  if (!Array.isArray(rawMatchers)) {
    throw new RelayRedactionPolicyError(
      "redaction policy matchers MUST be a list",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "matchers_wrong_type" },
      },
    );
  }
  const compiled: CompiledMatcher[] = [];
  for (let idx = 0; idx < rawMatchers.length; idx++) {
    const raw = rawMatchers[idx];
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      throw new RelayRedactionPolicyError(`matcher #${idx} MUST be an object`, {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "matcher_wrong_type", index: idx },
      });
    }
    const m = raw as Record<string, unknown>;
    const kind = m["kind"];
    if (typeof kind !== "string" || !KNOWN_MATCHER_KINDS.has(kind)) {
      throw new RelayRedactionPolicyError(
        `matcher #${idx} has unknown kind ${JSON.stringify(kind)}`,
        {
          code: RELAY_SDK_POLICY_INVALID_CODE,
          details: { reason: "unknown_kind", index: idx, received: kind ?? null },
        },
      );
    }
    const action = m["action"];
    if (typeof action !== "string" || !KNOWN_ACTIONS.has(action)) {
      throw new RelayRedactionPolicyError(
        `matcher #${idx} has unknown action ${JSON.stringify(action)}`,
        {
          code: RELAY_SDK_POLICY_INVALID_CODE,
          details: { reason: "unknown_action", index: idx, received: action ?? null },
        },
      );
    }
    const matcherId = m["id"];
    if (typeof matcherId !== "string" || matcherId.trim() === "") {
      throw new RelayRedactionPolicyError(`matcher #${idx} MUST have a non-empty id`, {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "matcher_id_missing", index: idx },
      });
    }
    let pattern: RegExp | null = null;
    let jsonPaths: ReadonlyArray<string> = [];
    let jsonPointers: ReadonlyArray<string> = [];
    if (kind === "regex") {
      const rawPattern = m["pattern"];
      if (typeof rawPattern !== "string" || rawPattern === "") {
        throw new RelayRedactionPolicyError(
          `regex matcher #${idx} MUST have a non-empty pattern`,
          {
            code: RELAY_SDK_POLICY_INVALID_CODE,
            details: { reason: "regex_pattern_missing", index: idx },
          },
        );
      }
      // Translate the supported Python regex-flag/syntax subset to JS before
      // compiling (VAL-REDACT-003): a leading (?i)/(?s)/(?m) prefix maps to
      // the JS flags string, Python named groups (?P<...>) are rejected
      // consistently with the Python SDK, and mid-pattern global flags fail
      // closed -- so the same policy body loads (or is rejected) identically
      // on both runtimes.
      const compiled = compileRegexPattern(rawPattern);
      if (!compiled.ok) {
        // VAL-REDACT-006: a catastrophic-backtracking (ReDoS) rejection carries
        // the distinct code RELAY-SDK-017 so callers can branch on it; every
        // other compile rejection keeps the generic policy-invalid code. The
        // Python SDK surfaces the identical code + reason for the ReDoS case.
        const code =
          compiled.reason === "redos_pattern"
            ? RELAY_SDK_REGEX_REDOS_CODE
            : RELAY_SDK_POLICY_INVALID_CODE;
        throw new RelayRedactionPolicyError(
          `regex matcher #${idx} pattern is invalid: ${compiled.error}`,
          {
            code,
            details: {
              reason: compiled.reason,
              index: idx,
              pattern: rawPattern,
              error: compiled.error,
            },
          },
        );
      }
      pattern = compiled.pattern;
    } else if (kind === "json_pointer") {
      const rawPaths = m["paths"];
      if (
        !Array.isArray(rawPaths) ||
        rawPaths.length === 0 ||
        !rawPaths.every((p) => typeof p === "string" && p !== "")
      ) {
        throw new RelayRedactionPolicyError(
          `json_pointer matcher #${idx} MUST have a non-empty list of string paths`,
          {
            code: RELAY_SDK_POLICY_INVALID_CODE,
            details: { reason: "json_paths_missing", index: idx },
          },
        );
      }
      jsonPaths = Object.freeze([...(rawPaths as string[])]);
    } else if (kind === "json_path") {
      // VAL-V3M5-018. JSONPath selectors (RFC 9535 subset). The SDK
      // ships a minimal native parser to keep the redaction path
      // dep-free and deterministic across both runtimes; the supported
      // subset is documented at :func:`jsonPathToPointer`.
      const rawPaths = m["paths"];
      if (
        !Array.isArray(rawPaths) ||
        rawPaths.length === 0 ||
        !rawPaths.every((p) => typeof p === "string" && p !== "")
      ) {
        throw new RelayRedactionPolicyError(
          `json_path matcher #${idx} MUST have a non-empty list of string paths`,
          {
            code: RELAY_SDK_POLICY_INVALID_CODE,
            details: { reason: "json_paths_missing", index: idx },
          },
        );
      }
      const compiledPointers: string[] = [];
      for (const sel of rawPaths as string[]) {
        try {
          compiledPointers.push(jsonPathToPointer(sel));
        } catch (exc) {
          throw new RelayRedactionPolicyError(
            `json_path matcher #${idx} has an unsupported selector: ${exc instanceof Error ? exc.message : String(exc)}`,
            {
              code: RELAY_SDK_POLICY_INVALID_CODE,
              details: {
                reason: "json_path_unsupported",
                index: idx,
                error: exc instanceof Error ? exc.message : String(exc),
              },
              cause: exc,
            },
          );
        }
      }
      jsonPaths = Object.freeze([...(rawPaths as string[])]);
      jsonPointers = Object.freeze(compiledPointers);
    }
    compiled.push({
      id: matcherId,
      kind: kind as "regex" | "json_pointer" | "json_path",
      action: action as "redact" | "hash" | "drop",
      pattern,
      jsonPaths,
      jsonPointers,
    });
  }

  // action_policy block.
  const rawActionPolicy = obj["action_policy"] ?? {};
  if (rawActionPolicy === null || typeof rawActionPolicy !== "object" || Array.isArray(rawActionPolicy)) {
    throw new RelayRedactionPolicyError(
      "redaction policy action_policy MUST be an object",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "action_policy_wrong_type" },
      },
    );
  }
  const ap = rawActionPolicy as Record<string, unknown>;

  const hashBlock = (ap["hash"] ?? {}) as Record<string, unknown>;
  if (hashBlock === null || typeof hashBlock !== "object" || Array.isArray(hashBlock)) {
    throw new RelayRedactionPolicyError(
      "redaction policy action_policy.hash MUST be an object",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "hash_block_wrong_type" },
      },
    );
  }
  const hashAlgorithm = (hashBlock["algorithm"] as string | undefined) ?? "hmac-sha256";
  if (hashAlgorithm !== "hmac-sha256") {
    throw new RelayRedactionPolicyError(
      "redaction policy action_policy.hash.algorithm MUST be 'hmac-sha256' (plain SHA-256 is forbidden, spec G.2)",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: {
          reason: "hash_algorithm_unsupported",
          received: hashAlgorithm,
        },
      },
    );
  }
  const hashSaltRef = hashBlock["salt_ref"];
  if (typeof hashSaltRef !== "string" || hashSaltRef.trim() === "") {
    throw new RelayRedactionPolicyError(
      "redaction policy action_policy.hash.salt_ref MUST be a non-empty string",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "hash_salt_ref_missing" },
      },
    );
  }
  const redactBlock = (ap["redact"] ?? {}) as Record<string, unknown>;
  if (redactBlock === null || typeof redactBlock !== "object" || Array.isArray(redactBlock)) {
    throw new RelayRedactionPolicyError(
      "redaction policy action_policy.redact MUST be an object",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "redact_block_wrong_type" },
      },
    );
  }
  const redactPlaceholderRaw = redactBlock["placeholder"] ?? "<redacted>";
  if (typeof redactPlaceholderRaw !== "string") {
    throw new RelayRedactionPolicyError(
      "redaction policy action_policy.redact.placeholder MUST be a string",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "redact_placeholder_wrong_type" },
      },
    );
  }

  const dropBlock = (ap["drop"] ?? {}) as Record<string, unknown>;
  if (dropBlock === null || typeof dropBlock !== "object" || Array.isArray(dropBlock)) {
    throw new RelayRedactionPolicyError(
      "redaction policy action_policy.drop MUST be an object",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "drop_block_wrong_type" },
      },
    );
  }
  const dropPlaceholderRaw = dropBlock["placeholder"];
  if (
    dropPlaceholderRaw !== undefined &&
    dropPlaceholderRaw !== null &&
    typeof dropPlaceholderRaw !== "string"
  ) {
    throw new RelayRedactionPolicyError(
      "redaction policy action_policy.drop.placeholder MUST be a string or null",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "drop_placeholder_wrong_type" },
      },
    );
  }
  const dropPlaceholder: string | null =
    typeof dropPlaceholderRaw === "string" ? dropPlaceholderRaw : null;

  const actionPolicy: ActionPolicy = {
    hashSaltRef,
    hashAlgorithm: "hmac-sha256",
    redactPlaceholder: redactPlaceholderRaw,
    dropPlaceholder,
  };

  // applies_to_fields list (optional override).
  const rawFields = obj["applies_to_fields"];
  let appliesToFields: ReadonlyArray<string>;
  if (rawFields === undefined) {
    appliesToFields = DEFAULT_APPLIES_TO_FIELDS;
  } else if (
    Array.isArray(rawFields) &&
    rawFields.every((f) => typeof f === "string" && f !== "")
  ) {
    appliesToFields = Object.freeze([...(rawFields as string[])]);
  } else {
    throw new RelayRedactionPolicyError(
      "redaction policy applies_to_fields MUST be a list of non-empty strings",
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "applies_to_fields_wrong_type" },
      },
    );
  }

  return new RedactionPolicyImpl({
    policyVersion,
    rawCapture,
    dpaRef,
    approverUserId,
    matchers: Object.freeze(compiled),
    actionPolicy,
    appliesToFields,
  });
}

// ---------------------------------------------------------------------------
// Salt provider + HMAC primitive
// ---------------------------------------------------------------------------

/**
 * Caller-supplied salt resolution. Salts are tenant-scoped secrets; the
 * SDK never bakes them in. Production callers wire this to the sidecar
 * salt registry; tests pass a deterministic in-memory provider.
 */
export type SaltProvider = (saltRef: string) => Uint8Array;

/**
 * Return the lowercase hex digest of HMAC-SHA-256(salt, plaintext utf-8).
 * Byte-equal to Python ``hmac.new(salt, plaintext.encode('utf-8'),
 * hashlib.sha256).hexdigest()``.
 */
export function hmacSha256Hex(salt: Uint8Array, plaintext: string): string {
  return crypto
    .createHmac("sha256", Buffer.from(salt))
    .update(plaintext, "utf8")
    .digest("hex");
}

/**
 * Return the lowercase hex digest of SHA-256(value bytes). Used for binary
 * attachment digest references (VAL-W4-025).
 */
function sha256HexBytes(value: Uint8Array): string {
  return crypto.createHash("sha256").update(Buffer.from(value)).digest("hex");
}

/**
 * Escape a single RFC 6901 JSON Pointer reference token.
 *
 * Per RFC 6901 sec 4: ``~`` -> ``~0``, ``/`` -> ``~1``. The ``~`` escape
 * MUST happen before the ``/`` escape so the encoder is its own inverse
 * on round-trip. Mirrors :func:`_escape_pointer_token` in the Python
 * redaction module.
 */
function escapePointerToken(token: string): string {
  return token.replace(/~/g, "~0").replace(/\//g, "~1");
}

/**
 * Compile a JSONPath (RFC 9535 subset) selector to an RFC 6901 pointer.
 *
 * Supported subset (VAL-V3M5-018):
 *
 *   * ``$``                   -- the root document (returns ``""``).
 *   * ``$.<key>``             -- dotted child access; key chars are
 *     ``[A-Za-z_][A-Za-z0-9_-]*``. RFC 6901 escapes are applied to the
 *     key (``~`` -> ``~0``, ``/`` -> ``~1``).
 *   * ``$.<key>[N]``          -- non-negative integer array index.
 *   * Chained combinations:    ``$.a.b[0].c[1]`` etc.
 *
 * Out of scope (throws :class:`Error`):
 *
 *   * ``..`` (recursive descent), ``*`` (wildcard), ``[?(expr)]``
 *     (filter), ``[start:end:step]`` (slice), bracket-notation string
 *     keys ``['key']`` (the spec G.3 fixtures use only dotted form).
 *
 * Returns the equivalent RFC 6901 pointer string. The empty pointer
 * ``""`` represents the document root.
 *
 * Cross-runtime parity: the Python redaction module ships an
 * identically-shaped parser
 * (``packages/sdk-python/relay/redaction.py:_jsonpath_to_pointer``) so
 * both runtimes resolve the same selector to the same pointer.
 */
function jsonPathToPointer(selector: string): string {
  if (typeof selector !== "string" || selector.length === 0) {
    throw new Error("selector MUST be a non-empty string");
  }
  if (!selector.startsWith("$")) {
    throw new Error(`selector MUST start with '$': ${JSON.stringify(selector)}`);
  }
  const rest = selector.slice(1);
  if (rest.length === 0) return "";
  const parts: string[] = [];
  let i = 0;
  const n = rest.length;
  while (i < n) {
    const ch = rest[i];
    if (ch === ".") {
      // Dotted child access: read the key up to the next '.' or '['.
      i += 1;
      if (i >= n || rest[i] === "." || rest[i] === "[") {
        throw new Error(
          `selector has empty key after '.': ${JSON.stringify(selector)}`,
        );
      }
      const start = i;
      while (i < n && rest[i] !== "." && rest[i] !== "[") {
        const keyCh = rest[i];
        if (keyCh === "*" || keyCh === "?" || keyCh === "(") {
          throw new Error(
            `selector uses unsupported feature ${JSON.stringify(keyCh)}: ${JSON.stringify(selector)}`,
          );
        }
        i += 1;
      }
      const key = rest.slice(start, i);
      if (key.length === 0) {
        throw new Error(
          `selector has empty key segment: ${JSON.stringify(selector)}`,
        );
      }
      parts.push(escapePointerToken(key));
    } else if (ch === "[") {
      // Integer array index: ``[N]`` where N >= 0.
      i += 1;
      const indexStart = i;
      while (i < n) {
        const digitCh = rest[i];
        if (digitCh === undefined || digitCh < "0" || digitCh > "9") break;
        i += 1;
      }
      if (i === indexStart || i >= n || rest[i] !== "]") {
        throw new Error(
          `selector has malformed array index: ${JSON.stringify(selector)}`,
        );
      }
      const indexToken = rest.slice(indexStart, i);
      i += 1; // consume ']'
      parts.push(indexToken);
    } else {
      throw new Error(
        `selector has unexpected character ${JSON.stringify(ch)} at position ${i + 1}: ${JSON.stringify(selector)}`,
      );
    }
  }
  return parts.length > 0 ? "/" + parts.join("/") : "";
}

/**
 * Return ``true`` if RFC 6901 ``pointer`` matches a ``json_pointer`` matcher
 * path, honoring a single-segment ``*`` wildcard (VAL-REDACT-001).
 *
 * Both arguments are RFC 6901 JSON Pointers built by the same convention used
 * in ``RedactionEngine.walk``: a leading ``/`` then ``/``-separated reference
 * tokens, each token escaped per RFC 6901 sec 4 (``~`` -> ``~0``, ``/`` ->
 * ``~1``). Splitting on ``/`` therefore yields aligned, identically-escaped
 * segments on both sides, so exact tokens compare correctly and a ``*`` token
 * in the matcher path matches any single concrete segment.
 *
 * Wildcard semantics (byte-for-byte identical to the Python
 * ``_json_pointer_matches`` in
 * ``packages/sdk-python/relay/redaction.py``):
 *
 *   * A matcher token equal to ``*`` matches exactly one concrete segment
 *     (any array index or object key) at that position.
 *   * Every other matcher token must equal the concrete token exactly.
 *   * The wildcard is single-segment, never a recursive-descent glob, so the
 *     matcher path and the concrete pointer MUST have the same number of
 *     segments to match. ``/messages/<star>/content/text`` does NOT match
 *     ``/messages/0/extra/content/text``.
 *
 * A matcher path with no ``*`` token reduces to exact string equality,
 * preserving prior behavior (and cross-runtime parity) for every non-wildcard
 * ``json_pointer`` matcher.
 */
function jsonPointerMatches(matcherPath: string, pointer: string): boolean {
  if (!matcherPath.includes("*")) {
    // Fast path: no wildcard -> exact equality, identical to the
    // pre-VAL-REDACT-001 ``includes`` behavior.
    return matcherPath === pointer;
  }
  const matcherTokens = matcherPath.split("/");
  const pointerTokens = pointer.split("/");
  if (matcherTokens.length !== pointerTokens.length) {
    return false;
  }
  for (let i = 0; i < matcherTokens.length; i += 1) {
    const matcherToken = matcherTokens[i];
    const pointerToken = pointerTokens[i];
    if (matcherToken === "*") {
      // Single-segment wildcard. The empty string only occurs as the
      // synthetic leading segment (both sides share it); a leading-segment
      // ``*`` would require the matcher path to start with ``*`` rather than
      // ``/``, which never occurs for a well-formed RFC 6901 pointer, so an
      // empty concrete token here would be a malformed pointer -- reject it.
      if (pointerToken === "") {
        return false;
      }
      continue;
    }
    if (matcherToken !== pointerToken) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/**
 * A policy-bound redactor that walks a payload and emits a copy.
 *
 * The engine is stateless across calls: redacting the same payload twice
 * produces byte-identical output (after JCS canonicalization). The engine
 * is safe to reuse across many calls; the compiled regex patterns and
 * HMAC primitives are re-entrant.
 */
export class RedactionEngine {
  private readonly _policy: RedactionPolicyImpl;
  private readonly _saltProvider: SaltProvider;
  private _cachedSalt: Uint8Array | null;

  constructor(args: { policy: RedactionPolicyImpl; saltProvider: SaltProvider }) {
    this._policy = args.policy;
    this._saltProvider = args.saltProvider;
    this._cachedSalt = null;
  }

  get policy(): RedactionPolicyImpl {
    return this._policy;
  }

  private resolveSalt(): Uint8Array {
    if (this._cachedSalt === null) {
      const resolved = this._saltProvider(this._policy.actionPolicy.hashSaltRef);
      if (!(resolved instanceof Uint8Array) && !Buffer.isBuffer(resolved)) {
        throw new RelayRedactionPolicyError(
          "saltProvider MUST return a Uint8Array (or Buffer)",
          {
            code: RELAY_SDK_POLICY_INVALID_CODE,
            details: {
              reason: "salt_provider_wrong_type",
              salt_ref: this._policy.actionPolicy.hashSaltRef,
            },
          },
        );
      }
      this._cachedSalt = resolved;
    }
    return this._cachedSalt;
  }

  private buildReplacement(matcher: CompiledMatcher, matchedText: string): string {
    const ap = this._policy.actionPolicy;
    if (matcher.action === "redact") return ap.redactPlaceholder;
    if (matcher.action === "hash") {
      const salt = this.resolveSalt();
      return hmacSha256Hex(salt, matchedText);
    }
    if (matcher.action === "drop") return ap.dropPlaceholder ?? "";
    // Unreachable: loadRedactionPolicy validates the action set.
    throw new RelayRedactionPolicyError(
      `matcher ${matcher.id} has unsupported action ${matcher.action}`,
      {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "unsupported_action", matcher_id: matcher.id },
      },
    );
  }

  private applyMatchersToString(value: string): string {
    if (value.length === 0) return value;
    // VAL-REDACT-006: clamp an over-cap leaf BEFORE matching. A leaf longer
    // than MAX_REDACTION_LEAF_LENGTH is truncated to the cap; the removed tail
    // is replaced by REDACTION_TRUNCATION_MARKER, which is appended AFTER
    // matching so the marker itself is never scanned or redacted. This bounds
    // total matcher work (defense against ReDoS via huge inputs as well as
    // linear-but-slow patterns) and guarantees raw plaintext beyond the cap
    // never crosses the wire. Byte-identical to the Python SDK clamp.
    let truncated = false;
    let leaf = value;
    if (leaf.length > MAX_REDACTION_LEAF_LENGTH) {
      leaf = leaf.slice(0, MAX_REDACTION_LEAF_LENGTH);
      truncated = true;
    }
    const redacted = this.applyMatchersToClampedString(leaf);
    return truncated ? redacted + REDACTION_TRUNCATION_MARKER : redacted;
  }

  private applyMatchersToClampedString(value: string): string {
    // Matching runs on the NFKC + confusables-folded DETECTION surface so
    // homograph-disguised secrets are still caught. The EMITTED output is
    // reconstructed from the ORIGINAL code points: only the original spans
    // corresponding to matched folded spans are replaced by the placeholder,
    // and every unmatched original code unit is reproduced verbatim. This
    // fixes VAL-REDACT-007 (the engine previously emitted the folded string,
    // silently transliterating legitimate non-secret Cyrillic/Greek content
    // into ASCII look-alikes) WITHOUT weakening detection. Byte-identical to
    // the Python ``_apply_matchers_to_clamped_string``.
    const { folded, originStarts, originEnds } = foldWithOrigin(value);
    // The folded detection surface MUST equal normaliseForMatching exactly so
    // match behavior (and Python<->TS parity) is unchanged by origin tracking.
    // If a pathological input made the per-segment fold diverge from the
    // whole-string fold, fail closed by redacting the WHOLE leaf rather than
    // risk a wrong-offset splice (no plaintext leak, no partial result).
    if (folded !== normaliseForMatching(value)) {
      return this._policy.actionPolicy.redactPlaceholder;
    }
    // Walk matchers, collecting (origStart, origEnd, replacement) tuples in
    // ORIGINAL-string coordinates (mapped from folded match spans).
    const spans: Array<[number, number, string]> = [];
    for (const matcher of this._policy.matchers) {
      if (matcher.kind !== "regex" || matcher.pattern === null) {
        // json_pointer matchers are applied at the leaf level by the
        // walker, not at the string level.
        continue;
      }
      // Important: clone the regex per use to reset `lastIndex` and
      // avoid sticky state between calls.
      const re = new RegExp(matcher.pattern.source, matcher.pattern.flags);
      let m: RegExpExecArray | null;
      while ((m = re.exec(folded)) !== null) {
        const fstart = m.index;
        const fend = m.index + m[0].length;
        const matchedText = folded.slice(fstart, fend);
        const replacement = this.buildReplacement(matcher, matchedText);
        // Map folded span -> original span. A zero-width folded match maps to
        // the zero-width original point at that folded index's origin start.
        // The fold-equality guard above guarantees match offsets fall within
        // ``originStarts`` (length === folded.length), so the ?? fallbacks are
        // unreachable defense; ``value.length`` covers a span that ends at EOF.
        let ostart: number;
        let oend: number;
        if (fend > fstart) {
          ostart = originStarts[fstart] ?? value.length;
          oend = originEnds[fend - 1] ?? value.length;
        } else {
          ostart =
            fstart < originStarts.length
              ? (originStarts[fstart] ?? value.length)
              : value.length;
          oend = ostart;
        }
        spans.push([ostart, oend, replacement]);
        // Guard against zero-width matches causing an infinite loop.
        if (fend === fstart) re.lastIndex += 1;
      }
    }
    // No matcher fired: emit the ORIGINAL string verbatim (the fix -- the
    // folded/transliterated form is never emitted). VAL-REDACT-007.
    if (spans.length === 0) return value;
    // Sort by start, then by end DESCENDING so the span that OPENS each
    // overlap group is the earliest-starting and (among equal starts)
    // longest match -- a deterministic, replacement-defining "highest
    // priority" span. Overlapping spans are then merged into their
    // INTERVAL UNION rather than dropped (matches Python sort key
    // ``(start, -end)`` and merge at redaction.py:919-932).
    //
    // VAL-REDACT-004 (HIGH / security; byte-identical to the Python
    // VAL-REDACT-002 fix): the prior logic skipped any span that overlapped
    // the kept span. When a later span started inside the kept span but
    // extended BEYOND its end, the tail between the two ends was spliced
    // back in as plaintext -- leaking the unredacted tail of a matched
    // secret (e.g. "alphabravosecret" emitted "<redacted>vosecret").
    // Proper interval merging extends the open interval's end to max(end)
    // so the entire union of matched ranges is redacted by a single
    // replacement and no matched byte is ever emitted in clear.
    spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
    const merged: Array<[number, number, string]> = [];
    for (const span of spans) {
      const last = merged.length > 0 ? merged[merged.length - 1] : undefined;
      if (last !== undefined && span[0] < last[1]) {
        // Overlap: extend the open interval to the union end, keeping the
        // replacement of the span that opened the interval (the earliest-
        // starting / longest-at-that-start match). The end is max() because
        // a fully-contained later span (end <= prev_end) must not shrink the
        // redacted range.
        if (span[1] > last[1]) {
          last[1] = span[1];
        }
        continue;
      }
      merged.push(span);
    }
    // Splice replacements into the ORIGINAL string at the mapped offsets.
    // Unmatched runs are copied from the original verbatim, so non-secret
    // Cyrillic/Greek content round-trips unchanged (VAL-REDACT-007); matched
    // secret spans are replaced by the placeholder. The folded-span ->
    // original-span mapping (foldWithOrigin) guarantees each match span fully
    // covers its contributing original code points, so the union still
    // contains no clear matched byte (the VAL-REDACT-004 / Bug 4 guarantee).
    // Mirrors Python ``_apply_matchers_to_clamped_string``.
    const out: string[] = [];
    let cursor = 0;
    for (const [start, end, repl] of merged) {
      out.push(value.slice(cursor, start));
      out.push(repl);
      cursor = end;
    }
    out.push(value.slice(cursor));
    return out.join("");
  }

  /**
   * Return a redacted deep-copy of ``payload``.
   *
   * The full payload tree is walked; the matcher set is global because
   * real-world callers nest tool args + retrieval docs under many shapes.
   * Strings outside ``applies_to_fields`` are also redacted in v0.1: the
   * SDK errs on the side of more redaction, never less (CLAUDE.md
   * keystone #7). Binary buffer values (Uint8Array, Buffer, ArrayBuffer)
   * are replaced by ``{_digest_sha256: "<hex>"}`` references
   * (VAL-W4-025); raw bytes never appear in the output object.
   */
  redact(payload: Record<string, unknown>): Record<string, unknown> {
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      throw new RelayRedactionPolicyError("payload MUST be an object", {
        code: RELAY_SDK_POLICY_INVALID_CODE,
        details: { reason: "payload_wrong_type" },
      });
    }
    return this.walk(payload) as Record<string, unknown>;
  }

  private walk(value: unknown, pointer: string = ""): unknown {
    // VAL-V2M08-025: json_pointer leaf evaluation. A matcher whose
    // ``paths`` includes the current RFC 6901 pointer wins over any
    // regex matcher for the same leaf (most-specific selector). Apply
    // at every non-container leaf type. Containers (object/array)
    // descend unconditionally.
    const jsonPointerMatch = this.findJsonPointerMatch(pointer);
    if (value === null || value === undefined) {
      if (jsonPointerMatch !== null) {
        return this.buildReplacement(jsonPointerMatch, value === null ? "null" : "undefined");
      }
      return value;
    }
    if (typeof value === "string") {
      if (jsonPointerMatch !== null) {
        // Pointer-match wins; skip regex matchers entirely.
        return this.buildReplacement(jsonPointerMatch, value);
      }
      return this.applyMatchersToString(value);
    }
    if (typeof value === "number" || typeof value === "boolean") {
      if (jsonPointerMatch !== null) {
        return this.buildReplacement(jsonPointerMatch, String(value));
      }
      return value;
    }
    // Binary buffers MUST become digest-only references (VAL-W4-025).
    // An explicit json_pointer match on a bytes leaf produces the
    // matcher's placeholder instead (caller asked for the path to be
    // redacted; honor that even when the leaf is binary). Mirrors
    // Python redaction.py:_walk bytes branch.
    if (value instanceof Uint8Array) {
      if (jsonPointerMatch !== null) {
        return this.buildReplacement(
          jsonPointerMatch,
          new TextDecoder("utf-8", { fatal: false }).decode(value),
        );
      }
      return { _digest_sha256: sha256HexBytes(value) };
    }
    if (value instanceof ArrayBuffer) {
      const bytes = new Uint8Array(value);
      if (jsonPointerMatch !== null) {
        return this.buildReplacement(
          jsonPointerMatch,
          new TextDecoder("utf-8", { fatal: false }).decode(bytes),
        );
      }
      return { _digest_sha256: sha256HexBytes(bytes) };
    }
    if (typeof Blob !== "undefined" && value instanceof Blob) {
      // Blob is async-only; we cannot read it synchronously here. Refuse
      // to embed it; the caller MUST pass the resolved bytes (Uint8Array)
      // or a Buffer.
      throw new RelayRedactionPolicyError(
        "Blob payloads MUST be resolved to Uint8Array before redaction; refusing to include a raw Blob",
        {
          code: RELAY_SDK_POLICY_INVALID_CODE,
          details: { reason: "unresolved_blob" },
        },
      );
    }
    if (Array.isArray(value)) {
      return value.map((v, idx) => this.walk(v, pointer + "/" + String(idx)));
    }
    if (typeof value === "object") {
      const obj = value as Record<string, unknown>;
      // Null-prototype target so an OWN "__proto__" key round-trips as a
      // real own enumerable property instead of mutating the prototype
      // (which would silently DROP the field). Python's dict keeps
      // "__proto__" as a normal key; matching it preserves Py<->TS
      // canonical-wire byte parity (sdk-ts-01). JSON.stringify /
      // canonicalJsonStringify enumerate own enumerable keys, so a
      // null-prototype object serialises identically to a plain object.
      const out: Record<string, unknown> = Object.create(null) as Record<
        string,
        unknown
      >;
      for (const k of Object.keys(obj)) {
        out[k] = this.walk(obj[k], pointer + "/" + escapePointerToken(k));
      }
      return out;
    }
    // Anything else (function, symbol, bigint) gets coerced to string and
    // re-matched -- mirrors Python ``str(value)`` fallback.
    if (jsonPointerMatch !== null) {
      return this.buildReplacement(jsonPointerMatch, String(value));
    }
    return this.applyMatchersToString(String(value));
  }

  /**
   * Return the first pointer-style matcher whose declared selector
   * resolves to ``pointer``.
   *
   * Two matcher kinds participate in pointer-level evaluation:
   *
   *   * ``json_pointer`` (RFC 6901) -- raw pointers stored in
   *     ``matcher.jsonPaths``. A ``*`` reference token in a matcher path is a
   *     single-segment wildcard (VAL-REDACT-001): it matches any one array
   *     index or object key at that position. All other tokens must match
   *     exactly. The wildcard is single-segment, never a recursive-descent
   *     glob, so the matcher path and the concrete pointer must have the same
   *     segment count to match. Mirrors the Python ``_json_pointer_matches``
   *     byte-for-byte so both runtimes agree (keystone invariant #7).
   *   * ``json_path`` (RFC 9535 subset, VAL-V3M5-018) -- selectors
   *     compiled to RFC 6901 pointer form at policy load and stored in
   *     ``matcher.jsonPointers``. ``jsonPathToPointer`` rejects ``*``
   *     selectors, so these compiled pointers contain no wildcards and are
   *     compared by exact membership.
   *
   * Matchers are evaluated in declaration order. The root pointer
   * (empty string) never matches: matchers declare leaf paths like
   * ``/user/email``, not the document root.
   */
  private findJsonPointerMatch(pointer: string): CompiledMatcher | null {
    if (pointer.length === 0) return null;
    for (const matcher of this._policy.matchers) {
      if (matcher.kind === "json_pointer") {
        if (matcher.jsonPaths.some((path) => jsonPointerMatches(path, pointer)))
          return matcher;
      } else if (matcher.kind === "json_path") {
        if (matcher.jsonPointers.includes(pointer)) return matcher;
      }
    }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Canonical bytes serializer (RFC 8785 JCS subset)
// ---------------------------------------------------------------------------

/**
 * Recursive, sorted-key, compact-separator JSON stringifier used by
 * :func:`redactCapturePayload` to produce the wire body. Mirrors the
 * canonicalizer in ``packages/schemas/typescript/src/envelopes.ts`` so
 * the SDK does not need a workspace dep on ``@epochly/relay-schemas``.
 *
 * Cross-language byte equality with Python: callers compare the JCS
 * canonicalization of the redacted dict on both sides (the Python helper
 * uses ``json.dumps(..., sort_keys=True, separators=(",", ":"))``).
 */
function canonicalJsonStringify(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      // VAL-REDACT-005 (MEDIUM / determinism; byte-identical fail-closed with
      // the Python ``redact_capture_payload`` non-finite guard): RFC 8785 JCS
      // forbids non-finite numbers (Infinity/-Infinity/NaN). Pre-fix this
      // threw a bare ``Error`` while Python ``json.dumps(..., allow_nan=True)``
      // emitted invalid ``Infinity``/``NaN`` tokens -- the two SDKs diverged
      // on both outcome and error shape. We now raise a typed
      // ``RelayRedactionPolicyError`` (code RELAY-SDK-010,
      // ``details.reason = "non_finite_number"``) so both runtimes report the
      // rejection identically and fail closed on a non-finite leaf.
      throw new RelayRedactionPolicyError(
        "non-finite number (Infinity/-Infinity/NaN) is not permitted in a " +
          "capture payload; RFC 8785 JCS forbids non-finite numbers",
        {
          code: RELAY_SDK_POLICY_INVALID_CODE,
          details: { reason: "non_finite_number" },
        },
      );
    }
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJsonStringify).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) continue;
      parts.push(JSON.stringify(k) + ":" + canonicalJsonStringify(v));
    }
    return "{" + parts.join(",") + "}";
  }
  if (value === undefined) return "null";
  throw new Error(`canonicalJsonStringify: unsupported type ${typeof value}`);
}

/**
 * Redact ``payload`` and serialise the result to canonical JSON bytes.
 *
 * This is the canonical SDK entry point used by the trace-capture
 * surface. The returned bytes are exactly what the SDK transport hands to
 * the HTTP client; the bytes are what tests inspect to assert plaintext
 * absence (VAL-W4-019, VAL-W4-023, VAL-W4-025).
 *
 * Canonical form: RFC 8785 JCS-compatible (sort keys, compact separators,
 * deterministic number/string emission). Cross-language byte equality
 * with Python is verified by the conformance corpus (VAL-W4-020) using
 * the same canonicalization on both sides.
 */
export function redactCapturePayload(
  engine: RedactionEngine,
  payload: Record<string, unknown>,
): Uint8Array {
  const redacted = engine.redact(payload);
  return new TextEncoder().encode(canonicalJsonStringify(redacted));
}

/** Iterate over the default ``applies_to_fields`` list (helper). */
export function iterKnownAppliesToFields(): IterableIterator<string> {
  return DEFAULT_APPLIES_TO_FIELDS[Symbol.iterator]();
}

// Re-export the canonical stringify under a stable name so test corpora
// can invoke it without going through the redact entry point. Internal
// helper -- not part of the public package surface.
export { canonicalJsonStringify as _canonicalJsonStringify };
