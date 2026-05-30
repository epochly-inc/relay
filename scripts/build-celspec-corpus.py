"""Re-derive the W17.3 cel-spec conformance corpus from upstream (VAL-W17-010).

This generator makes Relay's CEL conformance corpus *reproducible from the
pinned google/cel-spec commit*. It is the authoritative way to refresh the
corpus when the pin rotates; hand-editing celspec_vectors.json is forbidden
because it invites fabricated provenance (the failure this script exists to
prevent).

What it does:

  1. Reads the pinned commit SHA from
     tests/conformance/cel-spec/PINNED_COMMIT.txt (override with --sha).
  2. Fetches the relevant `tests/simple/testdata/*.textproto` files from
     google/cel-spec AT THAT COMMIT over HTTPS (cached under --cache-dir).
  3. Parses each file, extracting self-contained (no-binding) test cases
     whose expression stays inside Relay's CEL profile and whose golden
     value is a profile-safe JSON kind (int / bool / string / list / map /
     null). Out-of-profile expressions (dyn, timestamp, duration, uint,
     bytes) are dropped even when their value is profile-safe.
  4. Evaluates every candidate under BOTH cel-python and cel-js and keeps
     only those where cel-python == cel-js == the upstream golden. A
     candidate the two runtimes disagree on, or that diverges from the
     upstream golden, is out of profile by construction and is dropped.
  5. Emits, with every claim true and mechanically auditable:
       - celspec_vectors.json   (real expr / golden / source / pinned SHA)
       - relay-profile-filter.yaml
       - MANIFEST.sha256
  6. Appends a small curated EXCLUDED set (dyn / timestamp / duration)
     sourced from real upstream cases so the profile-rejection surface is
     demonstrated.

Modes:
    (default)   write the three generated files.
    --check     regenerate in memory and diff against the committed files;
                exit 1 on any drift (no network-free guarantee -- this mode
                is for maintainers, not CI; CI uses
                scripts/check-cel-spec-drift.py which is offline).

Run under uv so cel-python / relay_contracts resolve:
    uv run python scripts/build-celspec-corpus.py
    uv run python scripts/build-celspec-corpus.py --check

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CELSPEC_DIR = REPO_ROOT / "tests" / "conformance" / "cel-spec"
PINNED_COMMIT_PATH = CELSPEC_DIR / "PINNED_COMMIT.txt"
UPSTREAM_PINS_PATH = CELSPEC_DIR / ".upstream-pins.json"
VECTORS_PATH = CELSPEC_DIR / "celspec_vectors.json"
PROFILE_FILTER_PATH = CELSPEC_DIR / "relay-profile-filter.yaml"
MANIFEST_PATH = CELSPEC_DIR / "MANIFEST.sha256"
DROPPED_PATH = CELSPEC_DIR / "dropped-candidates.json"
CELJS_RUNNER = (
    REPO_ROOT / "packages" / "contracts-typescript" / "test" / "_w17_3_celjs_runner.mjs"
)

RAW_BASE = "https://raw.githubusercontent.com/google/cel-spec/{sha}/tests/simple/testdata/{name}"
SOURCE_REPO = "https://github.com/google/cel-spec"
SOURCE_TREE = "tests/simple/testdata"
CELSPEC_TAG_COMPAT = "v0.20.0"

# Upstream files consumed for the INCLUDED set. These are the
# protobuf-free conformance files whose self-contained scalar/collection
# cases map cleanly onto Relay's CEL profile. dynamic.textproto and the
# proto2/proto3 files are intentionally excluded -- they exercise dyn(),
# protobuf packing, and Any, none of which are in profile.
INCLUDED_SOURCE_FILES = (
    "basic.textproto",
    "comparisons.textproto",
    "fields.textproto",
    "integer_math.textproto",
    "lists.textproto",
    "logic.textproto",
    "parse.textproto",
    "string.textproto",
)

# Patterns that mark an expression as OUTSIDE Relay's CEL profile, even
# when its golden value is a profile-safe JSON kind. All are matched
# against the CODE-ONLY form of the expression (string-literal bodies
# stripped by _strip_string_bodies) so a string such as "dyn(" or "5u" or
# "b" (which contains the substring b") is NOT misclassified.
_EXPR_DENY_SUBSTR = ("dyn(", "timestamp(", "duration(", "bytes(", "uint(")
#   - uint literal:  0u / 5U
#   - bytes literal: a CEL bytes prefix before a quote, at a token boundary.
#     CEL allows b / B and the raw-byte orderings br / bR / rb / Rb (any
#     case), e.g. b"x", B'x', br"x", rb"x". A plain raw STRING r"x" / R"x"
#     is NOT bytes and is left in profile. On stripped code the lookbehind
#     keeps a stray b/B/r that ends an identifier from matching.
_EXPR_DENY_RE = re.compile(
    r"\b\d+[uU]\b|(?<![A-Za-z0-9_])(?:[bB][rR]?|[rR][bB])['\"]"
)

# Upstream files that the curated EXCLUDED_VECTORS are sourced from. Fetched
# and parsed so each excluded vector's expression/expected_value/source can
# be validated against the real upstream record (no fabricated exclusions).
EXCLUDED_SOURCE_FILES = ("lists.textproto", "timestamps.textproto")

# Curated EXCLUDED vectors. Each is a REAL upstream case (real expr, real
# golden, real source) whose expression uses a feature Relay's profile
# rejects. They are never evaluated by the conformance test; they document
# the rejection surface (VAL-W17-011 requires a justified exclusion).
EXCLUDED_VECTORS: tuple[dict[str, Any], ...] = (
    {
        "vector_id": "lists/index/zero_based_double",
        "expression": "[7, 8, 9][dyn(0.0)]",
        "bindings": {},
        "expected_value": 7,
        "source": f"{SOURCE_TREE}/lists.textproto::index::zero_based_double",
        "_exclusion_reason": "profile-rejects-dyn",
        "_exclusion_citation": "eng-plan CQ1 (Relay CEL profile excludes dyn type)",
        "_exclusion_note": "uses dyn() to widen a double index; dyn is out of Relay's CEL profile",
    },
    {
        "vector_id": "timestamps/timestamp_conversions/toString_timestamp",
        "expression": "string(timestamp('2009-02-13T23:31:30Z'))",
        "bindings": {},
        "expected_value": "2009-02-13T23:31:30Z",
        "source": f"{SOURCE_TREE}/timestamps.textproto::timestamp_conversions::toString_timestamp",
        "_exclusion_reason": "profile-rejects-timestamp",
        "_exclusion_citation": "eng-plan CQ1 (Relay CEL profile excludes native timestamp())",
        "_exclusion_note": "constructs a native timestamp(); out of Relay's CEL profile",
    },
    {
        "vector_id": "timestamps/duration_conversions/toString_duration",
        "expression": "string(duration('1000000s'))",
        "bindings": {},
        "expected_value": "1000000s",
        "source": f"{SOURCE_TREE}/timestamps.textproto::duration_conversions::toString_duration",
        "_exclusion_reason": "profile-rejects-duration",
        "_exclusion_citation": "eng-plan CQ1 (Relay CEL profile excludes native duration())",
        "_exclusion_note": "constructs a native duration(); out of Relay's CEL profile",
    },
)

# Files covered by MANIFEST.sha256 (must match the drift checker + test:
# everything under cel-spec/ except PINNED_COMMIT.txt and MANIFEST.sha256
# and test_*/_*/*.pyc).
MANIFEST_FILES = (
    ".upstream-pins.json",
    "celspec_vectors.json",
    "relay-profile-filter.yaml",
    "dropped-candidates.json",
)


# ---------------------------------------------------------------------------
# textproto tokenizer + recursive-descent parser (subset).
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>[\s,;]+)
  | (?P<comment>\#[^\n]*)
  | (?P<string>[bBrR]?"(?:\\.|[^"\\])*"|[bBrR]?'(?:\\.|[^'\\])*')
  | (?P<extname>\[[^\]]*\])
  | (?P<lbrace>\{)
  | (?P<rbrace>\})
  | (?P<colon>:)
  | (?P<number>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.VERBOSE,
)
# Note: the optional [bBrR] string prefix (bytes/raw literals) and the
# [type.url] proto-Any extension-field token are NOT present in the clean
# INCLUDED_SOURCE_FILES; they exist so timestamps.textproto (which packs
# proto Any in later tests) tokenizes for EXCLUDED-vector validation.


def _unquote(tok: str) -> str:
    """Strip an optional b/B/r/R prefix and surrounding quotes, then
    decode escapes. Plain quoted strings are unaffected."""
    if len(tok) >= 2 and tok[0] in "bBrR" and tok[1] in "\"'":
        tok = tok[1:]
    return _unescape(tok[1:-1])


def _tokenize(text: str) -> list[tuple[str, str]]:
    toks: list[tuple[str, str]] = []
    i = 0
    n = len(text)
    while i < n:
        m = _TOKEN_RE.match(text, i)
        if not m:
            raise ValueError(f"tokenize failure at {i}: {text[i:i + 40]!r}")
        i = m.end()
        kind = m.lastgroup
        # Every alternative in _TOKEN_RE is a named group, so a successful
        # match always sets lastgroup to a non-None group name. Assert the
        # invariant so the tuple value type narrows from `str | None` to `str`.
        assert kind is not None
        if kind in ("ws", "comment"):
            continue
        toks.append((kind, m.group()))
    return toks


def _unescape(s: str) -> str:
    # Decode into a BYTE buffer, then UTF-8 decode once at the end.
    # cel-spec encodes non-ASCII string_value bytes as a run of \xHH (and
    # octal) escapes that together form a UTF-8 sequence -- e.g. a cat
    # emoji is `\xf0\x9f\x90\xb1`. Emitting one Python char per byte
    # (chr(0xf0)...) produces mojibake; the bytes must be reassembled and
    # decoded as UTF-8. Literal characters and \u/\U escapes are emitted
    # as their UTF-8 encoding so the whole buffer is valid UTF-8.
    buf = bytearray()
    i = 0
    n = len(s)
    simple = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b",
              "f": "\f", "v": "\v", '"': '"', "'": "'", "\\": "\\", "?": "?"}
    while i < n:
        c = s[i]
        if c != "\\":
            buf.extend(c.encode("utf-8"))
            i += 1
            continue
        i += 1
        e = s[i]
        if e in simple:
            buf.extend(simple[e].encode("utf-8"))
            i += 1
        elif e == "x":
            j = i + 1
            while j < n and j < i + 3 and s[j] in "0123456789abcdefABCDEF":
                j += 1
            buf.append(int(s[i + 1:j], 16))
            i = j
        elif e == "u":
            buf.extend(chr(int(s[i + 1:i + 5], 16)).encode("utf-8"))
            i += 5
        elif e == "U":
            buf.extend(chr(int(s[i + 1:i + 9], 16)).encode("utf-8"))
            i += 9
        elif e in "01234567":
            j = i
            while j < n and j < i + 3 and s[j] in "01234567":
                j += 1
            buf.append(int(s[i:j], 8))
            i = j
        else:
            buf.extend(e.encode("utf-8"))
            i += 1
    return buf.decode("utf-8", "replace")


class _Parser:
    def __init__(self, toks: list[tuple[str, str]]):
        self.toks = toks
        self.pos = 0

    def _peek(self) -> tuple[Any, Any]:
        return self.toks[self.pos] if self.pos < len(self.toks) else (None, None)

    def parse_message(self) -> dict[str, Any]:
        msg: dict[str, Any] = {}
        while True:
            kind, val = self._peek()
            if kind is None or kind == "rbrace":
                break
            # `extname` is a proto-Any extension field name, e.g.
            # [type.googleapis.com/google.protobuf.Duration]; treat it as
            # an ordinary field name.
            if kind not in ("ident", "extname"):
                raise ValueError(f"expected field ident, got {kind}:{val!r}")
            self.pos += 1
            name = val
            k2, _ = self._peek()
            if k2 == "colon":
                self.pos += 1
                k3, v3 = self._peek()
                if k3 == "lbrace":
                    self.pos += 1
                    sub = self.parse_message()
                    self._expect("rbrace")
                    self._add(msg, name, sub)
                elif k3 == "string":
                    parts: list[str] = []
                    while self._peek()[0] == "string":
                        _, sv = self._peek()
                        parts.append(_unquote(sv))
                        self.pos += 1
                    self._add(msg, name, "".join(parts))
                else:
                    self.pos += 1
                    self._add(msg, name, self._scalar(k3, v3))
            elif k2 == "lbrace":
                self.pos += 1
                sub = self.parse_message()
                self._expect("rbrace")
                self._add(msg, name, sub)
            else:
                raise ValueError(f"unexpected token after field {name}: {k2}")
        return msg

    def _scalar(self, kind: str, val: str) -> Any:
        if kind == "string":
            return _unquote(val)
        if kind == "number":
            return float(val) if any(ch in val for ch in ".eE") else int(val)
        if kind == "ident":
            if val == "true":
                return True
            if val == "false":
                return False
            return val
        raise ValueError(f"bad scalar {kind}:{val!r}")

    def _add(self, msg: dict[str, Any], name: str, value: Any) -> None:
        if name in msg:
            if not isinstance(msg[name], list):
                msg[name] = [msg[name]]
            msg[name].append(value)
        else:
            msg[name] = value

    def _expect(self, kind: str) -> None:
        k, v = self._peek()
        if k != kind:
            raise ValueError(f"expected {kind}, got {k}:{v!r}")
        self.pos += 1


def _aslist(x: Any) -> list[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


# ---------------------------------------------------------------------------
# Value decoding + profile classification.
# ---------------------------------------------------------------------------

class _Unsafe(Exception):
    pass


def _decode_value(v: dict[str, Any]) -> Any:
    if not isinstance(v, dict):
        raise _Unsafe(f"non-message value: {v!r}")
    if "int64_value" in v:
        return int(v["int64_value"])
    if "double_value" in v:
        # Finite doubles are in profile (Relay's CEL profile rejects only
        # double-precision EDGE cases). NaN/Inf are not JSON-roundtrippable
        # and are dropped. Parity verification against both runtimes is the
        # backstop for any value the two evaluators format differently.
        d = float(v["double_value"])
        if d != d or d in (float("inf"), float("-inf")):
            raise _Unsafe("non-finite double")
        return d
    if "bool_value" in v:
        return bool(v["bool_value"])
    if "string_value" in v:
        return str(v["string_value"])
    if "null_value" in v:
        return None
    if "list_value" in v:
        lv = v["list_value"] or {}
        return [_decode_value(e) for e in _aslist(lv.get("values"))]
    if "map_value" in v:
        mv = v["map_value"] or {}
        out: dict[str, Any] = {}
        for entry in _aslist(mv.get("entries")):
            key = _decode_value(entry["key"])
            if not isinstance(key, str):
                raise _Unsafe("non-string map key")
            out[key] = _decode_value(entry["value"])
        return out
    raise _Unsafe(f"out-of-profile value kind: {sorted(v.keys())}")


def _strip_string_bodies(expr: str) -> str:
    """Return the expression with the CONTENTS of every string literal
    removed but the quote characters kept (e.g. b"xy" -> b"", "dyn(" ->
    "", 'ab' -> ''). Profile checks run on this code-only form so a
    pattern that appears only INSIDE a string body (a string value, not a
    token) is never misclassified as an out-of-profile construct.

    RAW strings (an r/R appears in the b/B/r/R prefix, e.g. r"...", rb'...')
    do NOT process backslash escapes, so a raw string ending in a
    backslash before its delimiter terminates AT that delimiter. Treating
    \\" as an escaped quote there would over-consume into following code
    and hide a denied token (e.g. r"a\\" + dyn(0)). The prefix is inspected
    to decide whether escapes apply."""
    out: list[str] = []
    i = 0
    n = len(expr)
    while i < n:
        c = expr[i]
        if c in "\"'":
            quote = c
            # Inspect the b/B/r/R prefix (max 2 chars) immediately before
            # the quote, but only if it is a real string prefix (not the
            # tail of an identifier). A raw prefix disables escapes.
            prefix = ""
            k = i - 1
            while k >= 0 and expr[k] in "bBrR" and len(prefix) < 2:
                prefix = expr[k] + prefix
                k -= 1
            if k >= 0 and (expr[k].isalnum() or expr[k] == "_"):
                prefix = ""  # glued to an identifier; not a string prefix
            is_raw = "r" in prefix.lower()
            out.append(quote)
            i += 1
            while i < n and expr[i] != quote:
                if (not is_raw) and expr[i] == "\\" and i + 1 < n:
                    i += 2  # skip escaped char inside a non-raw string body
                    continue
                i += 1
            if i < n:  # closing quote
                out.append(quote)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _expr_in_profile(expr: str) -> bool:
    code = _strip_string_bodies(expr)
    if any(s in code for s in _EXPR_DENY_SUBSTR):
        return False
    return _EXPR_DENY_RE.search(code) is None


# ---------------------------------------------------------------------------
# Fetch + extract + verify.
# ---------------------------------------------------------------------------

def _fetch(
    sha: str, cache_dir: Path, names: tuple[str, ...] = INCLUDED_SOURCE_FILES
) -> dict[str, str]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    out: dict[str, str] = {}
    for name in names:
        cached = cache_dir / f"{sha}__{name}"
        if cached.exists():
            out[name] = cached.read_text(encoding="utf-8")
            continue
        url = RAW_BASE.format(sha=sha, name=name)
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - fixed host
            if resp.status != 200:
                raise RuntimeError(f"fetch {url} -> HTTP {resp.status}")
            text = resp.read().decode("utf-8")
        cached.write_text(text, encoding="utf-8")
        out[name] = text
    return out


def _extract(files_text: dict[str, str]) -> list[dict[str, Any]]:
    cands: list[dict[str, Any]] = []
    for name, text in files_text.items():
        top = _Parser(_tokenize(text)).parse_message()
        for sec in _aslist(top.get("section")):
            sname = sec.get("name")
            for t in _aslist(sec.get("test")):
                tname = t.get("name")
                expr = t.get("expr")
                if not (
                    isinstance(expr, str)
                    and isinstance(sname, str)
                    and isinstance(tname, str)
                ):
                    continue
                if "bindings" in t or "type_env" in t or "container" in t:
                    continue
                if "eval_error" in t or "value" not in t:
                    continue
                if not _expr_in_profile(expr):
                    continue
                try:
                    golden = _decode_value(t["value"])
                except _Unsafe:
                    continue
                cands.append(
                    {"file": name, "section": sname, "test": tname, "expr": expr, "golden": golden}
                )
    return cands


def _validate_excluded(files_text: dict[str, str]) -> None:
    """Validate every curated EXCLUDED vector against the real upstream
    record, so a hardcoded excluded entry cannot carry fabricated or
    stale provenance (its expr / expected_value / source must match the
    upstream test it names). Raises SystemExit on any mismatch."""

    # Index upstream tests by (file, section, test) -> (expr, golden).
    index: dict[tuple[str, str, str], tuple[str, Any]] = {}
    for name, text in files_text.items():
        top = _Parser(_tokenize(text)).parse_message()
        for sec in _aslist(top.get("section")):
            sname = sec.get("name")
            for t in _aslist(sec.get("test")):
                tname = t.get("name")
                expr = t.get("expr")
                if not (
                    isinstance(expr, str)
                    and isinstance(sname, str)
                    and isinstance(tname, str)
                ):
                    continue
                try:
                    golden = _decode_value(t["value"]) if "value" in t else _SENTINEL
                except _Unsafe:
                    golden = _SENTINEL
                index[(name, sname, tname)] = (expr, golden)

    errors: list[str] = []
    for e in EXCLUDED_VECTORS:
        src = e["source"]
        # source is "tests/simple/testdata/<file>::<section>::<test>"
        try:
            rel, sectest = src.split("::", 1)
            section, test = sectest.split("::", 1)
            fname = rel.rsplit("/", 1)[-1]
        except ValueError:
            errors.append(f"{e['vector_id']}: malformed source {src!r}")
            continue
        up = index.get((fname, section, test))
        if up is None:
            errors.append(
                f"{e['vector_id']}: upstream case {fname}::{section}::{test} not found "
                f"at the pinned commit"
            )
            continue
        up_expr, up_golden = up
        if up_expr != e["expression"]:
            errors.append(
                f"{e['vector_id']}: expression mismatch\n      curated:  {e['expression']!r}\n"
                f"      upstream: {up_expr!r}"
            )
        if up_golden is not _SENTINEL and up_golden != e["expected_value"]:
            errors.append(
                f"{e['vector_id']}: expected_value mismatch (curated "
                f"{e['expected_value']!r} != upstream {up_golden!r})"
            )
    if errors:
        raise SystemExit(
            "EXCLUDED vector validation failed (fabricated/stale provenance):\n  "
            + "\n  ".join(errors)
        )


def _to_python(value: Any, celtypes: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, celtypes.BoolType):
        return bool(value)
    if isinstance(value, celtypes.IntType):
        return int(value)
    if isinstance(value, celtypes.DoubleType):
        return float(value)
    if isinstance(value, celtypes.StringType):
        return str(value)
    if isinstance(value, celtypes.ListType | list | tuple):
        return [_to_python(v, celtypes) for v in value]
    if isinstance(value, celtypes.MapType | dict):
        return {str(k): _to_python(v, celtypes) for k, v in value.items()}
    if isinstance(value, bool | int | float | str):
        return value
    raise TypeError(type(value).__name__)


def _verify(cands: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    import celpy.celtypes as celtypes
    from relay_contracts import RELAY_UDFS, RelayCelEvaluator

    ev = RelayCelEvaluator(udfs=RELAY_UDFS)
    py: dict[int, Any] = {}
    for i, c in enumerate(cands):
        try:
            py[i] = _to_python(ev.evaluate(c["expr"], {}), celtypes)
        except Exception:  # noqa: BLE001
            py[i] = _SENTINEL
    # cel-js batch.
    vectors = [
        {"vector_id": str(i), "expression": c["expr"], "bindings": {}}
        for i, c in enumerate(cands)
    ]
    proc = subprocess.run(
        ["node", str(CELJS_RUNNER)],
        input=json.dumps({"vectors": vectors}).encode(),
        capture_output=True, cwd=str(REPO_ROOT), timeout=300, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError("cel-js runner failed: " + proc.stderr.decode()[:2000])
    ts: dict[int, Any] = {int(r["vector_id"]): (r["value"] if r.get("ok") else _SENTINEL)
                          for r in json.loads(proc.stdout.decode())["results"]}
    verified: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for i, c in enumerate(cands):
        pv = py.get(i, _SENTINEL)
        tv = ts.get(i, _SENTINEL)
        if pv == c["golden"] and tv == c["golden"]:
            verified.append(c)
        else:
            dropped.append(
                {"file": c["file"], "section": c["section"], "test": c["test"],
                 "expr": c["expr"], "golden": c["golden"], "py": pv, "ts": tv}
            )
    # Report dropped candidates LOUDLY. A candidate is statically in
    # profile (passed _expr_in_profile + has a decodable golden) yet one
    # runtime disagrees with the upstream golden. Most are cel-js feature
    # gaps (cel-js 0.8.x lacks some CEL builtins), which legitimately fall
    # outside the verified profile -- but a NEW drop after a previously
    # clean run can signal a real cel-python/cel-js regression silently
    # shrinking the corpus. Surfacing them keeps that visible.
    if dropped:
        sys.stderr.write(
            f"[build] dropped {len(dropped)} in-profile candidate(s) on "
            f"runtime/golden mismatch (cel-js feature gaps expected; a NEW "
            f"increase may signal a regression):\n"
        )
        for d in dropped:
            py_s = "<err>" if d["py"] is _SENTINEL else repr(d["py"])
            ts_s = "<err>" if d["ts"] is _SENTINEL else repr(d["ts"])
            sys.stderr.write(
                f"  - {d['file']}::{d['section']}::{d['test']}  expr={d['expr']!r} "
                f"golden={d['golden']!r} py={py_s} ts={ts_s}\n"
            )
    return verified, dropped


_SENTINEL = object()


# ---------------------------------------------------------------------------
# Render output files.
# ---------------------------------------------------------------------------

def _vector_id(c: dict[str, Any]) -> str:
    stem = c["file"].replace(".textproto", "")
    return f"{stem}/{c['section']}/{c['test']}"


def _build_vectors_doc(sha: str, verified: list[dict[str, Any]]) -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []
    for c in verified:
        vid = _vector_id(c)
        vectors.append({
            "vector_id": vid,
            "expression": c["expr"],
            "bindings": {},
            "expected_value": c["golden"],
            "source": f"{SOURCE_TREE}/{c['file']}::{c['section']}::{c['test']}",
        })
    for e in EXCLUDED_VECTORS:
        vectors.append({
            "vector_id": e["vector_id"],
            "expression": e["expression"],
            "bindings": e["bindings"],
            "expected_value": e["expected_value"],
            "source": e["source"],
        })
    return {
        "_doc": (
            "W17.3 cel-spec conformance vectors (VAL-W17-010..014). Generated by "
            "scripts/build-celspec-corpus.py -- DO NOT hand-edit. Every INCLUDED "
            "vector is a verbatim google/cel-spec testdata case at the commit in "
            "_pinned_commit_sha: 'expression' and 'expected_value' are copied from "
            "the upstream test's expr/value, and 'source' is the upstream "
            "file::section::test path, so a diff against upstream is mechanically "
            "auditable. Only self-contained (no-binding) cases inside Relay's CEL "
            "profile are included, and only after cel-python AND cel-js both "
            "reproduce the upstream golden. EXCLUDED vectors are also real upstream "
            "cases; their expressions use features Relay's profile rejects (dyn / "
            "timestamp / duration) and are classified in relay-profile-filter.yaml. "
            "Regenerate with: uv run python scripts/build-celspec-corpus.py"
        ),
        "_schema_version": 1,
        "_source_repo": SOURCE_REPO,
        "_source_tree": SOURCE_TREE,
        "_celspec_tag_compat": CELSPEC_TAG_COMPAT,
        "_pinned_commit_sha": sha,
        "vectors": vectors,
    }


def _build_profile_filter(verified: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append("# W17.3 Relay CEL profile filter (VAL-W17-011).")
    lines.append("#")
    lines.append("# GENERATED by scripts/build-celspec-corpus.py -- DO NOT hand-edit.")
    lines.append("#")
    lines.append("# Partitions every vector in celspec_vectors.json into two disjoint")
    lines.append("# sets. 'included' vectors are inside Relay's CEL profile; cel-python")
    lines.append("# AND cel-js both reproduce the upstream golden (enforced by")
    lines.append("# tests/conformance/cel-spec/test_w17_3_celspec_corpus.py). 'excluded'")
    lines.append("# vectors are real upstream cases whose expressions use a feature the")
    lines.append("# profile rejects; each carries a 'reason' from the closed enum and a")
    lines.append("# 'citation'.")
    lines.append("#")
    lines.append("# Closed enum for 'reason' (kept in sync with the validator at")
    lines.append("# test_w17_3_celspec_corpus.py::")
    lines.append("#   test_profile_filter_excluded_entries_carry_reason_and_citation):")
    lines.append("#   - profile-rejects-dyn")
    lines.append("#   - profile-rejects-timestamp")
    lines.append("#   - profile-rejects-duration")
    lines.append("#   - profile-rejects-protobuf-message")
    lines.append("#   - profile-rejects-regex-backreference")
    lines.append("#   - profile-rejects-bytes-literal")
    lines.append("#   - profile-rejects-double-precision-edge")
    lines.append("#   - profile-rejects-uint-arithmetic")
    lines.append("#   - upstream-vector-uses-untyped-bindings")
    lines.append("#   - profile-rejects-macro-with-side-effect-shadow")
    lines.append("")
    lines.append("included:")
    for c in verified:
        vid = _vector_id(c)
        note = (
            f"upstream {c['file']} {c['section']}/{c['test']} "
            "(cel-python and cel-js match golden)"
        )
        lines.append(f"  - vector_id: {vid}")
        lines.append(f"    note: {note}")
    lines.append("")
    lines.append("excluded:")
    for e in EXCLUDED_VECTORS:
        lines.append(f"  - vector_id: {e['vector_id']}")
        lines.append(f"    reason: {e['_exclusion_reason']}")
        lines.append(f"    citation: \"{e['_exclusion_citation']}\"")
    lines.append("")
    return "\n".join(lines)


def _render_vectors_json(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def _build_dropped_doc(sha: str, dropped: list[dict[str, Any]]) -> str:
    """Render the audit list of in-profile candidates the runtime/golden
    parity check dropped (committed alongside the corpus so a NEW drop is
    visible in the PR diff). Deterministic ordering for stable diffs."""
    items = sorted(
        dropped, key=lambda d: (d["file"], d["section"], d["test"])
    )
    out_items: list[dict[str, Any]] = []
    for d in items:
        out_items.append({
            "source": f"{SOURCE_TREE}/{d['file']}::{d['section']}::{d['test']}",
            "expression": d["expr"],
            "upstream_golden": d["golden"],
            "cel_python": "<error>" if d["py"] is _SENTINEL else d["py"],
            "cel_js": "<error>" if d["ts"] is _SENTINEL else d["ts"],
        })
    doc = {
        "_doc": (
            "W17.3 cel-spec parity-dropped candidates (audit artifact). Each "
            "entry is an upstream testdata case that passed the static profile "
            "filter and has a profile-safe golden, but at least one of cel-python "
            "/ cel-js disagreed with the upstream golden -- so it was NOT included "
            "in celspec_vectors.json. Tracked in git (and digested in MANIFEST.sha256) "
            "so a NEW drop is visible as a PR diff and reviewable as a potential "
            "regression. Generated by scripts/build-celspec-corpus.py -- DO NOT "
            "hand-edit."
        ),
        "_schema_version": 1,
        "_pinned_commit_sha": sha,
        "dropped": out_items,
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def _build_manifest(
    vectors_json: str, profile_yaml: str, dropped_json: str
) -> str:
    digests: dict[str, str] = {}
    for rel in MANIFEST_FILES:
        if rel == "celspec_vectors.json":
            data = vectors_json.encode("utf-8")
        elif rel == "relay-profile-filter.yaml":
            data = profile_yaml.encode("utf-8")
        elif rel == "dropped-candidates.json":
            data = dropped_json.encode("utf-8")
        else:
            data = (CELSPEC_DIR / rel).read_bytes()
        digests[rel] = hashlib.sha256(data).hexdigest()
    header = [
        "# W17.3 cel-spec corpus integrity manifest (VAL-W17-010).",
        "#",
        "# GENERATED by scripts/build-celspec-corpus.py -- DO NOT hand-edit.",
        "# sha256sum-compatible format: '<64 hex><two spaces><relative path>'.",
        "# Verify with: cd tests/conformance/cel-spec && sha256sum -c MANIFEST.sha256",
        "# (shasum -a 256 -c on macOS). PINNED_COMMIT.txt and MANIFEST.sha256 are",
        "# excluded by design (the pin is validated by the nightly git ls-remote",
        "# check; the manifest cannot contain its own digest).",
        "",
    ]
    body = [f"{digests[rel]}  {rel}" for rel in MANIFEST_FILES]
    return "\n".join(header + body) + "\n"


def _read_pinned_sha() -> str:
    for raw in PINNED_COMMIT_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            return line
    raise SystemExit("PINNED_COMMIT.txt has no non-comment SHA line")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sha", help="cel-spec commit SHA (default: read PINNED_COMMIT.txt)")
    ap.add_argument("--cache-dir", default=str(Path(tempfile.gettempdir()) / "relay-celspec-cache"))
    ap.add_argument(
        "--check",
        action="store_true",
        help="diff against committed files; exit 1 on drift",
    )
    ap.add_argument(
        "--allow-shrink",
        action="store_true",
        help="permit the regenerated included-vector count to drop below the "
        "committed count (otherwise a shrink is a hard error: it usually means "
        "a parser/profile/runtime regression silently lost coverage)",
    )
    args = ap.parse_args(argv)

    sha = args.sha or _read_pinned_sha()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise SystemExit(f"SHA must be 40-char lowercase hex, got {sha!r}")

    cache_dir = Path(args.cache_dir)
    files_text = _fetch(sha, cache_dir)
    cands = _extract(files_text)
    sys.stderr.write(f"[build] extracted {len(cands)} profile candidates\n")
    verified, dropped = _verify(cands)
    sys.stderr.write(f"[build] verified {len(verified)} included vectors (py==ts==golden)\n")
    if len(verified) < 25:
        raise SystemExit(f"only {len(verified)} verified vectors; floor is 25")

    # Validate the curated EXCLUDED vectors against the real upstream
    # record (no fabricated/stale exclusions).
    _validate_excluded(_fetch(sha, cache_dir, EXCLUDED_SOURCE_FILES))

    # Anti-shrink guard (PER VECTOR ID, not a total count): never let a
    # regeneration silently DROP a previously-included vector. A count
    # comparison can be masked when an unrelated newly-recovered vector
    # offsets a lost one, so compare the SET of committed included
    # vector_ids against the regenerated set and fail on any that vanished.
    # A drop almost always means a parser/profile/runtime regression;
    # require --allow-shrink to override (e.g. a pin bump that legitimately
    # removed upstream cases).
    excluded_ids = {e["vector_id"] for e in EXCLUDED_VECTORS}
    committed_included_ids: set[str] = set()
    if VECTORS_PATH.exists():
        try:
            committed = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
            committed_included_ids = {
                vid
                for v in committed.get("vectors", [])
                if (vid := v.get("vector_id")) and vid not in excluded_ids
            }
        except (json.JSONDecodeError, OSError):
            committed_included_ids = set()
    new_ids = {_vector_id(c) for c in verified}
    vanished = sorted(committed_included_ids - new_ids)
    if vanished and not args.allow_shrink:
        raise SystemExit(
            f"{len(vanished)} previously-included vector(s) no longer verify "
            f"(a regression usually). Re-run with --allow-shrink if intentional "
            f"(e.g. a pin bump that removed upstream cases):\n  "
            + "\n  ".join(vanished)
        )

    doc = _build_vectors_doc(sha, verified)
    vectors_json = _render_vectors_json(doc)
    profile_yaml = _build_profile_filter(verified)
    dropped_json = _build_dropped_doc(sha, dropped)
    manifest = _build_manifest(vectors_json, profile_yaml, dropped_json)

    if args.check:
        drift = []
        for path, fresh in (
            (VECTORS_PATH, vectors_json),
            (PROFILE_FILTER_PATH, profile_yaml),
            (DROPPED_PATH, dropped_json),
            (MANIFEST_PATH, manifest),
        ):
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current != fresh:
                drift.append(str(path.relative_to(REPO_ROOT)))
        if drift:
            sys.stderr.write(
                "[drift] committed corpus differs from regenerated: "
                + ", ".join(drift) + "\n"
            )
            return 1
        sys.stderr.write("[check] corpus matches upstream regeneration\n")
        return 0

    VECTORS_PATH.write_text(vectors_json, encoding="utf-8")
    PROFILE_FILTER_PATH.write_text(profile_yaml, encoding="utf-8")
    DROPPED_PATH.write_text(dropped_json, encoding="utf-8")
    MANIFEST_PATH.write_text(manifest, encoding="utf-8")
    sys.stderr.write(
        f"[build] wrote {VECTORS_PATH.name} ({len(verified) + len(EXCLUDED_VECTORS)} vectors), "
        f"{PROFILE_FILTER_PATH.name}, {DROPPED_PATH.name} ({len(dropped)} dropped), "
        f"{MANIFEST_PATH.name}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
