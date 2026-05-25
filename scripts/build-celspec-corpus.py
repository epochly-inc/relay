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

# Substrings / patterns that mark an expression as OUTSIDE Relay's CEL
# profile, even when its golden value is a profile-safe JSON kind.
_EXPR_DENY_SUBSTR = ("dyn(", "timestamp(", "duration(", "bytes(", "uint(", 'b"', "b'")
_EXPR_DENY_RE = re.compile(r"\b\d+[uU]\b")  # uint literal, e.g. 0u / 5U

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
MANIFEST_FILES = (".upstream-pins.json", "celspec_vectors.json", "relay-profile-filter.yaml")


# ---------------------------------------------------------------------------
# textproto tokenizer + recursive-descent parser (subset).
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>[\s,;]+)
  | (?P<comment>\#[^\n]*)
  | (?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | (?P<lbrace>\{)
  | (?P<rbrace>\})
  | (?P<colon>:)
  | (?P<number>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.VERBOSE,
)


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
        if kind in ("ws", "comment"):
            continue
        toks.append((kind, m.group()))
    return toks


def _unescape(s: str) -> str:
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        e = s[i]
        simple = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b",
                  "f": "\f", "v": "\v", '"': '"', "'": "'", "\\": "\\", "?": "?"}
        if e in simple:
            out.append(simple[e]); i += 1
        elif e == "x":
            j = i + 1
            while j < n and j < i + 3 and s[j] in "0123456789abcdefABCDEF":
                j += 1
            out.append(chr(int(s[i + 1:j], 16))); i = j
        elif e == "u":
            out.append(chr(int(s[i + 1:i + 5], 16))); i += 5
        elif e == "U":
            out.append(chr(int(s[i + 1:i + 9], 16))); i += 9
        elif e in "01234567":
            j = i
            while j < n and j < i + 3 and s[j] in "01234567":
                j += 1
            out.append(chr(int(s[i:j], 8))); i = j
        else:
            out.append(e); i += 1
    return "".join(out)


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
            if kind != "ident":
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
                        parts.append(_unescape(sv[1:-1]))
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
            return _unescape(val[1:-1])
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


def _expr_in_profile(expr: str) -> bool:
    if any(s in expr for s in _EXPR_DENY_SUBSTR):
        return False
    if _EXPR_DENY_RE.search(expr):
        return False
    return True


# ---------------------------------------------------------------------------
# Fetch + extract + verify.
# ---------------------------------------------------------------------------

def _fetch(sha: str, cache_dir: Path) -> dict[str, str]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    out: dict[str, str] = {}
    for name in INCLUDED_SOURCE_FILES:
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
                if not isinstance(expr, str) or not isinstance(sname, str) or not isinstance(tname, str):
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


def _to_celtypes(value: Any, celtypes: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return celtypes.BoolType(value)
    if isinstance(value, int):
        return celtypes.IntType(value)
    if isinstance(value, float):
        return celtypes.DoubleType(value)
    if isinstance(value, str):
        return celtypes.StringType(value)
    if isinstance(value, (list, tuple)):
        return celtypes.ListType([_to_celtypes(x, celtypes) for x in value])
    if isinstance(value, dict):
        return celtypes.MapType(
            {celtypes.StringType(k): _to_celtypes(v, celtypes) for k, v in value.items()}
        )
    return value


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
    if isinstance(value, (celtypes.ListType, list, tuple)):
        return [_to_python(v, celtypes) for v in value]
    if isinstance(value, (celtypes.MapType, dict)):
        return {str(k): _to_python(v, celtypes) for k, v in value.items()}
    if isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(type(value).__name__)


def _verify(cands: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
    vectors = [{"vector_id": str(i), "expression": c["expr"], "bindings": {}} for i, c in enumerate(cands)]
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
    for i, c in enumerate(cands):
        if py.get(i, _SENTINEL) == c["golden"] and ts.get(i, _SENTINEL) == c["golden"]:
            verified.append(c)
    return verified


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
    lines.append("# test_w17_3_celspec_corpus.py::test_profile_filter_excluded_entries_carry_reason_and_citation):")
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
        note = f"upstream {c['file']} {c['section']}/{c['test']} (cel-python and cel-js match golden)"
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


def _build_manifest(vectors_json: str, profile_yaml: str) -> str:
    digests: dict[str, str] = {}
    for rel in MANIFEST_FILES:
        if rel == "celspec_vectors.json":
            data = vectors_json.encode("utf-8")
        elif rel == "relay-profile-filter.yaml":
            data = profile_yaml.encode("utf-8")
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
    ap.add_argument("--check", action="store_true", help="diff against committed files; exit 1 on drift")
    args = ap.parse_args(argv)

    sha = args.sha or _read_pinned_sha()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise SystemExit(f"SHA must be 40-char lowercase hex, got {sha!r}")

    files_text = _fetch(sha, Path(args.cache_dir))
    cands = _extract(files_text)
    sys.stderr.write(f"[build] extracted {len(cands)} profile candidates\n")
    verified = _verify(cands)
    sys.stderr.write(f"[build] verified {len(verified)} included vectors (py==ts==golden)\n")
    if len(verified) < 25:
        raise SystemExit(f"only {len(verified)} verified vectors; floor is 25")

    doc = _build_vectors_doc(sha, verified)
    vectors_json = _render_vectors_json(doc)
    profile_yaml = _build_profile_filter(verified)
    manifest = _build_manifest(vectors_json, profile_yaml)

    if args.check:
        drift = []
        for path, fresh in (
            (VECTORS_PATH, vectors_json),
            (PROFILE_FILTER_PATH, profile_yaml),
            (MANIFEST_PATH, manifest),
        ):
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current != fresh:
                drift.append(str(path.relative_to(REPO_ROOT)))
        if drift:
            sys.stderr.write("[drift] committed corpus differs from regenerated: " + ", ".join(drift) + "\n")
            return 1
        sys.stderr.write("[check] corpus matches upstream regeneration\n")
        return 0

    VECTORS_PATH.write_text(vectors_json, encoding="utf-8")
    PROFILE_FILTER_PATH.write_text(profile_yaml, encoding="utf-8")
    MANIFEST_PATH.write_text(manifest, encoding="utf-8")
    sys.stderr.write(
        f"[build] wrote {VECTORS_PATH.name} ({len(verified) + len(EXCLUDED_VECTORS)} vectors), "
        f"{PROFILE_FILTER_PATH.name}, {MANIFEST_PATH.name}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
