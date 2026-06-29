"""Keystone invariant #11/#16 (Py<->TS JCS byte parity): GENERATIVE property.

The Relay trust anchor rests on the claim that the Python JCS canonicalizer
(``relay_contracts.canonical.jcs_canonicalize``) and the TypeScript
canonicalizer (``packages/contracts-typescript/src/canonical.ts``,
``jcsCanonicalize``) produce BYTE-IDENTICAL output for every JSON-compatible
value -- OR reject the value identically with the SAME structured error code.
Any divergence silently breaks cross-runtime signature verification and is a
P0 (CLAUDE.md keystone invariant #11, banned pattern #16).

The example-based corpus (``verifier/tests/test_w10_3_jcs_corpus.py``,
``contracts-typescript/test/w6_2_014_jcs_canonical.test.ts``) pins specific
vectors. This test is the universally-quantified counterpart: Hypothesis
generates random JSON-compatible values -- nested objects/arrays, strings with
non-ASCII + BMP + supplementary-plane code points, control characters, quotes
and backslashes (escape paths), arbitrary-precision integers, IEEE-754 floats
(incl. negative zero / subnormals / wide exponents), booleans and null -- and a
single test drives BOTH runtimes: Python in-process and TypeScript through a
Node subprocess that imports the compiled ``dist/canonical.js``.

Property asserted for every generated value ``v``:

  * If Python ``jcs_canonicalize(v)`` succeeds, TS ``jcsCanonicalize`` succeeds
    AND the two byte strings are equal.
  * If Python raises ``CanonicalEncodingError`` (the only structured rejection
    reachable from JSON-transportable input: a supplementary-plane object KEY,
    code ``RELAY-CANON-NON-BMP-KEY``), TS rejects with the SAME ``code``.

Type fidelity across the Python->Node boundary is preserved by a fully tagged
transport (``{"k": <kind>, "v": <payload>}``): integers travel as decimal
strings and are reconstructed as JS ``bigint`` (so arbitrary precision -- well
beyond 2^53 -- is faithful; bare JSON numbers would silently round). Floats
travel as JSON numbers (Python ``repr`` and JS ``JSON.parse`` both round-trip
the exact IEEE-754 double). Strings and object keys travel as JSON strings
(surrogate pairs preserved), so supplementary-plane code points survive intact
to drive the shared rejection path.

The harness mirrors the Node-subprocess pattern used by
``packages/sdk-python/tests/test_redaction_parity.py``.

ASCII-only per CLAUDE.md "ASCII-Safe Source": all non-ASCII test inputs are
constructed at runtime via ``chr(<codepoint>)``; the source stays pure ASCII.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from relay_contracts.canonical import (
    CanonicalEncodingError,
    jcs_canonicalize,
)

# ---------------------------------------------------------------------------
# TS harness: invoke the compiled canonicalizer in a Node subprocess.
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_TS_DIST = (
    _REPO_ROOT / "packages" / "contracts-typescript" / "dist" / "canonical.js"
)


def _find_node() -> str | None:
    return shutil.which("node")


# Node ESM worker. Reads {"cases": [<transport-node>, ...]} from stdin,
# reconstructs each native JS value from the tagged transport, runs the
# TS JCS canonicalizer, and writes a JSON array of per-case outcomes:
#   {"ok": true,  "hex": "<utf8-bytes-hex>"}        on success
#   {"ok": false, "code": "<error-code>"}           on rejection
# Per-case try/catch so one rejecting value never aborts the batch.
_TS_WORKER = """
import {{ jcsCanonicalize, CanonicalEncodingError }} from {dist_json};

function fromTransport(node) {{
  const k = node.k;
  if (k === "null") return null;
  if (k === "bool") return node.v;
  if (k === "int") return BigInt(node.v);
  if (k === "float") return node.v;
  if (k === "str") return node.v;
  if (k === "arr") return node.v.map(fromTransport);
  if (k === "obj") {{
    const o = {{}};
    for (const pair of node.v) {{
      o[pair[0]] = fromTransport(pair[1]);
    }}
    return o;
  }}
  throw new Error("bad transport kind: " + String(k));
}}

const stdin = await new Promise((resolve) => {{
  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (c) => {{ buf += c; }});
  process.stdin.on("end", () => resolve(buf));
}});

const input = JSON.parse(stdin);
const out = [];
for (const node of input.cases) {{
  try {{
    const value = fromTransport(node);
    const bytes = jcsCanonicalize(value);
    out.push({{ ok: true, hex: Buffer.from(bytes).toString("hex") }});
  }} catch (err) {{
    const code =
      err && err.code
        ? err.code
        : "ERR:" + (err && err.name ? err.name : String(err));
    out.push({{ ok: false, code: code }});
  }}
}}
process.stdout.write(JSON.stringify(out));
"""


def _to_transport(v: Any) -> dict[str, Any]:
    """Encode a Python JSON-compatible value into the tagged transport form.

    bool is checked before int (bool subclasses int in Python). Integers are
    carried as decimal strings to survive the Node boundary at arbitrary
    precision; floats as JSON numbers (faithful IEEE-754 round-trip).
    """
    if v is None:
        return {"k": "null"}
    if isinstance(v, bool):
        return {"k": "bool", "v": v}
    if isinstance(v, int):
        return {"k": "int", "v": str(v)}
    if isinstance(v, float):
        return {"k": "float", "v": v}
    if isinstance(v, str):
        return {"k": "str", "v": v}
    if isinstance(v, list):
        return {"k": "arr", "v": [_to_transport(x) for x in v]}
    if isinstance(v, dict):
        return {
            "k": "obj",
            "v": [[key, _to_transport(val)] for key, val in v.items()],
        }
    raise TypeError(f"untransportable type {type(v).__name__}")


def _ts_outcomes_via_node(cases: list[Any]) -> list[dict[str, Any]] | None:
    """Canonicalize ``cases`` through the TS engine; return per-case outcomes.

    Returns ``None`` when Node or the compiled TS dist are unavailable so the
    caller skips (offline / pre-build) rather than flaking on environment.
    """
    node = _find_node()
    if node is None or not _TS_DIST.exists():
        return None
    script = _TS_WORKER.format(dist_json=json.dumps(str(_TS_DIST)))
    payload = {"cases": [_to_transport(v) for v in cases]}
    proc = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(payload, ensure_ascii=True, allow_nan=False),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"node TS subprocess failed: rc={proc.returncode} "
            f"stderr={proc.stderr!r}"
        )
    outcomes = json.loads(proc.stdout.strip())
    assert isinstance(outcomes, list) and len(outcomes) == len(cases), (
        f"TS returned {len(outcomes)} outcomes for {len(cases)} cases"
    )
    return outcomes


def _py_outcome(v: Any) -> dict[str, Any]:
    """Python in-process canonicalization outcome, normalized to the same
    shape the Node worker emits."""
    try:
        return {"ok": True, "bytes": jcs_canonicalize(v)}
    except CanonicalEncodingError as exc:
        return {"ok": False, "code": exc.code}


def _assert_parity(cases: list[Any]) -> None:
    ts_outcomes = _ts_outcomes_via_node(cases)
    if ts_outcomes is None:
        pytest.skip(
            "node binary or TS dist "
            "(packages/contracts-typescript/dist/canonical.js) not "
            "available; build with `npm run build` in that package."
        )
    for v, ts in zip(cases, ts_outcomes, strict=True):
        py = _py_outcome(v)
        # Same accept/reject verdict.
        assert py["ok"] == ts["ok"], (
            f"verdict divergence for {v!r}: python ok={py['ok']} "
            f"ts ok={ts['ok']} (ts={ts!r})"
        )
        if py["ok"]:
            ts_bytes = bytes.fromhex(ts["hex"])
            assert py["bytes"] == ts_bytes, (
                f"JCS BYTE divergence for {v!r}:\n"
                f"  python={py['bytes']!r}\n"
                f"  ts    ={ts_bytes!r}"
            )
        else:
            # Both reject -- structured codes MUST match.
            assert py["code"] == ts["code"], (
                f"reject-code divergence for {v!r}: python={py['code']!r} "
                f"ts={ts['code']!r}"
            )


# ---------------------------------------------------------------------------
# Hypothesis strategies for JSON-compatible values.
# ---------------------------------------------------------------------------

# Value-string code points: ASCII (incl. control chars 0x00-0x1F, quote 0x22,
# backslash 0x5C -> escape paths), Latin-1 supplement, combining diacritics
# (NFC parity), BMP CJK/symbol, and supplementary-plane emoji (allowed in
# VALUES; only KEYS are screened). Surrogate range (0xD800-0xDFFF) excluded:
# lone surrogates are not JSON-transportable.
_value_codepoint = st.one_of(
    st.integers(min_value=0x00, max_value=0x7F),
    st.integers(min_value=0x80, max_value=0xFF),
    st.sampled_from([0x300, 0x301, 0x308, 0x327]),
    st.sampled_from([0x20AC, 0x2603, 0x4E2D, 0x6587]),
    st.sampled_from([0x1F600, 0x1F4A9, 0x10000, 0x10FFFF]),
)
_value_str = st.lists(_value_codepoint, max_size=10).map(
    lambda cps: "".join(chr(c) for c in cps)
)

# Object-key code points: printable ASCII (incl. quote/backslash escape paths)
# and a few BMP non-ASCII keys -- PLUS a low-weight supplementary-plane code
# point (U+1F600) that MUST drive both runtimes into the shared rejection
# path (RELAY-CANON-NON-BMP-KEY). Keys are sorted by the encoders, so this
# also exercises cross-runtime key-ordering parity.
_key_codepoint = st.one_of(
    st.integers(min_value=0x20, max_value=0x7E),
    st.sampled_from([0xE9, 0xFC, 0x20AC, 0x4E2D]),
    # ~1-in-9 weight toward a non-BMP key to exercise reject parity.
    st.just(0x1F600),
)
_key = st.lists(_key_codepoint, min_size=0, max_size=5).map(
    lambda cps: "".join(chr(c) for c in cps)
)

_leaf = st.one_of(
    st.none(),
    st.booleans(),
    # Arbitrary-precision integers, well beyond +/-2^53.
    st.integers(min_value=-(2**80), max_value=2**80),
    st.floats(allow_nan=False, allow_infinity=False),
    _value_str,
)

_json_value = st.recursive(
    _leaf,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(keys=_key, values=children, max_size=5),
    ),
    max_leaves=15,
)

# Deterministic anchor cases prepended to EVERY batch so the load-bearing
# vectors run on every Hypothesis example regardless of shrinking: nested
# structure, multi-key sort, escape paths, big int, float edges, a non-BMP
# object key (reject parity), and a non-BMP VALUE (must still encode).
_ANCHOR_CASES: list[Any] = [
    {"b": 1, "a": [1, 2, {"c": "x"}], "A": True, "z": None},
    {"b": 2, "B": 2, "a": 3, "A": 4},  # uppercase-before-lowercase sort
    "tab\tquote\"slash\\nul\x00",
    {"k" + chr(0x00E9): "caf" + chr(0x00E9)},  # BMP non-ASCII key + value
    2**70,
    -(2**70),
    [-0.0, 0.0, 1.0, -1.0, 0.5, 1e21, 1e-7, 1e10, 12345678901234.5],
    {"emoji": chr(0x1F600)},  # non-BMP VALUE: allowed, must encode
    {"a" + chr(0x1F600): 1},  # non-BMP KEY: both runtimes MUST reject
    {"outer": {chr(0x1F600) + "nested": 1}},  # nested non-BMP KEY: reject
    {},
    [],
]


@pytest.mark.plumbing
@settings(max_examples=40, deadline=None)
@given(batch=st.lists(_json_value, min_size=0, max_size=18))
def test_jcs_python_typescript_byte_parity(batch: list[Any]) -> None:
    """Py and TS JCS canonicalizers agree byte-for-byte (or reject with the
    same code) for every generated JSON-compatible value.

    Keystone invariant #11/#16: cross-runtime byte equality is the trust
    anchor's load-bearing property; a single divergence is a P0.
    """
    _assert_parity(_ANCHOR_CASES + batch)
