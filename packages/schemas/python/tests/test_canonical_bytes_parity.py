"""Py<->TS byte parity for the schemas-package canonical serializer
(re-hunt schemas-03/-04/-05 + the CRITICAL ensure_ascii divergence).

The schemas package emits canonical JSON via ``canonical_bytes`` (Python) and
``canonicalBytes`` (TS). Both MUST produce byte-identical UTF-8 for the same
logical value -- a JCS byte-determinism keystone (CLAUDE.md #11/#16: any Py<->TS
divergence is a P0). Three divergences were closed:

  * schemas-05 / CRITICAL: the two dedicated serializers
    (serialize_event_log_entry_canonical / serialize_replay_fixture_canonical)
    omitted ensure_ascii=False/allow_nan=False, so a non-ASCII field diverged
    (Python \\uXXXX vs TS raw UTF-8) and a non-finite float emitted invalid-JSON
    NaN/Infinity. Both now route through canonical_bytes.
  * schemas-03: bare floats / >2^53 integers. Python json.dumps used repr-style
    float formatting (1e16 -> "1e+16") while TS String() uses ECMA-262
    ("10000000000000000"); >2^53 integers lose precision in JS. canonical_bytes
    now ECMA-262-encodes finite floats and REJECTS integer values outside the JS
    safe-integer range (the TS guard throws identically).
  * schemas-04: object keys sorted by Unicode code point (Python) vs UTF-16 code
    unit (TS) diverged for non-BMP keys. canonical_bytes now sorts by UTF-16.

These assert the FIXED behavior directly (deterministic bytes) and, when Node +
the TS dist are present, byte-equality across the runtimes.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from relay_schemas.envelopes import canonical_bytes

pytestmark = pytest.mark.plumbing

_REPO_ROOT = Path(__file__).resolve().parents[4]
_TS_DIST = _REPO_ROOT / "packages" / "schemas" / "typescript" / "dist" / "envelopes.js"

# Values whose canonical bytes MUST match Py<->TS exactly. None carries an
# unsafe integer or non-finite float (those are reject-parity, tested below).
_PARITY_VALUES = [
    {"event_type": "run.recué", "payload": {"model": "café", "city": "São Paulo"}},
    {"msg": "héllo 世界", "emoji": "🚀", "tab": "a\tb\nc"},
    {"count": 12.5, "ratio": 0.1, "milli": 0.001, "whole": 1.0, "neg": -0.0},
    {"small": 1e-7, "tiny": 1.5e-10, "frac": 0.333},
    {"\U0001F600": 1, "￿": 2, "a": 3},  # SMP key sorts before U+FFFF (UTF-16)
    {"nested": {"z": [1, 2, {"b": None, "a": True}], "y": "x"}},
    {"ints": [0, -1, 42, 9007199254740991, -9007199254740991]},  # JS-safe ints
]

# Expected canonical bytes (the FIXED output) -- deterministic, no Node needed.
_EXPECTED = {
    'whole_float_is_ecma262': ({"whole": 1.0}, b'{"whole":1}'),
    'neg_zero_collapses': ({"z": -0.0}, b'{"z":0}'),
    'small_float_exponential': ({"e": 1e-7}, b'{"e":1e-7}'),
    'non_ascii_raw_utf8': ({"m": "café"}, '{"m":"café"}'.encode("utf-8")),
    # UTF-16 sort: U+1F600 (high surrogate 0xD83D) sorts BEFORE U+FFFF.
    'utf16_key_sort': (
        {"￿": 2, "\U0001F600": 1},
        '{"\U0001F600":1,"￿":2}'.encode("utf-8"),
    ),
}


@pytest.mark.parametrize("name", sorted(_EXPECTED))
def test_canonical_bytes_fixed_output(name: str) -> None:
    value, expected = _EXPECTED[name]
    assert canonical_bytes(value) == expected, name


@pytest.mark.parametrize(
    "bad",
    [
        {"x": float("nan")},
        {"x": float("inf")},
        {"x": float("-inf")},
        {"x": 2**53},  # first unsafe positive integer
        {"x": -(2**53)},
        {"x": 10**18},
        {"x": 1e16},  # integer-valued exponential float, > 2^53
        {"x": 6.022e23},
    ],
)
def test_canonical_bytes_rejects_unrepresentable_numbers(bad: dict) -> None:
    """Non-finite floats and integer values outside the JS safe-integer range
    are rejected fail-closed so the canonical form never diverges Py<->TS (the
    TS canonicalJsonStringify throws on the same inputs)."""
    with pytest.raises((ValueError, TypeError)):
        canonical_bytes(bad)


def _node() -> str | None:
    return shutil.which("node")


@pytest.mark.parametrize("value", _PARITY_VALUES)
def test_canonical_bytes_byte_equal_typescript_via_node(value: dict) -> None:
    """canonical_bytes(Py) is byte-identical to canonicalBytes(TS) for the same
    value. Skipped when Node or the TS dist are unavailable (offline tier-1);
    authoritative when present."""
    node = _node()
    if node is None or not _TS_DIST.exists():
        pytest.skip("node binary or TS dist (packages/schemas/typescript/dist) absent")
    script = (
        f"import {{ canonicalBytes }} from {json.dumps(str(_TS_DIST))};\n"
        "let buf='';process.stdin.on('data',c=>buf+=c);"
        "process.stdin.on('end',()=>{const v=JSON.parse(buf);"
        "process.stdout.write(Buffer.from(canonicalBytes(v)).toString('hex'));});"
    )
    proc = subprocess.run(
        [node, "--input-type=module", "-e", script],
        input=json.dumps(value, ensure_ascii=False),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"node failed: rc={proc.returncode} {proc.stderr!r}")
    ts_hex = proc.stdout.strip()
    assert canonical_bytes(value).hex() == ts_hex, (
        f"Py<->TS canonical byte divergence for {value!r}:\n"
        f"  PY {canonical_bytes(value).hex()}\n  TS {ts_hex}"
    )
