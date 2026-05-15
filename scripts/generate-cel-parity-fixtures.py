"""W6.2 cross-language CEL JCS parity fixture generator (VAL-W6-014).

Generates ``tests/conformance/cel/parity_fixtures.json`` containing input
values and the corresponding cel-python ``jcs_canonicalize`` byte output
encoded as base64. The TS test
(``packages/contracts-typescript/test/w6_2_014_jcs_canonical.test.ts``)
reads this file and asserts ``sha256(ts_jcs_bytes) == sha256(py_jcs_bytes)``
for every case.

Storing the Python-side BYTES (not just the input) is load-bearing: if
we re-canonicalised at test time we would never catch encoder
divergence between cel-python and the TS encoder. The Python encoder
runs once at fixture-generation time; the TS test compares against
its frozen output.

Happy path:

    $ uv run python scripts/generate-cel-parity-fixtures.py
    [check] wrote 25 cases to tests/conformance/cel/parity_fixtures.json
    exit 0

Idempotency:

    Running twice produces a byte-identical file (assuming cel-python
    and the canonicalizer have not changed). The generator is
    deterministic: the case list is hard-coded; no clock, no PRNG.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from relay_contracts import jcs_canonicalize

SCHEMA_VERSION = "relay.cel.parity_fixtures.v1"


def _repo_root() -> Path:
    # scripts/ lives at the relay/ repo root.
    return Path(__file__).resolve().parents[1]


def _output_path() -> Path:
    return _repo_root() / "tests" / "conformance" / "cel" / "parity_fixtures.json"


# ---------------------------------------------------------------------------
# Case list. Each case is (name, input_value). The corresponding cel-python
# JCS bytes are computed at generation time. Add cases here when the
# encoders gain new edge cases to validate.
# ---------------------------------------------------------------------------

CASES: list[tuple[str, Any]] = [
    # --- Primitives -------------------------------------------------------
    ("null", None),
    ("bool_true", True),
    ("bool_false", False),
    ("int_zero", 0),
    ("int_positive", 42),
    ("int_negative", -7),
    ("int_safe_max", 9007199254740992),
    ("int_safe_min", -9007199254740992),
    ("float_one", 1.0),
    ("float_neg_zero", -0.0),
    ("float_half", 0.5),
    ("float_negative", -3.14),
    ("float_small_decimal", 0.1),
    ("string_empty", ""),
    ("string_simple", "relay"),
    ("string_with_quote", 'a"b'),
    ("string_with_backslash", "a\\b"),
    ("string_with_newline", "line1\nline2"),
    ("string_with_tab", "col1\tcol2"),
    ("string_with_del", "\x7f"),
    # Latin-1 e-acute U+00E9 in the data; source escaped to keep the
    # file ASCII-only per CLAUDE.md "ASCII-Safe Source".
    ("string_with_unicode_bmp", "caf\u00e9"),
    # --- Containers -------------------------------------------------------
    ("list_empty", []),
    ("list_of_ints", [1, 2, 3]),
    ("list_mixed", [1, "two", True, None, 3.14]),
    ("list_nested", [[1, 2], [3, 4]]),
    ("dict_empty", {}),
    ("dict_simple", {"a": 1, "b": 2}),
    ("dict_unsorted_keys", {"z": 1, "a": 2, "m": 3}),
    ("dict_nested", {"outer": {"inner": [1, 2, 3]}}),
    # --- Realistic Relay payload (mirrors test_jcs_known_digest_for_fixed_input)
    (
        "relay_known_good",
        {"name": "relay", "ok": True, "count": 3, "items": [1, 2, 3]},
    ),
    # --- Coverage / contract-evaluation result shapes --------------------
    (
        "coverage_result",
        {
            "covered": ["step.a", "step.b"],
            "missing": ["step.c"],
            "ratio": 0.6666666666666666,
        },
    ),
    (
        "tool_args_capture",
        {
            "tool": "search.web",
            "args": {"query": "relay", "limit": 10},
            "trace_span_id": "0123456789abcdef",
        },
    ),
]


def _generate_cases() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, value in CASES:
        py_bytes = jcs_canonicalize(value)
        out.append(
            {
                "name": name,
                "input": value,
                "py_jcs_b64": base64.b64encode(py_bytes).decode("ascii"),
            }
        )
    return out


def _atomic_write_bytes(target: Path, payload: bytes) -> None:
    """Write payload to target via write-tmp + rename.

    Mirrors the local_atomic_file_write primitive's safety contract
    (write to sibling tempfile, fsync, atomic rename) without requiring
    the import path to the sidecar app from a developer script.
    """

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".tmp", dir=str(target.parent)
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, str(target))
    except BaseException:
        # Best-effort cleanup; never leak the tempfile.
        if Path(tmp_path).exists():
            os.unlink(tmp_path)
        raise


def main() -> int:
    cases = _generate_cases()
    fixtures = {
        "schema_version": SCHEMA_VERSION,
        "cases": cases,
    }
    # Pretty-print with stable key order so the file diffs cleanly when
    # cases are added.
    payload = (
        json.dumps(fixtures, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("ascii")
    out_path = _output_path()
    _atomic_write_bytes(out_path, payload)
    rel = out_path.relative_to(_repo_root())
    print(f"[check] wrote {len(cases)} cases to {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
