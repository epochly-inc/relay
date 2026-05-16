"""W17.4 -- Per-UDF case-file generator.

Reads the existing Relay-CEL conformance corpus at
``tests/conformance/cel/relay_cel_corpus.json`` (built in W6.5) and
emits per-UDF case files at:

    tests/conformance/cel/relay-udfs/<udf_name>/case_<NNN>.json

Each emitted case carries the contract-mandated fields per
VAL-W17-015:

  - ``label``             : stable case ID (case_id from W6.5 corpus)
  - ``udf``               : UDF dotted name (e.g. "relay.coverage")
  - ``args``              : positional arg array (as in source corpus)
  - ``input_expression``  : equivalent CEL expression bound by named
                            bindings (so a CEL evaluator can exercise it)
  - ``input_bindings``    : map of binding name -> value referenced by
                            ``input_expression``
  - ``expected_output``   : JSON-decoded value of the UDF result
  - ``py_jcs_b64``        : base64(JCS bytes) for parity with the
                            W6.5 byte-golden runner
  - ``edge_category``     : optional; carried through when present

This script is deterministic and idempotent. Running it with no args
overwrites any existing case files via ``local_atomic_file_write``.
Running it with ``--check`` exits non-zero when re-generation would
produce different bytes than what is on disk.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "relay_cel_corpus.json"
OUTPUT_ROOT = REPO_ROOT / "tests" / "conformance" / "cel" / "relay-udfs"

# Mapping of UDF dotted name -> generator that builds (expression, bindings).
# We bind the args as named CEL bindings so the expression is a literal
# `relay.coverage(trace, "step_name")` form. The shapes of the binding
# values mirror the args field of the source corpus case.


def _coverage_expression(args: list[Any]) -> tuple[str, dict[str, Any]]:
    trace, step = args
    return "relay.coverage(trace, step_name)", {"trace": trace, "step_name": step}


def _tool_arg_expression(args: list[Any]) -> tuple[str, dict[str, Any]]:
    call, key = args
    return "relay.tool_arg(call, key)", {"call": call, "key": key}


def _schema_match_expression(args: list[Any]) -> tuple[str, dict[str, Any]]:
    payload, schema = args
    return "relay.schema_match(payload, schema)", {
        "payload": payload,
        "schema": schema,
    }


EXPRESSION_BUILDERS: dict[str, Any] = {
    "relay.coverage": _coverage_expression,
    "relay.tool_arg": _tool_arg_expression,
    "relay.schema_match": _schema_match_expression,
}


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Write payload to path via temp + atomic rename. Mirrors the
    semantics of `local_atomic_file_write` for test-corpus generation.
    Test data is write-once authored content (not persistent runtime
    state) so a direct file write is permitted per boundaries.md s3
    ("Test files are exempt for fixture preparation")."""

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(payload)
    tmp.replace(path)


def _decode_expected_output(py_jcs_b64: str) -> Any:
    """Decode the base64-JCS bytes back to a Python value.

    JCS is a canonical JSON form; ``json.loads`` round-trips it back to
    a Python value. Used to surface the expected_output as a structured
    JSON value rather than only as opaque bytes."""

    raw = base64.b64decode(py_jcs_b64.encode("ascii"))
    return json.loads(raw.decode("utf-8"))


def build_cases() -> dict[str, list[dict[str, Any]]]:
    """Return {udf_name: [case_dict, ...]} sorted by case label."""

    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    by_udf: dict[str, list[dict[str, Any]]] = {}
    for c in corpus["cases"]:
        if c.get("kind") != "udf_value":
            continue
        udf = c.get("udf")
        if udf not in EXPRESSION_BUILDERS:
            continue
        args = c["args"]
        expr, bindings = EXPRESSION_BUILDERS[udf](args)
        expected = _decode_expected_output(c["py_jcs_b64"])
        case: dict[str, Any] = {
            "label": c["id"],
            "udf": udf,
            "args": args,
            "input_expression": expr,
            "input_bindings": bindings,
            "expected_output": expected,
            "py_jcs_b64": c["py_jcs_b64"],
        }
        if "edge_category" in c:
            case["edge_category"] = c["edge_category"]
        if "idiom" in c:
            case["idiom"] = c["idiom"]
        by_udf.setdefault(udf, []).append(case)
    for udf in by_udf:
        by_udf[udf].sort(key=lambda c: c["label"])
    return by_udf


def render_case_bytes(case: dict[str, Any]) -> bytes:
    """Render the case file as canonical (sort_keys=True) JSON bytes."""

    return (json.dumps(case, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_all(by_udf: dict[str, list[dict[str, Any]]]) -> list[Path]:
    paths: list[Path] = []
    for udf, cases in sorted(by_udf.items()):
        udf_dir = OUTPUT_ROOT / udf
        # Wipe stale case files (everything other than the schema and
        # the README, both written below). This keeps the on-disk set
        # in lockstep with the source corpus.
        if udf_dir.exists():
            for existing in udf_dir.glob("case_*.json"):
                existing.unlink()
        for idx, case in enumerate(cases):
            out_path = udf_dir / f"case_{idx:03d}.json"
            _atomic_write_bytes(out_path, render_case_bytes(case))
            paths.append(out_path)
    return paths


def write_schema() -> Path:
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://relay.epochly.com/schemas/w17.4/udf-case.json",
        "title": "Relay-CEL Conformance Corpus -- per-UDF case (W17.4)",
        "type": "object",
        "required": [
            "label",
            "udf",
            "args",
            "input_expression",
            "input_bindings",
            "expected_output",
            "py_jcs_b64",
        ],
        "additionalProperties": False,
        "properties": {
            "label": {
                "type": "string",
                "minLength": 1,
                "description": "Stable case ID; matches W6.5 corpus case id.",
            },
            "udf": {
                "type": "string",
                "enum": [
                    "relay.coverage",
                    "relay.tool_arg",
                    "relay.schema_match",
                ],
            },
            "args": {
                "type": "array",
                "minItems": 1,
                "description": "Positional args passed to the Python UDF callable.",
            },
            "input_expression": {
                "type": "string",
                "minLength": 1,
                "description": "Equivalent CEL expression in named-binding form.",
            },
            "input_bindings": {
                "type": "object",
                "description": "Bindings referenced by input_expression.",
            },
            "expected_output": {
                "description": "JSON-decoded result of the UDF (any JSON type).",
            },
            "py_jcs_b64": {
                "type": "string",
                "minLength": 1,
                "description": "base64(JCS bytes) of expected_output (W6.5 golden).",
            },
            "edge_category": {
                "type": "string",
                "enum": ["null", "empty", "unicode", "large", "nested"],
            },
            "idiom": {"type": "string"},
        },
    }
    out_path = OUTPUT_ROOT / "case.schema.json"
    _atomic_write_bytes(
        out_path, (json.dumps(schema, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    return out_path


def write_readme(by_udf: dict[str, list[dict[str, Any]]]) -> Path:
    lines: list[str] = []
    lines.append("# W17.4 -- Per-UDF Relay-CEL conformance cases")
    lines.append("")
    lines.append(
        "Auto-generated by `scripts/generate-w17-4-udf-cases.py` from"
    )
    lines.append(
        "`tests/conformance/cel/relay_cel_corpus.json`. Do not hand-edit;"
    )
    lines.append("regenerate via:")
    lines.append("")
    lines.append("    uv run python scripts/generate-w17-4-udf-cases.py")
    lines.append("")
    lines.append(
        "Each case file conforms to `case.schema.json` and carries the"
    )
    lines.append("contract-mandated fields per VAL-W17-015:")
    lines.append("")
    lines.append("- `label`             : stable case ID")
    lines.append("- `udf`               : dotted UDF name")
    lines.append("- `args`              : positional args to Python UDF callable")
    lines.append("- `input_expression`  : equivalent CEL expression (named bindings)")
    lines.append("- `input_bindings`    : bindings referenced by input_expression")
    lines.append("- `expected_output`   : JSON-decoded result")
    lines.append("- `py_jcs_b64`        : base64(JCS bytes) golden (W6.5)")
    lines.append("")
    lines.append("## Per-UDF case counts")
    lines.append("")
    for udf, cases in sorted(by_udf.items()):
        lines.append(f"- `{udf}`: {len(cases)} cases")
    lines.append("")
    out_path = OUTPUT_ROOT / "README.md"
    _atomic_write_bytes(out_path, ("\n".join(lines)).encode("utf-8"))
    return out_path


def check_in_sync(by_udf: dict[str, list[dict[str, Any]]]) -> int:
    """Verify on-disk case files match what would be regenerated.

    Returns 0 on match, non-zero with a structured diff on stdout
    otherwise. Used by the in-tree "is the corpus stale?" guard test.
    """

    drift: list[str] = []
    for udf, cases in sorted(by_udf.items()):
        udf_dir = OUTPUT_ROOT / udf
        on_disk = sorted(udf_dir.glob("case_*.json")) if udf_dir.exists() else []
        if len(on_disk) != len(cases):
            drift.append(
                f"{udf}: on-disk={len(on_disk)} regenerated={len(cases)}"
            )
            continue
        for idx, case in enumerate(cases):
            path = udf_dir / f"case_{idx:03d}.json"
            if not path.exists():
                drift.append(f"{udf}: missing case file {path.name}")
                continue
            expected = render_case_bytes(case)
            actual = path.read_bytes()
            if expected != actual:
                exp_h = hashlib.sha256(expected).hexdigest()[:16]
                act_h = hashlib.sha256(actual).hexdigest()[:16]
                drift.append(
                    f"{path.relative_to(REPO_ROOT)}: byte drift "
                    f"(expected sha256:{exp_h} actual sha256:{act_h})"
                )
    schema_path = OUTPUT_ROOT / "case.schema.json"
    if not schema_path.exists():
        drift.append("case.schema.json missing")
    readme_path = OUTPUT_ROOT / "README.md"
    if not readme_path.exists():
        drift.append("README.md missing")
    if drift:
        print(
            "W17.4 per-UDF case files are stale; regenerate via "
            "`uv run python scripts/generate-w17-4-udf-cases.py`:"
        )
        for line in drift:
            print(f"  {line}")
        return 1
    print("W17.4 per-UDF case files are in sync.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if on-disk files differ from regeneration.",
    )
    args = parser.parse_args(argv)

    by_udf = build_cases()

    if args.check:
        return check_in_sync(by_udf)

    write_schema()
    write_readme(by_udf)
    write_all(by_udf)
    total = sum(len(c) for c in by_udf.values())
    print(
        f"W17.4: wrote {total} per-UDF case files across "
        f"{len(by_udf)} UDF directories under "
        f"{OUTPUT_ROOT.relative_to(REPO_ROOT)}/"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
