"""w6.3 -- Relay UDF behavioral tests + cross-runtime parity corpus.

Pins the v0.1 semantics of:
  - relay.coverage(trace, step_name) -> bool
  - relay.tool_arg(call, key) -> any
  - relay.schema_match(payload, schema) -> bool

The same fixtures land in
``tests/conformance/cel/relay_udfs_parity.json`` so the TypeScript
mirror (cel-js side, packages/contracts-typescript/test/) asserts
byte-identical JCS output for the exact same input set. This is the
W6.3 Relay Conformance Corpus contribution required by eng plan
CQ1 line 147-150.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from relay_contracts import (
    jcs_canonicalize,
    relay_coverage,
    relay_schema_match,
    relay_tool_arg,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
PARITY_CORPUS = REPO_ROOT / "tests" / "conformance" / "cel" / "relay_udfs_parity.json"


def _b64(value: Any) -> str:
    return base64.b64encode(jcs_canonicalize(value)).decode("ascii")


# ---------------------------------------------------------------------------
# relay.coverage
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
def test_coverage_finds_named_step() -> None:
    trace = {"steps": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}
    assert relay_coverage(trace, "b") is True


@pytest.mark.plumbing
def test_coverage_missing_step_returns_false() -> None:
    trace = {"steps": [{"name": "a"}]}
    assert relay_coverage(trace, "z") is False


@pytest.mark.plumbing
def test_coverage_empty_steps_returns_false() -> None:
    assert relay_coverage({"steps": []}, "a") is False


@pytest.mark.plumbing
def test_coverage_no_steps_field_returns_false() -> None:
    assert relay_coverage({}, "a") is False


@pytest.mark.plumbing
def test_coverage_non_mapping_trace_returns_false() -> None:
    for trace in ([], "abc", 42, None, True):
        assert relay_coverage(trace, "a") is False


@pytest.mark.plumbing
def test_coverage_steps_must_be_list_or_tuple() -> None:
    # str is iterable but is not a list-of-step-objects.
    assert relay_coverage({"steps": "abc"}, "a") is False
    # dict is iterable but is not a list-of-step-objects.
    assert relay_coverage({"steps": {"a": 1}}, "a") is False


@pytest.mark.plumbing
def test_coverage_step_name_must_be_string() -> None:
    trace = {"steps": [{"name": "a"}]}
    for bad in (1, None, True, [], {}):
        assert relay_coverage(trace, bad) is False


@pytest.mark.plumbing
def test_coverage_skips_malformed_step_entries() -> None:
    trace = {"steps": [None, 1, "x", {"name": "match"}, {"other": "no"}]}
    assert relay_coverage(trace, "match") is True
    assert relay_coverage(trace, "no") is False


@pytest.mark.plumbing
def test_coverage_is_codepoint_exact() -> None:
    # Case-sensitive, byte-exact.
    trace = {"steps": [{"name": "Step.A"}]}
    assert relay_coverage(trace, "Step.A") is True
    assert relay_coverage(trace, "step.a") is False
    assert relay_coverage(trace, "STEP.A") is False


# ---------------------------------------------------------------------------
# relay.tool_arg
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
def test_tool_arg_returns_value_when_present() -> None:
    call = {"args": {"k": "v", "n": 1, "b": True, "x": None}}
    assert relay_tool_arg(call, "k") == "v"
    assert relay_tool_arg(call, "n") == 1
    assert relay_tool_arg(call, "b") is True
    assert relay_tool_arg(call, "x") is None


@pytest.mark.plumbing
def test_tool_arg_missing_key_returns_none() -> None:
    call = {"args": {"a": 1}}
    assert relay_tool_arg(call, "missing") is None


@pytest.mark.plumbing
def test_tool_arg_no_args_field_returns_none() -> None:
    assert relay_tool_arg({"tool_name": "x"}, "k") is None


@pytest.mark.plumbing
def test_tool_arg_non_mapping_call_returns_none() -> None:
    for call in ([], "abc", 42, None, True):
        assert relay_tool_arg(call, "k") is None


@pytest.mark.plumbing
def test_tool_arg_args_must_be_mapping() -> None:
    for args in ([1, 2], "abc", 42, True):
        assert relay_tool_arg({"args": args}, "k") is None


@pytest.mark.plumbing
def test_tool_arg_key_must_be_string() -> None:
    call = {"args": {"k": "v"}}
    for bad in (1, None, True, [], {}):
        assert relay_tool_arg(call, bad) is None


@pytest.mark.plumbing
def test_tool_arg_returns_nested_value_unchanged() -> None:
    inner = {"deep": [1, 2, 3]}
    call = {"args": {"obj": inner}}
    assert relay_tool_arg(call, "obj") is inner  # identity preserved


# ---------------------------------------------------------------------------
# relay.schema_match
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
def test_schema_match_empty_schema_matches_anything() -> None:
    for payload in (None, True, 0, "x", [], {}, {"a": 1}):
        assert relay_schema_match(payload, {}) is True


@pytest.mark.plumbing
def test_schema_match_type_string() -> None:
    assert relay_schema_match("hi", {"type": "string"}) is True
    assert relay_schema_match(1, {"type": "string"}) is False
    assert relay_schema_match(None, {"type": "string"}) is False


@pytest.mark.plumbing
def test_schema_match_type_integer_excludes_bool() -> None:
    assert relay_schema_match(1, {"type": "integer"}) is True
    assert relay_schema_match(True, {"type": "integer"}) is False
    assert relay_schema_match(1.5, {"type": "integer"}) is False


@pytest.mark.plumbing
def test_schema_match_type_number_accepts_int_and_float_excludes_bool() -> None:
    assert relay_schema_match(1, {"type": "number"}) is True
    assert relay_schema_match(1.5, {"type": "number"}) is True
    assert relay_schema_match(True, {"type": "number"}) is False


@pytest.mark.plumbing
def test_schema_match_number_rejects_nan_inf() -> None:
    """NaN / +Inf / -Inf MUST be rejected for ``"type": "number"``.

    The TypeScript mirror uses ``Number.isFinite`` and rejects them.
    Python had previously accepted them via ``isinstance(int | float)``;
    same payload returned True in Python but False in TS, breaking the
    byte-identical JCS parity guarantee promised in the module docstring.
    """
    assert relay_schema_match(float("nan"), {"type": "number"}) is False
    assert relay_schema_match(float("inf"), {"type": "number"}) is False
    assert relay_schema_match(float("-inf"), {"type": "number"}) is False
    # Plain finite values still pass.
    assert relay_schema_match(42, {"type": "number"}) is True
    assert relay_schema_match(3.14, {"type": "number"}) is True
    # Booleans still excluded (subclass-of-int gotcha).
    assert relay_schema_match(True, {"type": "number"}) is False
    assert relay_schema_match(False, {"type": "number"}) is False


@pytest.mark.plumbing
def test_schema_match_type_boolean() -> None:
    assert relay_schema_match(True, {"type": "boolean"}) is True
    assert relay_schema_match(False, {"type": "boolean"}) is True
    assert relay_schema_match(0, {"type": "boolean"}) is False
    assert relay_schema_match(1, {"type": "boolean"}) is False


@pytest.mark.plumbing
def test_schema_match_type_null() -> None:
    assert relay_schema_match(None, {"type": "null"}) is True
    assert relay_schema_match(0, {"type": "null"}) is False
    assert relay_schema_match("", {"type": "null"}) is False


@pytest.mark.plumbing
def test_schema_match_type_object_and_array() -> None:
    assert relay_schema_match({"a": 1}, {"type": "object"}) is True
    assert relay_schema_match([1, 2], {"type": "array"}) is True
    assert relay_schema_match("abc", {"type": "array"}) is False
    assert relay_schema_match([1, 2], {"type": "object"}) is False


@pytest.mark.plumbing
def test_schema_match_required_keys() -> None:
    schema = {"type": "object", "required": ["a", "b"]}
    assert relay_schema_match({"a": 1, "b": 2}, schema) is True
    assert relay_schema_match({"a": 1}, schema) is False
    assert relay_schema_match({}, schema) is False


@pytest.mark.plumbing
def test_schema_match_properties_validate_present() -> None:
    schema = {
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"type": "string"}},
    }
    assert relay_schema_match({"a": 1, "b": "x"}, schema) is True
    assert relay_schema_match({"a": "wrong"}, schema) is False
    # Additional properties permitted by default (mirrors JSON Schema).
    assert relay_schema_match({"a": 1, "extra": True}, schema) is True


@pytest.mark.plumbing
def test_schema_match_array_items() -> None:
    schema = {"type": "array", "items": {"type": "integer"}}
    assert relay_schema_match([1, 2, 3], schema) is True
    assert relay_schema_match([1, "two", 3], schema) is False
    assert relay_schema_match([], schema) is True  # empty array is fine


@pytest.mark.plumbing
def test_schema_match_unknown_type_rejected() -> None:
    assert relay_schema_match("x", {"type": "rainbow"}) is False


@pytest.mark.plumbing
def test_schema_match_non_mapping_schema_rejected() -> None:
    for bad in ("hi", 1, None, [1, 2]):
        assert relay_schema_match("x", bad) is False


# ---------------------------------------------------------------------------
# Cross-runtime parity corpus
# ---------------------------------------------------------------------------

# Corpus shape: each case has
#   - "udf": one of "relay.coverage" | "relay.tool_arg" | "relay.schema_match"
#   - "name": stable unique identifier
#   - "args": list of two JSON-roundtrippable inputs to the UDF
#   - "py_jcs_b64": base64 of jcs_canonicalize(udf(*args)) -- the
#     canonical Python output that the TS mirror must reproduce
#     byte-for-byte


def _coverage_cases() -> list[dict[str, Any]]:
    base_trace = {"steps": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}
    return [
        {
            "udf": "relay.coverage",
            "name": "coverage_match",
            "args": [base_trace, "b"],
            "py_jcs_b64": _b64(relay_coverage(base_trace, "b")),
        },
        {
            "udf": "relay.coverage",
            "name": "coverage_no_match",
            "args": [base_trace, "z"],
            "py_jcs_b64": _b64(relay_coverage(base_trace, "z")),
        },
        {
            "udf": "relay.coverage",
            "name": "coverage_empty_steps",
            "args": [{"steps": []}, "a"],
            "py_jcs_b64": _b64(relay_coverage({"steps": []}, "a")),
        },
        {
            "udf": "relay.coverage",
            "name": "coverage_no_steps_field",
            "args": [{}, "a"],
            "py_jcs_b64": _b64(relay_coverage({}, "a")),
        },
        {
            "udf": "relay.coverage",
            "name": "coverage_non_mapping_trace",
            "args": [[1, 2], "a"],
            "py_jcs_b64": _b64(relay_coverage([1, 2], "a")),
        },
        {
            "udf": "relay.coverage",
            "name": "coverage_skips_malformed",
            "args": [
                {"steps": [None, 1, "x", {"name": "match"}, {"other": "no"}]},
                "match",
            ],
            "py_jcs_b64": _b64(
                relay_coverage(
                    {"steps": [None, 1, "x", {"name": "match"}, {"other": "no"}]},
                    "match",
                )
            ),
        },
        {
            "udf": "relay.coverage",
            "name": "coverage_case_sensitive",
            "args": [{"steps": [{"name": "Foo"}]}, "foo"],
            "py_jcs_b64": _b64(
                relay_coverage({"steps": [{"name": "Foo"}]}, "foo")
            ),
        },
    ]


def _tool_arg_cases() -> list[dict[str, Any]]:
    base = {"tool_name": "t", "args": {"k": "v", "n": 1, "b": True, "x": None}}
    return [
        {
            "udf": "relay.tool_arg",
            "name": "tool_arg_string",
            "args": [base, "k"],
            "py_jcs_b64": _b64(relay_tool_arg(base, "k")),
        },
        {
            "udf": "relay.tool_arg",
            "name": "tool_arg_int",
            "args": [base, "n"],
            "py_jcs_b64": _b64(relay_tool_arg(base, "n")),
        },
        {
            "udf": "relay.tool_arg",
            "name": "tool_arg_bool",
            "args": [base, "b"],
            "py_jcs_b64": _b64(relay_tool_arg(base, "b")),
        },
        {
            "udf": "relay.tool_arg",
            "name": "tool_arg_null_value",
            "args": [base, "x"],
            "py_jcs_b64": _b64(relay_tool_arg(base, "x")),
        },
        {
            "udf": "relay.tool_arg",
            "name": "tool_arg_missing_key",
            "args": [base, "missing"],
            "py_jcs_b64": _b64(relay_tool_arg(base, "missing")),
        },
        {
            "udf": "relay.tool_arg",
            "name": "tool_arg_no_args_field",
            "args": [{"tool_name": "x"}, "k"],
            "py_jcs_b64": _b64(relay_tool_arg({"tool_name": "x"}, "k")),
        },
        {
            "udf": "relay.tool_arg",
            "name": "tool_arg_non_mapping_call",
            "args": [[1, 2], "k"],
            "py_jcs_b64": _b64(relay_tool_arg([1, 2], "k")),
        },
        {
            "udf": "relay.tool_arg",
            "name": "tool_arg_nested_object",
            "args": [{"args": {"obj": {"a": [1, 2, 3]}}}, "obj"],
            "py_jcs_b64": _b64(
                relay_tool_arg({"args": {"obj": {"a": [1, 2, 3]}}}, "obj")
            ),
        },
    ]


def _schema_match_cases() -> list[dict[str, Any]]:
    return [
        {
            "udf": "relay.schema_match",
            "name": "schema_empty",
            "args": [{"x": 1}, {}],
            "py_jcs_b64": _b64(relay_schema_match({"x": 1}, {})),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_string_match",
            "args": ["hello", {"type": "string"}],
            "py_jcs_b64": _b64(relay_schema_match("hello", {"type": "string"})),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_string_mismatch",
            "args": [1, {"type": "string"}],
            "py_jcs_b64": _b64(relay_schema_match(1, {"type": "string"})),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_integer_excludes_bool",
            "args": [True, {"type": "integer"}],
            "py_jcs_b64": _b64(relay_schema_match(True, {"type": "integer"})),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_number_accepts_int",
            "args": [42, {"type": "number"}],
            "py_jcs_b64": _b64(relay_schema_match(42, {"type": "number"})),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_number_accepts_float",
            "args": [3.14, {"type": "number"}],
            "py_jcs_b64": _b64(relay_schema_match(3.14, {"type": "number"})),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_null_match",
            "args": [None, {"type": "null"}],
            "py_jcs_b64": _b64(relay_schema_match(None, {"type": "null"})),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_object_required_present",
            "args": [
                {"a": 1, "b": "x"},
                {"type": "object", "required": ["a", "b"]},
            ],
            "py_jcs_b64": _b64(
                relay_schema_match(
                    {"a": 1, "b": "x"},
                    {"type": "object", "required": ["a", "b"]},
                )
            ),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_object_required_missing",
            "args": [
                {"a": 1},
                {"type": "object", "required": ["a", "b"]},
            ],
            "py_jcs_b64": _b64(
                relay_schema_match(
                    {"a": 1},
                    {"type": "object", "required": ["a", "b"]},
                )
            ),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_object_properties_match",
            "args": [
                {"a": 1, "b": "x", "extra": True},
                {
                    "type": "object",
                    "properties": {
                        "a": {"type": "integer"},
                        "b": {"type": "string"},
                    },
                },
            ],
            "py_jcs_b64": _b64(
                relay_schema_match(
                    {"a": 1, "b": "x", "extra": True},
                    {
                        "type": "object",
                        "properties": {
                            "a": {"type": "integer"},
                            "b": {"type": "string"},
                        },
                    },
                )
            ),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_array_items_match",
            "args": [[1, 2, 3], {"type": "array", "items": {"type": "integer"}}],
            "py_jcs_b64": _b64(
                relay_schema_match(
                    [1, 2, 3], {"type": "array", "items": {"type": "integer"}}
                )
            ),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_array_items_mismatch",
            "args": [[1, "two"], {"type": "array", "items": {"type": "integer"}}],
            "py_jcs_b64": _b64(
                relay_schema_match(
                    [1, "two"], {"type": "array", "items": {"type": "integer"}}
                )
            ),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_unknown_type",
            "args": ["x", {"type": "rainbow"}],
            "py_jcs_b64": _b64(relay_schema_match("x", {"type": "rainbow"})),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_non_mapping",
            "args": ["x", "not-a-schema"],
            "py_jcs_b64": _b64(relay_schema_match("x", "not-a-schema")),
        },
        {
            "udf": "relay.schema_match",
            "name": "schema_nested_object",
            "args": [
                {"owner": {"id": 7, "name": "alice"}},
                {
                    "type": "object",
                    "properties": {
                        "owner": {
                            "type": "object",
                            "required": ["id"],
                            "properties": {
                                "id": {"type": "integer"},
                                "name": {"type": "string"},
                            },
                        },
                    },
                },
            ],
            "py_jcs_b64": _b64(
                relay_schema_match(
                    {"owner": {"id": 7, "name": "alice"}},
                    {
                        "type": "object",
                        "properties": {
                            "owner": {
                                "type": "object",
                                "required": ["id"],
                                "properties": {
                                    "id": {"type": "integer"},
                                    "name": {"type": "string"},
                                },
                            },
                        },
                    },
                )
            ),
        },
    ]


def _build_corpus() -> dict[str, Any]:
    cases = _coverage_cases() + _tool_arg_cases() + _schema_match_cases()
    return {"version": 1, "cases": cases}


@pytest.mark.plumbing
def test_parity_corpus_file_is_in_sync_with_python_outputs() -> None:
    """The on-disk parity corpus MUST match the freshly-computed
    Python outputs. If a UDF's behavior changes, the corpus must be
    regenerated and the TS mirror updated -- this test forces that
    coupling.

    Regenerate via: ``uv run python scripts/regen-relay-udfs-parity.py``
    (no scripts/ entry yet; for now run this test with PYTEST_REGEN=1
    to overwrite the corpus deliberately).
    """

    expected = _build_corpus()
    if not PARITY_CORPUS.exists():
        PARITY_CORPUS.parent.mkdir(parents=True, exist_ok=True)
        PARITY_CORPUS.write_text(
            json.dumps(expected, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    actual = json.loads(PARITY_CORPUS.read_text(encoding="utf-8"))
    # Compare structure with a stable ordering.
    assert actual == expected, (
        "VAL-W6-020..022: relay_udfs_parity.json is stale. The Python "
        "UDF outputs no longer match the corpus -- regenerate the "
        "corpus AND the TS mirror's expectations."
    )
