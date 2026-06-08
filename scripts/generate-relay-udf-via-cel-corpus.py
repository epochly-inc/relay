"""WS-E UDF-via-CEL conformance corpus generator (M3 P3CORPUS).

Produces ``tests/conformance/cel/relay_udf_via_cel_corpus.json`` -- a NEW,
SEPARATE corpus (it does NOT read or mutate ``relay_cel_corpus.json``) that
drives all three Relay UDFs (``relay.coverage`` / ``relay.tool_arg`` /
``relay.schema_match``) THROUGH CEL (the dotted ``input_expression`` form,
e.g. ``relay.coverage(trace, "step1")``) and records the typed-canonical
golden the BUILT wasm produces for each case.

Why a separate corpus fenced to ``engines == ["wasm"]``:

  - Only the wasm can evaluate a dotted ``relay.*`` UDF call THROUGH CEL
    (cel-python's CEL parses ``relay.coverage(...)`` as a member-method with
    no matching overload -- the known provably-unbounded two-engine gap this
    cutover exists to eliminate; cf. VAL-CWC-P1HOST-015 adjudication, the
    known-failing ``test_w17_4_*`` two-engine comparison).
  - cel-js is structurally excluded (``engines == ["wasm"]`` is a hard fence
    the loader REJECTS otherwise): UDF-via-CEL parity is validated wasm +
    fixed-cel-python, NEVER cel-js.

The cross-anchor (the load-bearing parity that REPLACES the retired
two-engine ``test_w17_4`` comparison):

  - wasm-through-CEL: the dotted ``input_expression`` evaluated by the wasm
    via the Python loader with ``relay_profile=True``. Only the wasm can
    drive ``relay.*`` through CEL.
  - cel-python-direct-call: the FIXED Python callable (``relay_coverage`` /
    ``relay_tool_arg`` / ``relay_schema_match``, fixed in ``a909466``)
    invoked DIRECTLY on the plain-Python args (NOT through CEL), then
    serialized to typed-canonical via ``py_to_typed``.

  For every case the generator asserts the wasm ``value`` typed-canonical
  form EQUALS the cel-python direct-call serialized typed-canonical form.
  ANY disagreement is reported and ABORTS generation with a non-zero exit
  (a divergence is a P0; the generator never silently records a divergent
  golden).

``cel_js_parseable`` boundary flag (legacy task #20 -- the cel-js parser
bug): a case whose ``input_expression`` contains a map literal ``{...}``
with two or more keys INCLUDING a ``"type"`` key has
``cel_js_parseable == false``; otherwise ``true``. The flag is COMPUTED by
the shared ``compute_cel_js_parseable`` function (NOT hand-set), and a guard
test independently recomputes it from the expression and asserts equality
for every case. The corpus thus documents exactly which cases cel-js could
never parse.

Determinism: ``relay_udf_via_cel_corpus.json`` is emitted with sorted keys
and stable case ordering; re-running this generator against an unchanged
built wasm reproduces byte-identical JSON (the ``--check`` mode asserts the
on-disk corpus equals a fresh run).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

# Make packages/contracts importable (cel-python direct callables + py_to_typed
# + the JCS encoder) and the wasm Python loader importable.
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "packages" / "contracts" / "src"))
sys.path.insert(0, str(REPO_ROOT / "packages" / "cel-wasm" / "python"))

from relay_cel_wasm import RelayCel  # noqa: E402  -- after sys.path adjustment
from relay_contracts import (  # noqa: E402  -- after sys.path adjustment
    jcs_canonicalize,
    relay_coverage,
    relay_schema_match,
    relay_tool_arg,
)
from relay_contracts.wasm_codec import py_to_typed  # noqa: E402

CORPUS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "relay_udf_via_cel_corpus.json"
SCHEMA_VERSION = 1

# Hard structural fence: every case carries exactly this engines array. cel-js
# is structurally excluded (UDF-via-CEL parity is validated wasm +
# fixed-cel-python, never cel-js -- the locked decision).
ENGINES_FENCE: list[str] = ["wasm"]

# The 3-name UDF allowlist. No case may reference a UDF outside this set.
UDF_ALLOWLIST: tuple[str, ...] = (
    "relay.coverage",
    "relay.schema_match",
    "relay.tool_arg",
)


# ---------------------------------------------------------------------------
# cel_js_parseable boundary classifier (SHARED -- imported by the guard test)
# ---------------------------------------------------------------------------
#
# Boundary (legacy task #20, the cel-js map-literal parser bug): a CEL map
# literal ``{...}`` whose top level has >= 2 keys, one of which is the string
# key ``"type"``, is NOT parseable by cel-js. Any other expression IS.
#
# The classifier scans the expression for map literals, parses each map's
# TOP-LEVEL keys (respecting nesting and string literals), and returns False
# as soon as one qualifying map is found.


def _scan_map_literals(expression: str) -> list[str]:
    """Return the inner text of every TOP-LEVEL-and-nested map literal ``{...}``
    found in ``expression``, in source order.

    A map literal is a ``{`` ... matching ``}`` span. Braces inside string
    literals are NOT structural. Each returned span is the text BETWEEN the
    braces (exclusive), so a caller can parse that map's own top-level keys
    (and recurse on nested maps via a fresh scan).
    """
    spans: list[str] = []
    i = 0
    n = len(expression)
    while i < n:
        ch = expression[i]
        if ch in ("'", '"'):
            i = _skip_string(expression, i)
            continue
        if ch == "{":
            end = _match_close_brace(expression, i)
            # Inner text is between the braces (exclusive of both).
            spans.append(expression[i + 1 : end])
            i = i + 1  # continue scanning inside for nested maps too
            continue
        i += 1
    return spans


def _skip_string(expression: str, start: int) -> int:
    """Return the index one past the closing quote of the string literal that
    begins at ``start`` (CEL single- or double-quoted, backslash escapes).
    """
    quote = expression[start]
    i = start + 1
    n = len(expression)
    while i < n:
        c = expression[i]
        if c == "\\":
            i += 2
            continue
        if c == quote:
            return i + 1
        i += 1
    return n


def _match_close_brace(expression: str, open_idx: int) -> int:
    """Return the index of the ``}`` matching the ``{`` at ``open_idx``,
    skipping string literals and nested braces. Returns ``len`` if unmatched.
    """
    depth = 0
    i = open_idx
    n = len(expression)
    while i < n:
        c = expression[i]
        if c in ("'", '"'):
            i = _skip_string(expression, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _top_level_map_keys(inner: str) -> list[str]:
    """Parse the TOP-LEVEL keys of a map literal given its inner text (the text
    between the outer braces). Returns the list of string-literal key texts
    (the decoded key string for string keys; the raw token for non-string
    keys, which the >=2-key/"type" test never matches on).

    Splits on top-level commas (ignoring commas inside nested ``{}``, ``[]``,
    ``()``, and string literals) into ``key : value`` entries, then extracts
    the key token left of the FIRST top-level ``:``.
    """
    keys: list[str] = []
    for entry in _split_top_level(inner, ","):
        key_token = _split_top_level(entry, ":")
        if not key_token:
            continue
        raw_key = key_token[0].strip()
        if not raw_key:
            continue
        keys.append(_decode_key(raw_key))
    return keys


def _split_top_level(text: str, sep: str) -> list[str]:
    """Split ``text`` on ``sep`` at brace/bracket/paren depth 0, ignoring
    separators inside string literals. For ``:`` we split only ONCE worth of
    semantics by returning the leading segment first; callers take ``[0]``.
    """
    parts: list[str] = []
    depth = 0
    i = 0
    n = len(text)
    start = 0
    while i < n:
        c = text[i]
        if c in ("'", '"'):
            i = _skip_string(text, i)
            continue
        if c in ("{", "[", "("):
            depth += 1
        elif c in ("}", "]", ")"):
            depth -= 1
        elif depth == 0 and c == sep:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def _decode_key(raw_key: str) -> str:
    """Decode a string-literal key token to its string value; return the raw
    token unchanged for a non-string key (so it cannot match ``"type"``).
    """
    if len(raw_key) >= 2 and raw_key[0] in ("'", '"') and raw_key[-1] == raw_key[0]:
        body = raw_key[1:-1]
        # Unescape the minimal CEL escapes needed for key matching. Keys are
        # simple identifiers like "type"; this handles a backslash-escaped quote
        # defensively without a full CEL unescaper.
        return body.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
    return raw_key


def validate_case_engines(case: dict[str, Any]) -> None:
    """Validating loader: REJECT a case whose ``engines`` field is missing or is
    not EXACTLY ``["wasm"]`` (the structural fence excluding cel-js).

    This is the single source of the engines fence both the generator (on
    emit) and the guard test (on load) call. Raises ``ValueError`` on any
    violation; returns ``None`` on a valid case.
    """
    if "engines" not in case:
        raise ValueError(
            f"case {case.get('label')!r}: missing required 'engines' field "
            "(must be exactly ['wasm'])"
        )
    engines = case["engines"]
    if engines != ENGINES_FENCE:
        raise ValueError(
            f"case {case.get('label')!r}: engines must be exactly {ENGINES_FENCE!r} "
            f"(UDF-via-CEL is fenced to wasm; cel-js is structurally excluded); "
            f"got {engines!r}"
        )


def compute_cel_js_parseable(input_expression: str) -> bool:
    """Return ``False`` iff ``input_expression`` contains a map literal whose
    TOP-LEVEL keys number >= 2 and include the string key ``"type"`` (the
    legacy task #20 cel-js parser boundary); ``True`` otherwise.

    This is the SINGLE source for the boundary: both this generator and the
    guard test call it and must agree on every case.
    """
    for inner in _scan_map_literals(input_expression):
        keys = _top_level_map_keys(inner)
        if len(keys) >= 2 and "type" in keys:
            return False
    return True


# ---------------------------------------------------------------------------
# Case definitions: (label, udf, input_expression, bindings, direct_args)
#   - input_expression drives the UDF THROUGH CEL (dotted form).
#   - bindings: typed-canonical bindings fed to the wasm loader (built from
#     plain-Python values via py_to_typed for byte-faithful round-trip).
#   - direct_args: the plain-Python positional args for the cel-python
#     DIRECT-call cross-anchor (NOT through CEL).
# Each list includes at least one >=2-key map-literal-with-"type" boundary
# case (cel_js_parseable=false) per UDF.
# ---------------------------------------------------------------------------


def _coverage_cases() -> list[dict[str, Any]]:
    trace_ab = {"steps": [{"name": "alpha"}, {"name": "beta"}]}
    trace_empty: dict[str, Any] = {"steps": []}
    # Boundary case for relay.coverage: a >=2-key map-with-"type" literal in
    # the steps argument expressed INLINE in the CEL expression. cel-js cannot
    # parse the {"type": ..., "name": ...} step entry.
    boundary_steps = {"steps": [{"type": "tool", "name": "alpha"}]}
    return [
        {
            "label": "covcel_first_match_binding",
            "udf": "relay.coverage",
            "input_expression": 'relay.coverage(trace, "alpha")',
            "bindings_py": {"trace": trace_ab},
            "direct_args": [trace_ab, "alpha"],
        },
        {
            "label": "covcel_no_match_binding",
            "udf": "relay.coverage",
            "input_expression": 'relay.coverage(trace, "missing")',
            "bindings_py": {"trace": trace_ab},
            "direct_args": [trace_ab, "missing"],
        },
        {
            "label": "covcel_empty_steps_binding",
            "udf": "relay.coverage",
            "input_expression": 'relay.coverage(trace, "alpha")',
            "bindings_py": {"trace": trace_empty},
            "direct_args": [trace_empty, "alpha"],
        },
        {
            "label": "covcel_inline_single_key_steps",
            "udf": "relay.coverage",
            # Single-key map literals ({"name": ...}) -- cel-js CAN parse these.
            "input_expression": 'relay.coverage({"steps": [{"name": "x"}]}, "x")',
            "bindings_py": {},
            "direct_args": [{"steps": [{"name": "x"}]}, "x"],
        },
        {
            "label": "covcel_boundary_type_step_inline",
            "udf": "relay.coverage",
            # >=2-key map-with-"type" literal: {"type": "tool", "name": "alpha"}
            # -> cel_js_parseable=false (the boundary case for relay.coverage).
            "input_expression": (
                'relay.coverage({"steps": [{"type": "tool", "name": "alpha"}]}, "alpha")'
            ),
            "bindings_py": {},
            "direct_args": [boundary_steps, "alpha"],
        },
    ]


def _tool_arg_cases() -> list[dict[str, Any]]:
    call_str = {"args": {"k": "v"}}
    call_int = {"args": {"n": 42}}
    # Boundary case for relay.tool_arg: a >=2-key map-with-"type" literal as the
    # call argument expressed INLINE. cel-js cannot parse the
    # {"type": ..., "args": ...} call literal.
    call_boundary = {"type": "tool_call", "args": {"k": "v"}}
    return [
        {
            "label": "argcel_string_value_binding",
            "udf": "relay.tool_arg",
            "input_expression": 'relay.tool_arg(call, "k")',
            "bindings_py": {"call": call_str},
            "direct_args": [call_str, "k"],
        },
        {
            "label": "argcel_int_value_binding",
            "udf": "relay.tool_arg",
            "input_expression": 'relay.tool_arg(call, "n")',
            "bindings_py": {"call": call_int},
            "direct_args": [call_int, "n"],
        },
        {
            "label": "argcel_missing_key_null_binding",
            "udf": "relay.tool_arg",
            "input_expression": 'relay.tool_arg(call, "absent")',
            "bindings_py": {"call": call_int},
            "direct_args": [call_int, "absent"],
        },
        {
            "label": "argcel_inline_single_key_args",
            "udf": "relay.tool_arg",
            # Single-key map literals ({"args": {"k": "v"}}, {"k": "v"}) --
            # cel-js CAN parse these (no >=2-key-with-type map present).
            "input_expression": 'relay.tool_arg({"args": {"k": "v"}}, "k")',
            "bindings_py": {},
            "direct_args": [{"args": {"k": "v"}}, "k"],
        },
        {
            "label": "argcel_boundary_type_call_inline",
            "udf": "relay.tool_arg",
            # >=2-key map-with-"type" literal: {"type": "tool_call", "args": ...}
            # -> cel_js_parseable=false (the boundary case for relay.tool_arg).
            "input_expression": (
                'relay.tool_arg({"type": "tool_call", "args": {"k": "v"}}, "k")'
            ),
            "bindings_py": {},
            "direct_args": [call_boundary, "k"],
        },
    ]


def _schema_match_cases() -> list[dict[str, Any]]:
    return [
        {
            "label": "smcel_string_ok_binding",
            "udf": "relay.schema_match",
            "input_expression": "relay.schema_match(payload, schema)",
            "bindings_py": {"payload": "hello", "schema": {"type": "string"}},
            "direct_args": ["hello", {"type": "string"}],
        },
        {
            "label": "smcel_string_mismatch_binding",
            "udf": "relay.schema_match",
            "input_expression": "relay.schema_match(payload, schema)",
            "bindings_py": {"payload": 123, "schema": {"type": "string"}},
            "direct_args": [123, {"type": "string"}],
        },
        {
            "label": "smcel_inline_single_key_type",
            "udf": "relay.schema_match",
            # Single-key {"type": "integer"} map literal -- cel-js CAN parse it
            # (only ONE key, so the >=2-key-with-type boundary does not fire).
            "input_expression": 'relay.schema_match(42, {"type": "integer"})',
            "bindings_py": {},
            "direct_args": [42, {"type": "integer"}],
        },
        {
            "label": "smcel_boundary_object_required_inline",
            "udf": "relay.schema_match",
            # >=2-key map-with-"type" literal: {"type": "object", "required":[...]}
            # -> cel_js_parseable=false (the boundary case for relay.schema_match;
            # schema literals naturally carry the {type: ...} shape).
            "input_expression": (
                'relay.schema_match({"a": 1}, {"type": "object", "required": ["a"]})'
            ),
            "bindings_py": {},
            "direct_args": [{"a": 1}, {"type": "object", "required": ["a"]}],
        },
        {
            "label": "smcel_boundary_array_items_inline",
            "udf": "relay.schema_match",
            # A second >=2-key map-with-"type" boundary case:
            # {"type": "array", "items": {"type": "integer"}} -> cel_js_parseable
            # false. (The nested {"type": "integer"} is single-key and parseable
            # on its own; the OUTER 2-key-with-"type" map is the boundary.)
            "input_expression": (
                'relay.schema_match([1, 2], {"type": "array", "items": {"type": "integer"}})'
            ),
            "bindings_py": {},
            "direct_args": [[1, 2], {"type": "array", "items": {"type": "integer"}}],
        },
    ]


def _all_case_specs() -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    specs.extend(_coverage_cases())
    specs.extend(_tool_arg_cases())
    specs.extend(_schema_match_cases())
    return specs


# ---------------------------------------------------------------------------
# Orchestration: drive each case through the wasm + cross-anchor to cel-python.
# ---------------------------------------------------------------------------


def _apply_direct(udf_name: str, args: list[Any]) -> Any:
    if udf_name == "relay.coverage":
        return relay_coverage(*args)
    if udf_name == "relay.tool_arg":
        return relay_tool_arg(*args)
    if udf_name == "relay.schema_match":
        return relay_schema_match(*args)
    raise ValueError(f"unknown udf: {udf_name!r}")


def _wasm_eval(cel: RelayCel, expression: str, bindings_py: dict[str, Any]) -> dict[str, Any]:
    """Drive ``expression`` THROUGH the wasm CEL engine with ``relay_profile=True``.

    Bindings are converted to typed-canonical via ``py_to_typed`` (the byte-
    faithful wire form). Returns the wasm response dict; raises on a non-ok
    envelope (an engine failure must abort, not silently record).
    """
    typed_bindings = {name: py_to_typed(value) for name, value in bindings_py.items()}
    response = cel.eval(expression, typed_bindings or None, relay_profile=True)
    if not response.get("ok"):
        raise RuntimeError(
            f"wasm engine returned non-ok for {expression!r}: {json.dumps(response)}"
        )
    return response


class CrossAnchorDivergence(Exception):
    """Raised when wasm-via-CEL and cel-python-direct-call disagree for a case.

    Carries the exact case label, expression, and BOTH typed-canonical results
    so the abort message is fully diagnostic (a divergence is a P0).
    """

    def __init__(
        self,
        label: str,
        expression: str,
        wasm_value: Any,
        direct_value: Any,
    ) -> None:
        self.label = label
        self.expression = expression
        self.wasm_value = wasm_value
        self.direct_value = direct_value
        super().__init__(
            "cross-anchor DIVERGENCE (wasm-via-CEL != cel-python-direct-call) for "
            f"case {label!r} expr {expression!r}:\n"
            f"  wasm-via-CEL   : {json.dumps(wasm_value, sort_keys=True)}\n"
            f"  cel-py-direct  : {json.dumps(direct_value, sort_keys=True)}"
        )


def build_case(cel: RelayCel, spec: dict[str, Any]) -> dict[str, Any]:
    """Build a single corpus case from a spec, cross-anchoring wasm vs cel-python.

    Raises ``CrossAnchorDivergence`` if the two disagree (the caller aborts).
    """
    label = spec["label"]
    udf = spec["udf"]
    expression = spec["input_expression"]
    bindings_py = spec["bindings_py"]
    direct_args = spec["direct_args"]

    if udf not in UDF_ALLOWLIST:
        raise ValueError(f"case {label!r} references non-allowlist UDF {udf!r}")

    # wasm-through-CEL value (typed-canonical).
    response = _wasm_eval(cel, expression, bindings_py)
    wasm_value = response["value"]

    # cel-python DIRECT-call value, serialized to typed-canonical.
    direct_result = _apply_direct(udf, direct_args)
    direct_typed = py_to_typed(direct_result)

    # Cross-anchor: the load-bearing parity that replaces the retired two-engine
    # comparison. ANY disagreement aborts.
    if wasm_value != direct_typed:
        raise CrossAnchorDivergence(label, expression, wasm_value, direct_typed)

    py_jcs_b64 = base64.b64encode(jcs_canonicalize(wasm_value)).decode("ascii")
    cel_js_parseable = compute_cel_js_parseable(expression)

    case = {
        "label": label,
        "udf": udf,
        "engines": list(ENGINES_FENCE),
        "input_expression": expression,
        "bindings": bindings_py,
        "direct_args": direct_args,
        "cel_js_parseable": cel_js_parseable,
        "golden_typed": wasm_value,
        "py_jcs_b64": py_jcs_b64,
    }
    # Self-validate the engines fence on emit (the same loader the guard uses).
    validate_case_engines(case)
    return case


def build_corpus() -> dict[str, Any]:
    cel = RelayCel()
    specs = _all_case_specs()

    seen_labels: set[str] = set()
    divergences: list[CrossAnchorDivergence] = []
    cases: list[dict[str, Any]] = []

    for spec in specs:
        label = spec["label"]
        if label in seen_labels:
            raise ValueError(f"duplicate case label: {label!r}")
        seen_labels.add(label)
        try:
            cases.append(build_case(cel, spec))
        except CrossAnchorDivergence as div:
            divergences.append(div)

    if divergences:
        # Report ALL divergences, then abort. A divergence is a P0: never
        # silently record a divergent golden.
        lines = [str(div) for div in divergences]
        raise SystemExit(
            "ABORT: cross-anchor divergence on "
            f"{len(divergences)}/{len(specs)} case(s):\n" + "\n".join(lines)
        )

    return {"schema_version": SCHEMA_VERSION, "cases": cases}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify on-disk corpus equals freshly-computed bytes; exit 1 on drift.",
    )
    parser.add_argument(
        "--out",
        default=str(CORPUS_PATH),
        help=f"Output path (default: {CORPUS_PATH}).",
    )
    args = parser.parse_args()

    corpus = build_corpus()
    serialised = json.dumps(corpus, indent=2, sort_keys=True) + "\n"
    out_path = Path(args.out)

    case_count = len(corpus["cases"])
    udf_breakdown: dict[str, int] = {}
    for case in corpus["cases"]:
        udf_breakdown[case["udf"]] = udf_breakdown.get(case["udf"], 0) + 1

    if args.check:
        print(
            f"cross-anchor: {case_count}/{case_count} cases agree "
            "(wasm-via-CEL == fixed cel-python direct-call)"
        )
        if not out_path.exists():
            print(f"FAIL: corpus file does not exist: {out_path}")
            return 1
        existing = out_path.read_text(encoding="utf-8")
        if existing != serialised:
            print("FAIL: corpus drift detected; regenerate via:")
            print("  uv run python scripts/generate-relay-udf-via-cel-corpus.py")
            return 1
        print(f"goldens unchanged ({case_count} cases): {udf_breakdown}")
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(serialised, encoding="utf-8")
    print(
        f"cross-anchor: {case_count}/{case_count} cases agree "
        "(wasm-via-CEL == fixed cel-python direct-call)"
    )
    print(f"OK: wrote {case_count} cases to {out_path}: {udf_breakdown}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
