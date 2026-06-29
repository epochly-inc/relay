"""W17.4 VAL-W17-017: cross-runtime byte-identical parity.

For every per-UDF case under
``tests/conformance/cel/relay-udfs/<udf>/case_NNN.json``, this test:

  (a) Invokes the Python UDF callable directly (relay_coverage,
      relay_tool_arg, or relay_schema_match) with the case's ``args``
      list.
  (b) Spawns a Node subprocess that imports the TypeScript mirror
      (``packages/contracts-typescript/dist/index.js``) and invokes the
      corresponding TS UDF (relayCoverage / relayToolArg /
      relaySchemaMatch) with the same args.
  (c) Canonicalises both outputs via RFC 8785 JCS using the validated
      Python and TypeScript JCS implementations (W17.1 / VAL-W17-002).
  (d) Asserts SHA-256(python_canonical) == SHA-256(typescript_canonical)
      AND that both digests equal SHA-256 of the recorded
      ``py_jcs_b64`` golden bytes.

Practical scope (per gap #2 below + the contract's spirit): the Relay
UDFs are direct-callable from both runtimes (the Python and TypeScript
host-side UDF implementations). Parity is therefore enforced at the
UDF-callable level + JCS-canonical-bytes level, which is the
byte-identical claim the contract names: "byte-identical output across
the Python and TypeScript hosts after JCS canonicalization". The
UDF-via-CEL byte parity through the single wasm engine is exercised by
the WS-E corpus suites (test_udf_via_cel_byte_match_runner.py +
test_dual_run_cross_host_wasm_parity.py), and the cross-runtime UDF
semantics are also exercised end-to-end in the W6.5 vitest mirror at
``packages/contracts-typescript/test/w6_5_corpus.test.ts``.

ANY divergence fails the suite with a structured diff containing:
  {vector_input, expected, py_output, ts_output, py_canonical_bytes_b64,
   ts_canonical_bytes_b64, py_digest, ts_digest, diff_payload_sha256}

Tool: cross-runtime-fixture (pytest plumbing tier).
ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
RELAY_UDFS_DIR = REPO_ROOT / "tests" / "conformance" / "cel" / "relay-udfs"
TS_DIST_INDEX = (
    REPO_ROOT / "packages" / "contracts-typescript" / "dist" / "index.js"
)

REQUIRED_UDFS: tuple[str, ...] = (
    "relay.coverage",
    "relay.tool_arg",
    "relay.schema_match",
)

# Node subprocess script: takes a JSON payload on stdin of shape
# {"cases": [{"label": str, "udf": str, "args": [...]} , ...]} and
# emits {"results": [{"label": str, "ok": bool, "jcs_b64": str|null,
# "error": str|null}, ...]} on stdout. Errors during evaluation are
# captured per-case; runner-level failures (bad import, etc.) cause
# non-zero exit.
_TS_RUNNER = r"""
import { readFileSync } from "node:fs";
import {
  jcsCanonicalize,
  RELAY_COVERAGE_NAME,
  RELAY_TOOL_ARG_NAME,
  RELAY_SCHEMA_MATCH_NAME,
  relayCoverage,
  relayToolArg,
  relaySchemaMatch,
} from "RELAY_TS_INDEX";
import { Buffer } from "node:buffer";

const raw = readFileSync(0, "utf-8");
const payload = JSON.parse(raw);
const results = [];
for (const c of payload.cases) {
  let value;
  let ok = true;
  let err = null;
  try {
    if (c.udf === RELAY_COVERAGE_NAME) {
      value = relayCoverage(c.args[0], c.args[1]);
    } else if (c.udf === RELAY_TOOL_ARG_NAME) {
      value = relayToolArg(c.args[0], c.args[1]);
    } else if (c.udf === RELAY_SCHEMA_MATCH_NAME) {
      value = relaySchemaMatch(c.args[0], c.args[1]);
    } else {
      ok = false;
      err = `unknown UDF: ${c.udf}`;
    }
  } catch (e) {
    ok = false;
    err = (e && e.message) ? e.message : String(e);
  }
  let jcs_b64 = null;
  if (ok) {
    try {
      const bytes = jcsCanonicalize(value);
      jcs_b64 = Buffer.from(bytes).toString("base64");
    } catch (e) {
      ok = false;
      err = `jcs: ${(e && e.message) ? e.message : String(e)}`;
    }
  }
  results.push({ label: c.label, ok, jcs_b64, error: err });
}
process.stdout.write(JSON.stringify({ results }));
"""


def _node_available() -> bool:
    return shutil.which("node") is not None


def _ts_dist_available() -> bool:
    return TS_DIST_INDEX.exists()


def _load_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for udf in REQUIRED_UDFS:
        udf_dir = RELAY_UDFS_DIR / udf
        if not udf_dir.is_dir():
            continue
        for path in sorted(udf_dir.glob("case_*.json")):
            cases.append(json.loads(path.read_text(encoding="utf-8")))
    return cases


def _python_jcs(value: Any) -> bytes:
    from relay_contracts import jcs_canonicalize

    return jcs_canonicalize(value)


def _python_invoke_udf(udf: str, args: list[Any]) -> Any:
    from relay_contracts import (
        relay_coverage,
        relay_schema_match,
        relay_tool_arg,
    )

    if udf == "relay.coverage":
        return relay_coverage(args[0], args[1])
    if udf == "relay.tool_arg":
        return relay_tool_arg(args[0], args[1])
    if udf == "relay.schema_match":
        return relay_schema_match(args[0], args[1])
    raise ValueError(f"unknown UDF: {udf}")


def _run_ts_batch(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Spawn a Node subprocess that evaluates every UDF case via the
    TypeScript mirror, returning one result record per case."""

    if not _node_available():
        pytest.fail(
            "VAL-W17-017: `node` binary not on PATH; cross-runtime parity "
            "requires Node 22+ to run the TypeScript mirror."
        )
    if not _ts_dist_available():
        pytest.fail(
            f"VAL-W17-017: TypeScript dist missing at {TS_DIST_INDEX}; "
            "run `npm run build --workspace @epochly/relay-contracts`."
        )
    script = _TS_RUNNER.replace("RELAY_TS_INDEX", TS_DIST_INDEX.as_uri())
    payload = json.dumps(
        {
            "cases": [
                {"label": c["label"], "udf": c["udf"], "args": c["args"]}
                for c in cases
            ]
        }
    ).encode("utf-8")
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        input=payload,
        capture_output=True,
        timeout=120,
        check=False,
        cwd=str(REPO_ROOT),
        env={**os.environ, "NODE_NO_WARNINGS": "1"},
    )
    if proc.returncode != 0:
        pytest.fail(
            f"VAL-W17-017: TS runner exited {proc.returncode}\n"
            f"  stderr: {proc.stderr.decode('utf-8', errors='replace')}\n"
            f"  stdout: {proc.stdout.decode('utf-8', errors='replace')[:2000]}"
        )
    try:
        return json.loads(proc.stdout.decode("utf-8"))["results"]
    except (json.JSONDecodeError, KeyError) as exc:
        pytest.fail(
            f"VAL-W17-017: TS runner produced unparseable output: {exc}\n"
            f"  stdout: {proc.stdout.decode('utf-8', errors='replace')[:2000]}"
        )


def _format_divergence(
    case: dict[str, Any],
    py_output: Any,
    ts_output: Any,
    py_jcs: bytes | None,
    ts_jcs: bytes | None,
    py_digest: str | None,
    ts_digest: str | None,
    ts_error: str | None = None,
) -> dict[str, Any]:
    payload = {
        "expected_b64": case.get("py_jcs_b64"),
        "py_output": py_output,
        "ts_output": ts_output,
    }
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "label": case.get("label"),
        "udf": case.get("udf"),
        "vector_input": {
            "expression": case.get("input_expression"),
            "args": case.get("args"),
            "bindings": case.get("input_bindings"),
        },
        "expected": case.get("expected_output"),
        "py_output": py_output,
        "ts_output": ts_output,
        "py_canonical_bytes_b64": (
            base64.b64encode(py_jcs).decode("ascii") if py_jcs is not None else None
        ),
        "ts_canonical_bytes_b64": (
            base64.b64encode(ts_jcs).decode("ascii") if ts_jcs is not None else None
        ),
        "py_digest": py_digest,
        "ts_digest": ts_digest,
        "expected_digest": (
            hashlib.sha256(
                base64.b64decode(case["py_jcs_b64"].encode("ascii"))
            ).hexdigest()
            if case.get("py_jcs_b64")
            else None
        ),
        "ts_error": ts_error,
        "diff_payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
    }


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-017")
def test_node_runtime_available_for_cross_runtime_parity() -> None:
    """The cross-runtime suite requires Node 22+ on PATH; the TS mirror
    must be built. Surface the prerequisite as its own test so the
    parity failure (if any) is unambiguous about cause."""

    assert _node_available(), (
        "VAL-W17-017: `node` binary not on PATH; cross-runtime parity "
        "requires Node 22+ (see CLAUDE.md > Project Structure)."
    )
    assert _ts_dist_available(), (
        f"VAL-W17-017: TypeScript dist missing at {TS_DIST_INDEX}; "
        "build via `npm run build --workspace @epochly/relay-contracts`."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-017")
def test_cross_runtime_byte_identical_parity_for_every_udf_case() -> None:
    """For every per-UDF case: cel-python invocation + JCS bytes MUST
    equal cel-js invocation + JCS bytes, AND both MUST equal the
    recorded ``py_jcs_b64`` golden. ANY divergence produces the
    structured diff."""

    cases = _load_cases()
    if not cases:
        pytest.fail(
            "VAL-W17-017: no per-UDF cases found at "
            f"{RELAY_UDFS_DIR}; regenerate via "
            "`uv run python scripts/generate-w17-4-udf-cases.py`."
        )

    # Python side: invoke UDFs and canonicalise.
    py_outputs: dict[str, Any] = {}
    py_jcs_bytes: dict[str, bytes] = {}
    py_digests: dict[str, str] = {}
    for c in cases:
        label = c["label"]
        value = _python_invoke_udf(c["udf"], c["args"])
        py_outputs[label] = value
        bytes_ = _python_jcs(value)
        py_jcs_bytes[label] = bytes_
        py_digests[label] = hashlib.sha256(bytes_).hexdigest()

    # TypeScript side: one batched Node subprocess invocation.
    ts_records = _run_ts_batch(cases)
    ts_outputs: dict[str, Any] = {}
    ts_jcs_bytes: dict[str, bytes] = {}
    ts_digests: dict[str, str] = {}
    ts_errors: dict[str, str] = {}
    for rec in ts_records:
        label = rec["label"]
        if rec["ok"] and rec["jcs_b64"] is not None:
            b = base64.b64decode(rec["jcs_b64"].encode("ascii"))
            ts_jcs_bytes[label] = b
            ts_digests[label] = hashlib.sha256(b).hexdigest()
            # Re-decode the JCS bytes back to a JSON value so the
            # divergence diff can name ts_output as a structured value
            # rather than only as a digest.
            try:
                ts_outputs[label] = json.loads(b.decode("utf-8"))
            except json.JSONDecodeError:
                ts_outputs[label] = f"<non-json-jcs-bytes:{rec['jcs_b64']}>"
        else:
            ts_errors[label] = rec.get("error") or "<unknown>"

    divergences: list[dict[str, Any]] = []
    for c in cases:
        label = c["label"]
        expected_b = base64.b64decode(c["py_jcs_b64"].encode("ascii"))
        expected_digest = hashlib.sha256(expected_b).hexdigest()
        if label in ts_errors:
            divergences.append(
                _format_divergence(
                    c,
                    py_output=py_outputs.get(label),
                    ts_output=None,
                    py_jcs=py_jcs_bytes.get(label),
                    ts_jcs=None,
                    py_digest=py_digests.get(label),
                    ts_digest=None,
                    ts_error=ts_errors[label],
                )
            )
            continue
        py_d = py_digests[label]
        ts_d = ts_digests[label]
        if py_d != ts_d or py_d != expected_digest:
            divergences.append(
                _format_divergence(
                    c,
                    py_output=py_outputs.get(label),
                    ts_output=ts_outputs.get(label),
                    py_jcs=py_jcs_bytes.get(label),
                    ts_jcs=ts_jcs_bytes.get(label),
                    py_digest=py_d,
                    ts_digest=ts_d,
                )
            )

    if divergences:
        rendered = "\n".join(
            json.dumps(d, sort_keys=True, indent=2) for d in divergences
        )
        for d in divergences:
            print("[w17.4-parity-diff]", json.dumps(d, sort_keys=True))
        pytest.fail(
            f"VAL-W17-017: {len(divergences)} cross-runtime parity "
            f"divergences (full diff follows; no counts):\n{rendered}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-017")
def test_divergence_formatter_contains_required_fields() -> None:
    """Negative-test surface: the structured diff record MUST carry
    every field the contract names so a real failure surfaces a fully
    actionable diff (not just a count)."""

    synthetic_case = {
        "label": "_test_only_synthetic",
        "udf": "relay.coverage",
        "args": [{"steps": [{"name": "x"}]}, "x"],
        "input_expression": "relay.coverage(trace, step_name)",
        "input_bindings": {
            "trace": {"steps": [{"name": "x"}]},
            "step_name": "x",
        },
        "expected_output": True,
        "py_jcs_b64": "dHJ1ZQ==",  # base64("true")
    }
    py_jcs = b"true"
    ts_jcs = b"false"
    rec = _format_divergence(
        synthetic_case,
        py_output=True,
        ts_output=False,
        py_jcs=py_jcs,
        ts_jcs=ts_jcs,
        py_digest=hashlib.sha256(py_jcs).hexdigest(),
        ts_digest=hashlib.sha256(ts_jcs).hexdigest(),
    )
    required = {
        "label",
        "udf",
        "vector_input",
        "expected",
        "py_output",
        "ts_output",
        "py_canonical_bytes_b64",
        "ts_canonical_bytes_b64",
        "py_digest",
        "ts_digest",
        "diff_payload_sha256",
    }
    missing = required - set(rec.keys())
    assert missing == set(), (
        f"VAL-W17-017: divergence formatter missing required fields: {missing}"
    )
    # Determinism: the diff_payload_sha256 must be reproducible.
    again = _format_divergence(
        synthetic_case,
        py_output=True,
        ts_output=False,
        py_jcs=py_jcs,
        ts_jcs=ts_jcs,
        py_digest=hashlib.sha256(py_jcs).hexdigest(),
        ts_digest=hashlib.sha256(ts_jcs).hexdigest(),
    )
    assert again["diff_payload_sha256"] == rec["diff_payload_sha256"]


# ---------------------------------------------------------------------------
# VAL-V3M5-007: BMP edge-case parity for the JCS encoder itself
# ---------------------------------------------------------------------------
#
# The UDF-level parity test above exercises full Relay UDF outputs after JCS
# canonicalisation. This block adds a focused parity sweep on the JCS encoder
# entry point itself, covering Basic Multilingual Plane (BMP) edge cases that
# the V3 audit-resolution m5-f02 feature pins:
#
#   - BMP keys with non-ASCII characters (U+00E9, U+4E2D, U+FFFD, etc.) MUST
#     produce byte-identical JCS bytes between cel-python and cel-js.
#   - BMP boundary key U+FFFF (the highest BMP codepoint) MUST encode
#     identically in both runtimes.
#   - Supplementary-plane keys (>= U+10000) MUST be rejected by BOTH
#     runtimes with CanonicalEncodingError code RELAY-CANON-NON-BMP-KEY.
#   - Non-BMP characters appearing in VALUES (not keys) MUST encode in both
#     runtimes and produce byte-identical output.
#
# The cross-runtime claim here is the SAME as the UDF claim above
# (byte-equality after JCS), but the surface is the encoder's own boundary
# rather than any UDF.

# Importing directly from canonical.js rather than the package index because
# the package's index.ts (not in this feature's filesOwned) currently
# re-exports only jcsCanonicalize, not CanonicalEncodingError. The runner
# needs both. canonical.js is part of the same dist directory.
_TS_JCS_RUNNER = r"""
import {
  jcsCanonicalize,
  CanonicalEncodingError,
} from "RELAY_TS_CANONICAL";
import { readFileSync } from "node:fs";
import { Buffer } from "node:buffer";

const raw = readFileSync(0, "utf-8");
const payload = JSON.parse(raw);
const results = [];
for (const c of payload.cases) {
  let ok = true;
  let err = null;
  let err_code = null;
  let jcs_b64 = null;
  try {
    const bytes = jcsCanonicalize(c.value);
    jcs_b64 = Buffer.from(bytes).toString("base64");
  } catch (e) {
    ok = false;
    err = (e && e.message) ? e.message : String(e);
    if (e instanceof CanonicalEncodingError) {
      err_code = e.code;
    }
  }
  results.push({ label: c.label, ok, jcs_b64, error: err, error_code: err_code });
}
process.stdout.write(JSON.stringify({ results }));
"""


def _run_ts_jcs_batch(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Spawn a Node subprocess that invokes ``jcsCanonicalize`` directly on
    each case value, returning per-case results (success bytes or error).

    The case payload is JSON-serialisable so the value must be JSON-safe.
    Each case is a dict ``{"label": str, "value": Any}``.
    """

    if not _node_available():
        pytest.fail(
            "VAL-V3M5-007: `node` binary not on PATH; BMP cross-runtime "
            "parity requires Node 22+ to run the TypeScript JCS encoder."
        )
    if not _ts_dist_available():
        pytest.fail(
            f"VAL-V3M5-007: TypeScript dist missing at {TS_DIST_INDEX}; "
            "run `npm run build --workspace @epochly/relay-contracts`."
        )
    ts_canonical_path = (
        REPO_ROOT
        / "packages"
        / "contracts-typescript"
        / "dist"
        / "canonical.js"
    )
    if not ts_canonical_path.exists():
        pytest.fail(
            f"VAL-V3M5-007: TypeScript canonical.js missing at "
            f"{ts_canonical_path}; run "
            "`npm run build --workspace @epochly/relay-contracts`."
        )
    script = _TS_JCS_RUNNER.replace(
        "RELAY_TS_CANONICAL", ts_canonical_path.as_uri()
    )
    payload = json.dumps(
        {"cases": [{"label": c["label"], "value": c["value"]} for c in cases]}
    ).encode("utf-8")
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        input=payload,
        capture_output=True,
        timeout=120,
        check=False,
        cwd=str(REPO_ROOT),
        env={**os.environ, "NODE_NO_WARNINGS": "1"},
    )
    if proc.returncode != 0:
        pytest.fail(
            f"VAL-V3M5-007: TS JCS runner exited {proc.returncode}\n"
            f"  stderr: {proc.stderr.decode('utf-8', errors='replace')}\n"
            f"  stdout: {proc.stdout.decode('utf-8', errors='replace')[:2000]}"
        )
    try:
        return json.loads(proc.stdout.decode("utf-8"))["results"]
    except (json.JSONDecodeError, KeyError) as exc:
        pytest.fail(
            f"VAL-V3M5-007: TS JCS runner produced unparseable output: {exc}\n"
            f"  stdout: {proc.stdout.decode('utf-8', errors='replace')[:2000]}"
        )


# The BMP-accept corpus: every entry encodes successfully in both runtimes,
# and the resulting JCS bytes are byte-identical. The "label" field is a
# stable ID for cross-reference into structured-review evidence.
_BMP_ACCEPT_CASES: list[dict[str, Any]] = [
    {
        "label": "bmp_accept_ascii_only_key",
        "value": {"abc": 1, "def": 2},
        "rationale": "pure-ASCII BMP keys; baseline parity.",
    },
    {
        "label": "bmp_accept_latin_extended_key",
        "value": {"caf" + chr(0x00E9): 1, "na" + chr(0x00EF) + "ve": 2},
        "rationale": "U+00E9 / U+00EF: BMP non-ASCII keys must encode identically.",
    },
    {
        "label": "bmp_accept_cjk_key",
        "value": {chr(0x4E2D) + chr(0x6587): "zh"},
        "rationale": "U+4E2D U+6587 (Chinese): BMP CJK keys must encode identically.",
    },
    {
        "label": "bmp_accept_replacement_char_key",
        "value": {chr(0xFFFD): True},
        "rationale": "U+FFFD (REPLACEMENT CHARACTER): in BMP, must encode.",
    },
    {
        "label": "bmp_accept_boundary_ffff_key",
        "value": {"k" + chr(0xFFFF): 0},
        "rationale": (
            "U+FFFF: highest BMP codepoint, immediate boundary below the "
            "non-BMP region. Must encode in both runtimes."
        ),
    },
    {
        "label": "bmp_accept_non_bmp_value_only",
        "value": {"emoji": chr(0x1F600), "count": 1},
        "rationale": (
            "Non-BMP codepoint U+1F600 in a VALUE (not a key) must encode "
            "in both runtimes; only KEYS are screened."
        ),
    },
    {
        "label": "bmp_accept_nested_bmp_keys",
        "value": {"outer": {"caf" + chr(0x00E9): {"x": 1}}},
        "rationale": (
            "Nested object with BMP non-ASCII keys at multiple depths must "
            "encode identically in both runtimes."
        ),
    },
]


# The BMP-reject corpus: every entry MUST raise CanonicalEncodingError
# with code RELAY-CANON-NON-BMP-KEY in both runtimes.
_BMP_REJECT_CASES: list[dict[str, Any]] = [
    {
        "label": "bmp_reject_top_level_emoji_key",
        "value": {chr(0x1F600): 1},
        "rationale": "U+1F600 (GRINNING FACE): supplementary-plane key.",
    },
    {
        "label": "bmp_reject_top_level_emoji_key_prefixed",
        "value": {"a" + chr(0x1F600): 1},
        "rationale": "ASCII prefix + non-BMP suffix in key: still rejected.",
    },
    {
        "label": "bmp_reject_nested_non_bmp_key",
        "value": {"outer": {chr(0x1F600) + "k": 1}},
        "rationale": "Nested non-BMP key must be screened recursively.",
    },
    {
        "label": "bmp_reject_just_above_bmp_boundary",
        "value": {chr(0x10000): 1},
        "rationale": (
            "U+10000: smallest supplementary-plane codepoint, immediate "
            "boundary above BMP. Must be rejected by both runtimes."
        ),
    },
    {
        "label": "bmp_reject_high_supplementary_plane_key",
        "value": {chr(0x10FFFF): 1},
        "rationale": "U+10FFFF: highest valid Unicode codepoint, must be rejected.",
    },
]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-007")
def test_bmp_accept_corpus_parity_python_vs_typescript() -> None:
    """Every BMP-accept case MUST produce byte-identical JCS bytes between
    cel-python and cel-js. Any divergence fails with the case label.

    V3 audit-resolution VAL-V3M5-007: cross-language parity corpus extended
    with BMP edge cases.
    """

    # Python side: invoke jcs_canonicalize on each value.
    py_jcs_bytes: dict[str, bytes] = {}
    py_digests: dict[str, str] = {}
    for c in _BMP_ACCEPT_CASES:
        b = _python_jcs(c["value"])
        py_jcs_bytes[c["label"]] = b
        py_digests[c["label"]] = hashlib.sha256(b).hexdigest()

    # TypeScript side: one batched Node subprocess.
    ts_records = _run_ts_jcs_batch(_BMP_ACCEPT_CASES)
    divergences: list[dict[str, Any]] = []
    for rec, case in zip(ts_records, _BMP_ACCEPT_CASES, strict=True):
        label = rec["label"]
        if not rec["ok"] or rec["jcs_b64"] is None:
            divergences.append(
                {
                    "label": label,
                    "rationale": case["rationale"],
                    "py_jcs_b64": base64.b64encode(
                        py_jcs_bytes[label]
                    ).decode("ascii"),
                    "ts_error": rec.get("error"),
                    "ts_error_code": rec.get("error_code"),
                }
            )
            continue
        ts_bytes = base64.b64decode(rec["jcs_b64"].encode("ascii"))
        ts_digest = hashlib.sha256(ts_bytes).hexdigest()
        if ts_digest != py_digests[label]:
            divergences.append(
                {
                    "label": label,
                    "rationale": case["rationale"],
                    "py_jcs_b64": base64.b64encode(
                        py_jcs_bytes[label]
                    ).decode("ascii"),
                    "ts_jcs_b64": rec["jcs_b64"],
                    "py_digest": py_digests[label],
                    "ts_digest": ts_digest,
                }
            )

    if divergences:
        pytest.fail(
            f"VAL-V3M5-007: {len(divergences)} BMP-accept cross-runtime "
            f"parity divergences:\n"
            + "\n".join(
                json.dumps(d, sort_keys=True, indent=2) for d in divergences
            )
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-007")
def test_bmp_reject_corpus_parity_python_vs_typescript() -> None:
    """Every BMP-reject case MUST raise CanonicalEncodingError with code
    RELAY-CANON-NON-BMP-KEY in BOTH runtimes. Any case that encodes
    successfully in either runtime is a parity failure.

    V3 audit-resolution VAL-V3M5-007: rejection parity is a critical claim;
    a one-sided reject silently breaks cross-runtime signature verification.
    """

    from relay_contracts.canonical import CanonicalEncodingError

    # Python side: each must raise CanonicalEncodingError(RELAY-CANON-NON-BMP-KEY).
    py_results: dict[str, dict[str, Any]] = {}
    for c in _BMP_REJECT_CASES:
        try:
            _python_jcs(c["value"])
            py_results[c["label"]] = {
                "ok": True,
                "error": None,
                "error_code": None,
            }
        except CanonicalEncodingError as exc:
            py_results[c["label"]] = {
                "ok": False,
                "error": str(exc),
                "error_code": exc.code,
            }
        except Exception as exc:  # noqa: BLE001 -- want exhaustive diagnostics
            py_results[c["label"]] = {
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
                "error_code": None,
            }

    # TypeScript side: same expectation, batched.
    ts_records = _run_ts_jcs_batch(_BMP_REJECT_CASES)

    failures: list[dict[str, Any]] = []
    for rec, case in zip(ts_records, _BMP_REJECT_CASES, strict=True):
        label = rec["label"]
        py = py_results[label]
        # Both runtimes must have rejected with the expected error code.
        py_rejected_correctly = (
            not py["ok"]
            and py["error_code"] == "RELAY-CANON-NON-BMP-KEY"
        )
        ts_rejected_correctly = (
            not rec["ok"]
            and rec.get("error_code") == "RELAY-CANON-NON-BMP-KEY"
        )
        if not (py_rejected_correctly and ts_rejected_correctly):
            failures.append(
                {
                    "label": label,
                    "rationale": case["rationale"],
                    "py_ok": py["ok"],
                    "py_error_code": py["error_code"],
                    "py_error": py["error"],
                    "ts_ok": rec["ok"],
                    "ts_error_code": rec.get("error_code"),
                    "ts_error": rec.get("error"),
                }
            )

    if failures:
        pytest.fail(
            f"VAL-V3M5-007: {len(failures)} BMP-reject cross-runtime "
            f"parity failures (both runtimes must reject with code "
            f"RELAY-CANON-NON-BMP-KEY):\n"
            + "\n".join(
                json.dumps(d, sort_keys=True, indent=2) for d in failures
            )
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-007")
def test_bmp_corpus_is_non_trivial() -> None:
    """Guard: the BMP corpus must contain at least one accept and one
    reject case at each of the critical boundaries (U+FFFF accept,
    U+10000 reject). Prevents accidental shrinkage of the corpus."""

    accept_labels = {c["label"] for c in _BMP_ACCEPT_CASES}
    reject_labels = {c["label"] for c in _BMP_REJECT_CASES}

    assert "bmp_accept_boundary_ffff_key" in accept_labels, (
        "VAL-V3M5-007: BMP accept corpus must cover U+FFFF boundary."
    )
    assert "bmp_reject_just_above_bmp_boundary" in reject_labels, (
        "VAL-V3M5-007: BMP reject corpus must cover U+10000 boundary."
    )
    assert "bmp_accept_non_bmp_value_only" in accept_labels, (
        "VAL-V3M5-007: BMP corpus must verify non-BMP values are NOT screened."
    )
    assert "bmp_reject_nested_non_bmp_key" in reject_labels, (
        "VAL-V3M5-007: BMP corpus must verify nested-key recursion."
    )
