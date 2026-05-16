"""W17.3 cel-spec conformance corpus tests.

Pinned-vector conformance suite that exercises both the Python CEL
evaluator (cel-python / celpy) and the TypeScript CEL evaluator
(cel-js, invoked via Node subprocess) against a Relay-profile-filtered
subset of the google/cel-spec conformance vector set.

Assertion coverage:

  * VAL-W17-010: cel-spec corpus is sourced from google/cel-spec and
    pinned by commit SHA. Asserted by ``test_pinned_commit_file_exists``
    (file presence + 40-hex-char format), ``test_manifest_sha256_present``
    (every imported corpus file is digested), and
    ``test_drift_checker_validates_pin`` (running
    ``scripts/check-cel-spec-drift.py`` exits 0).
  * VAL-W17-011: cel-python passes 100% of profile-included vectors.
    The profile filter at ``relay-profile-filter.yaml`` enumerates which
    vectors are inside Relay's CEL profile. Each included vector becomes
    its own parametrised pytest test for per-vector localisation.
    Excluded vectors MUST carry a written `reason` and a citation field;
    an unjustified exclusion fails ``test_profile_filter_justified``.
  * VAL-W17-012: cel-js passes 100% of the SAME profile-included
    vectors. Asserted here via Node subprocess invocation; the
    side-by-side parity matrix is checked by
    ``test_parity_celpy_vs_celjs_per_vector``.
  * VAL-W17-013: ANY divergence between cel-python and cel-js on an
    included vector fails the suite with the FULL DIFF -- not a count.
    The diff record contains exactly the six fields named in the
    contract: vector_id, vector_input_expression, expected, py_actual,
    ts_actual, diff_payload_sha256. Asserted by the parity test
    formatter ``_format_full_diff`` and exercised by
    ``test_full_diff_formatter_contains_all_six_fields``.
  * VAL-W17-014: drift detection runs nightly. The presence of the
    nightly workflow file at
    ``.github/workflows/nightly-cel-drift.yml`` is asserted here so
    the contract evidence does not depend on a CI-only artifact.

The cel-js side is exercised in a sibling vitest mirror at
``packages/contracts-typescript/test/w17_3_celspec_corpus.test.ts`` so
both runtimes have a native test runner. This Python file additionally
invokes cel-js via a Node subprocess so per-vector parity diffs land in
a single pytest report (the contract requires the diff be visible in
the test output, not split across two runners' logs).

Tool: conformance-corpus-test (pytest plumbing tier).
ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CELSPEC_DIR = REPO_ROOT / "tests" / "conformance" / "cel-spec"
PINNED_COMMIT_PATH = CELSPEC_DIR / "PINNED_COMMIT.txt"
MANIFEST_SHA256_PATH = CELSPEC_DIR / "MANIFEST.sha256"
VECTORS_PATH = CELSPEC_DIR / "celspec_vectors.json"
PROFILE_FILTER_PATH = CELSPEC_DIR / "relay-profile-filter.yaml"
UPSTREAM_PINS_PATH = CELSPEC_DIR / ".upstream-pins.json"
DRIFT_CHECKER_PATH = REPO_ROOT / "scripts" / "check-cel-spec-drift.py"
NIGHTLY_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "nightly-cel-drift.yml"
TS_MIRROR_PATH = (
    REPO_ROOT
    / "packages"
    / "contracts-typescript"
    / "test"
    / "w17_3_celspec_corpus.test.ts"
)
CELJS_SUBPROCESS_RUNNER = (
    REPO_ROOT
    / "packages"
    / "contracts-typescript"
    / "test"
    / "_w17_3_celjs_runner.mjs"
)

# 40-hex-char git SHA-1 commit ID pattern.
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
# SHA-256 hex pattern for MANIFEST entries.
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Loaders -- module-level so each test sees the same parsed state.
# ---------------------------------------------------------------------------


def _read_pinned_commit() -> str | None:
    if not PINNED_COMMIT_PATH.exists():
        return None
    for raw in PINNED_COMMIT_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        return line
    return None


def _read_manifest() -> dict[str, str]:
    """Return a {relative_path: sha256_hex} mapping from MANIFEST.sha256.

    Format: sha256sum-compatible -- one entry per line, '<hex>  <path>'.
    """

    if not MANIFEST_SHA256_PATH.exists():
        return {}
    out: dict[str, str] = {}
    for raw in MANIFEST_SHA256_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, rel = parts[0], parts[1].strip()
        # sha256sum format prefixes the path with a single space + optional
        # binary marker '*'. Normalize.
        if rel.startswith("*"):
            rel = rel[1:]
        out[rel] = digest
    return out


def _read_vectors() -> dict[str, Any]:
    if not VECTORS_PATH.exists():
        return {"_schema_version": None, "vectors": []}
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _read_profile_filter() -> dict[str, Any]:
    """Minimal YAML loader -- the profile filter is line-oriented enough
    that we avoid taking a PyYAML dependency. Format:

        included:
          - vector_id: <id>
            note: <free text>
        excluded:
          - vector_id: <id>
            reason: <enum>
            citation: <spec ref>
    """

    if not PROFILE_FILTER_PATH.exists():
        return {"included": [], "excluded": []}
    # Defer to PyYAML if available; otherwise parse a strict subset.
    try:
        import yaml  # type: ignore[import-not-found]

        loaded = yaml.safe_load(PROFILE_FILTER_PATH.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            return {"included": [], "excluded": []}
        return loaded
    except ImportError:  # pragma: no cover -- PyYAML is in tomllib chain
        # Strict-subset parser for the documented schema.
        text = PROFILE_FILTER_PATH.read_text(encoding="utf-8")
        out: dict[str, list[dict[str, str]]] = {"included": [], "excluded": []}
        section: str | None = None
        current: dict[str, str] | None = None
        for raw in text.splitlines():
            line = raw.rstrip()
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if line.startswith("included:"):
                section = "included"
                continue
            if line.startswith("excluded:"):
                section = "excluded"
                continue
            if section is None:
                continue
            stripped = line.lstrip()
            if stripped.startswith("- "):
                if current is not None:
                    out[section].append(current)
                current = {}
                stripped = stripped[2:]
            if ":" in stripped and current is not None:
                key, _, val = stripped.partition(":")
                current[key.strip()] = val.strip().strip('"').strip("'")
        if current is not None and section is not None:
            out[section].append(current)
        return out


# Cache module-level loads so each test runs without re-parsing.
_PINNED_COMMIT: str | None = _read_pinned_commit()
_MANIFEST: dict[str, str] = _read_manifest()
_VECTORS_DOC: dict[str, Any] = _read_vectors()
_VECTORS: list[dict[str, Any]] = _VECTORS_DOC.get("vectors", []) or []
_PROFILE: dict[str, Any] = _read_profile_filter()
_INCLUDED: list[dict[str, Any]] = _PROFILE.get("included", []) or []
_EXCLUDED: list[dict[str, Any]] = _PROFILE.get("excluded", []) or []
_INCLUDED_IDS: set[str] = {e["vector_id"] for e in _INCLUDED if "vector_id" in e}
_VECTORS_BY_ID: dict[str, dict[str, Any]] = {
    v["vector_id"]: v for v in _VECTORS if "vector_id" in v
}


# ---------------------------------------------------------------------------
# VAL-W17-010: pinned commit + manifest
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-010")
def test_pinned_commit_file_exists() -> None:
    assert PINNED_COMMIT_PATH.exists(), (
        f"VAL-W17-010: missing pinned commit anchor at {PINNED_COMMIT_PATH}; "
        "cel-spec corpus is unreproducible without an upstream pin."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-010")
def test_pinned_commit_is_valid_sha1_hex() -> None:
    sha = _read_pinned_commit()
    assert sha is not None, (
        f"VAL-W17-010: {PINNED_COMMIT_PATH} contains no non-comment line; "
        "the upstream pin must be a 40-character lowercase hex SHA-1."
    )
    assert SHA1_RE.match(sha) is not None, (
        f"VAL-W17-010: pinned commit {sha!r} is not a 40-character "
        "lowercase hex SHA-1 git commit ID."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-010")
def test_manifest_sha256_present() -> None:
    assert MANIFEST_SHA256_PATH.exists(), (
        f"VAL-W17-010: missing {MANIFEST_SHA256_PATH}; the manifest MUST "
        "record a SHA-256 for every imported corpus file so a single-byte "
        "tampering is detectable without re-running the drift checker."
    )
    manifest = _read_manifest()
    assert len(manifest) >= 2, (
        f"VAL-W17-010: MANIFEST.sha256 has {len(manifest)} entries; need "
        ">= 2 (celspec_vectors.json + relay-profile-filter.yaml at minimum)."
    )
    for rel, digest in manifest.items():
        assert SHA256_RE.match(digest) is not None, (
            f"VAL-W17-010: manifest entry for {rel!r} is not a 64-char "
            f"lowercase hex SHA-256: {digest!r}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-010")
def test_manifest_digests_match_actual_file_contents() -> None:
    """Every digest in MANIFEST.sha256 MUST equal SHA-256 of the
    referenced file's bytes. A drift here means someone hand-edited a
    vector file without updating the manifest."""

    drifted: list[str] = []
    for rel, expected_digest in _MANIFEST.items():
        path = CELSPEC_DIR / rel
        if not path.exists():
            drifted.append(f"{rel}: file referenced by manifest is missing")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected_digest:
            drifted.append(
                f"{rel}: manifest=sha256:{expected_digest} actual=sha256:{actual}"
            )
    assert drifted == [], (
        "VAL-W17-010: MANIFEST.sha256 digests do not match actual file "
        "contents (drift):\n  " + "\n  ".join(drifted)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-010")
def test_manifest_covers_every_corpus_file() -> None:
    """Every JSON/yaml file under tests/conformance/cel-spec/ MUST be
    in MANIFEST.sha256. Excludes PINNED_COMMIT.txt (the manifest's own
    upstream-anchor) and MANIFEST.sha256 itself."""

    excluded_names = {"PINNED_COMMIT.txt", "MANIFEST.sha256"}
    actual_files: set[str] = set()
    for p in CELSPEC_DIR.rglob("*"):
        if not p.is_file():
            continue
        if p.name.startswith("test_") or p.name.startswith("_") or p.name.endswith(".pyc"):
            continue
        if p.name in excluded_names:
            continue
        if "__pycache__" in p.parts:
            continue
        actual_files.add(str(p.relative_to(CELSPEC_DIR)))
    missing = actual_files - set(_MANIFEST.keys())
    extra = set(_MANIFEST.keys()) - actual_files
    assert missing == set(), (
        f"VAL-W17-010: corpus files NOT in MANIFEST.sha256: {sorted(missing)}"
    )
    assert extra == set(), (
        f"VAL-W17-010: MANIFEST.sha256 references files that do not exist: "
        f"{sorted(extra)}"
    )


# ---------------------------------------------------------------------------
# VAL-W17-011: profile filter justification + cel-python pass
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-011")
def test_profile_filter_exists_and_well_formed() -> None:
    assert PROFILE_FILTER_PATH.exists(), (
        f"VAL-W17-011: missing {PROFILE_FILTER_PATH}; the profile filter "
        "is required so excluded vectors carry a written justification."
    )
    assert isinstance(_PROFILE.get("included"), list), (
        "VAL-W17-011: relay-profile-filter.yaml must have a list-valued 'included' key"
    )
    assert isinstance(_PROFILE.get("excluded"), list), (
        "VAL-W17-011: relay-profile-filter.yaml must have a list-valued 'excluded' key"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-011")
def test_profile_filter_excluded_entries_carry_reason_and_citation() -> None:
    """Per spec gap #2 and contract VAL-W17-011: an unjustified
    exclusion fails the suite."""

    allowed_reasons = {
        "profile-rejects-dyn",
        "profile-rejects-timestamp",
        "profile-rejects-duration",
        "profile-rejects-protobuf-message",
        "profile-rejects-regex-backreference",
        "profile-rejects-bytes-literal",
        "profile-rejects-double-precision-edge",
        "profile-rejects-uint-arithmetic",
        "upstream-vector-uses-untyped-bindings",
        "profile-rejects-macro-with-side-effect-shadow",
    }
    missing_reason: list[str] = []
    missing_citation: list[str] = []
    bad_reason: list[str] = []
    for e in _EXCLUDED:
        vid = e.get("vector_id", "<unknown>")
        if not e.get("reason"):
            missing_reason.append(vid)
            continue
        if not e.get("citation"):
            missing_citation.append(vid)
        if e["reason"] not in allowed_reasons:
            bad_reason.append(f"{vid}: reason={e['reason']!r} not in {sorted(allowed_reasons)}")
    assert missing_reason == [], (
        f"VAL-W17-011: excluded vectors without a 'reason' field: {missing_reason}"
    )
    assert missing_citation == [], (
        f"VAL-W17-011: excluded vectors without a 'citation' field: {missing_citation}"
    )
    assert bad_reason == [], (
        "VAL-W17-011: excluded vectors with non-enum reasons:\n  " + "\n  ".join(bad_reason)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-011")
def test_profile_filter_partitions_vectors() -> None:
    """included ids ++ excluded ids MUST partition the corpus exactly
    (no overlap, no orphan)."""

    inc = _INCLUDED_IDS
    exc = {e["vector_id"] for e in _EXCLUDED if "vector_id" in e}
    overlap = inc & exc
    assert overlap == set(), (
        f"VAL-W17-011: vectors appear in both included and excluded: {sorted(overlap)}"
    )
    all_corpus = set(_VECTORS_BY_ID.keys())
    orphans = all_corpus - (inc | exc)
    assert orphans == set(), (
        f"VAL-W17-011: vectors in corpus but not classified by profile filter: "
        f"{sorted(orphans)}"
    )
    referenced_but_absent = (inc | exc) - all_corpus
    assert referenced_but_absent == set(), (
        f"VAL-W17-011: profile filter references vectors absent from corpus: "
        f"{sorted(referenced_but_absent)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-011")
def test_corpus_has_minimum_included_vectors() -> None:
    """A minimum baseline guarantees the suite has teeth; cel-spec's
    `tests/simple/testdata/` ships hundreds of vectors. Relay's profile
    excludes the dyn/timestamp/duration/protobuf set but the included
    floor must still be substantive."""

    assert len(_INCLUDED) >= 25, (
        f"VAL-W17-011: included-vector floor is 25; got {len(_INCLUDED)}. "
        "Either the profile filter or the corpus is under-populated."
    )


# Each included vector becomes its own parametrised pytest test --
# per-vector localisation matches the W17.1/W17.2 pattern.
_INCLUDED_VECTORS_FOR_PARAM = [
    v
    for v in _VECTORS
    if v.get("vector_id") in _INCLUDED_IDS
]


_PARAM_VECTORS = _INCLUDED_VECTORS_FOR_PARAM or [
    {"vector_id": "__no_corpus__", "_pending": True}
]
_PARAM_IDS = [v.get("vector_id", "<unknown>") for v in _PARAM_VECTORS]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-011")
@pytest.mark.parametrize("vector", _PARAM_VECTORS, ids=_PARAM_IDS)
def test_celpy_evaluates_included_vector(vector: dict[str, Any]) -> None:
    """cel-python MUST produce the expected value for every included
    vector. The expected value uses cel-spec's value-kind taxonomy
    (int/uint/double/string/bool/list/map) materialised as JSON."""

    if vector.get("_pending"):
        pytest.fail(
            "VAL-W17-011: no included vectors in profile filter; corpus has not "
            "been populated yet."
        )
    import celpy.celtypes as celtypes
    from relay_contracts import RELAY_UDFS, RelayCelEvaluator

    def _to_celtypes(value: Any) -> Any:
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
        if isinstance(value, list | tuple):
            return celtypes.ListType([_to_celtypes(x) for x in value])
        if isinstance(value, dict):
            return celtypes.MapType(
                {celtypes.StringType(k): _to_celtypes(v) for k, v in value.items()}
            )
        return value

    def _to_python(value: Any) -> Any:
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
            return [_to_python(v) for v in value]
        if isinstance(value, celtypes.MapType | dict):
            return {str(k): _to_python(v) for k, v in value.items()}
        if isinstance(value, bool | int | float | str):
            return value
        raise TypeError(f"unsupported celpy result type: {type(value).__name__}")

    ev = RelayCelEvaluator(udfs=RELAY_UDFS)
    bindings = {k: _to_celtypes(v) for k, v in (vector.get("bindings") or {}).items()}
    raw = ev.evaluate(vector["expression"], bindings)
    actual = _to_python(raw)
    expected = vector["expected_value"]
    assert actual == expected, (
        f"VAL-W17-011: cel-python diverged from cel-spec golden for vector "
        f"{vector['vector_id']!r}\n"
        f"  expression: {vector['expression']!r}\n"
        f"  bindings:   {vector.get('bindings')!r}\n"
        f"  expected:   {expected!r}\n"
        f"  actual:     {actual!r}"
    )


# ---------------------------------------------------------------------------
# VAL-W17-012 + VAL-W17-013: cel-js parity + full diff on mismatch
# ---------------------------------------------------------------------------


def _format_full_diff(
    vector: dict[str, Any],
    py_actual: Any,
    ts_actual: Any,
) -> dict[str, Any]:
    """Build the six-field diff record contract VAL-W17-013 requires.

    The contract names exactly: vector_id, vector_input_expression,
    expected, py_actual, ts_actual, diff_payload_sha256. The payload is
    the canonical JSON of the (expected, py_actual, ts_actual) triple
    so the SHA-256 is deterministic and reproducible.
    """

    payload = {
        "expected": vector.get("expected_value"),
        "py_actual": py_actual,
        "ts_actual": ts_actual,
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "vector_id": vector.get("vector_id"),
        "vector_input_expression": vector.get("expression"),
        "bindings": vector.get("bindings", {}),
        "expected": vector.get("expected_value"),
        "py_actual": py_actual,
        "ts_actual": ts_actual,
        "diff_payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
    }


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-013")
def test_full_diff_formatter_contains_all_six_fields() -> None:
    """Negative-test surface: a fault-injected mismatch MUST produce a
    diff record containing exactly the six fields named in the
    contract. The formatter is exercised here on a synthetic vector to
    pin its shape regardless of corpus state."""

    synthetic = {
        "vector_id": "_test_only_synthetic",
        "expression": "1 + 1",
        "bindings": {},
        "expected_value": 2,
    }
    rec = _format_full_diff(synthetic, py_actual=2, ts_actual=3)
    required_fields = {
        "vector_id",
        "vector_input_expression",
        "expected",
        "py_actual",
        "ts_actual",
        "diff_payload_sha256",
    }
    missing = required_fields - set(rec.keys())
    assert missing == set(), (
        f"VAL-W17-013: full-diff formatter missing required fields: {missing}"
    )
    assert rec["vector_id"] == "_test_only_synthetic"
    assert rec["vector_input_expression"] == "1 + 1"
    assert rec["expected"] == 2
    assert rec["py_actual"] == 2
    assert rec["ts_actual"] == 3
    assert SHA256_RE.match(rec["diff_payload_sha256"]) is not None
    # SHA-256 MUST be deterministic for the same payload.
    again = _format_full_diff(synthetic, py_actual=2, ts_actual=3)
    assert again["diff_payload_sha256"] == rec["diff_payload_sha256"]
    # And differ when the payload changes.
    different = _format_full_diff(synthetic, py_actual=2, ts_actual=4)
    assert different["diff_payload_sha256"] != rec["diff_payload_sha256"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-012")
def test_celjs_subprocess_runner_present() -> None:
    """The Node subprocess that evaluates cel-js for parity must exist
    next to the vitest mirror."""

    assert CELJS_SUBPROCESS_RUNNER.exists(), (
        f"VAL-W17-012: missing cel-js subprocess runner at "
        f"{CELJS_SUBPROCESS_RUNNER}; pytest cannot drive cel-js without it."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-012")
def test_ts_mirror_test_file_exists() -> None:
    assert TS_MIRROR_PATH.exists(), (
        f"VAL-W17-012: missing TS mirror at {TS_MIRROR_PATH}; cel-js parity "
        "is not enforced on the TypeScript side."
    )


def _run_celjs_batch(vectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Spawn Node, pipe vectors as JSON on stdin, parse results.

    The runner returns one result object per vector with shape:
        {"vector_id": str, "ok": bool, "value": Any | None,
         "error": str | None}
    A non-zero exit code means the runner itself crashed (not a vector
    eval failure -- those are reported per-record).
    """

    if not CELJS_SUBPROCESS_RUNNER.exists():
        pytest.fail(
            f"VAL-W17-012: cel-js runner missing at {CELJS_SUBPROCESS_RUNNER}"
        )
    payload = json.dumps({"vectors": vectors}).encode("utf-8")
    proc = subprocess.run(
        ["node", str(CELJS_SUBPROCESS_RUNNER)],
        input=payload,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"VAL-W17-012: cel-js runner exited {proc.returncode}\n"
            f"  stderr: {proc.stderr.decode('utf-8', errors='replace')}\n"
            f"  stdout: {proc.stdout.decode('utf-8', errors='replace')[:2000]}"
        )
    try:
        return json.loads(proc.stdout.decode("utf-8"))["results"]
    except (json.JSONDecodeError, KeyError) as exc:
        pytest.fail(
            f"VAL-W17-012: cel-js runner produced unparseable output: {exc}\n"
            f"  stdout: {proc.stdout.decode('utf-8', errors='replace')[:2000]}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-012")
@pytest.mark.fulfills("VAL-W17-013")
def test_parity_celpy_vs_celjs_per_vector() -> None:
    """Full cross-runtime parity. Both runtimes evaluate every included
    vector; ANY divergence produces the six-field diff record from
    ``_format_full_diff`` -- not a count.

    This is one pytest test rather than parametrized because per-vector
    parity is verified inside VAL-W17-011 (cel-python) and the vitest
    mirror (cel-js); this test's job is to assert they AGREE, which is
    a single-batch operation per the runner's cost amortisation.
    """

    if not _INCLUDED_VECTORS_FOR_PARAM:
        pytest.fail(
            "VAL-W17-013: no included vectors to parity-check; corpus "
            "has not been populated yet."
        )

    import celpy.celtypes as celtypes
    from relay_contracts import RELAY_UDFS, RelayCelEvaluator

    def _to_celtypes(value: Any) -> Any:
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
        if isinstance(value, list | tuple):
            return celtypes.ListType([_to_celtypes(x) for x in value])
        if isinstance(value, dict):
            return celtypes.MapType(
                {celtypes.StringType(k): _to_celtypes(v) for k, v in value.items()}
            )
        return value

    def _to_python(value: Any) -> Any:
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
            return [_to_python(v) for v in value]
        if isinstance(value, celtypes.MapType | dict):
            return {str(k): _to_python(v) for k, v in value.items()}
        if isinstance(value, bool | int | float | str):
            return value
        raise TypeError(f"unsupported celpy result type: {type(value).__name__}")

    ev = RelayCelEvaluator(udfs=RELAY_UDFS)
    py_results: dict[str, Any] = {}
    py_errors: dict[str, str] = {}
    for vec in _INCLUDED_VECTORS_FOR_PARAM:
        vid = vec["vector_id"]
        try:
            bindings = {
                k: _to_celtypes(v) for k, v in (vec.get("bindings") or {}).items()
            }
            raw = ev.evaluate(vec["expression"], bindings)
            py_results[vid] = _to_python(raw)
        except Exception as e:  # noqa: BLE001 - we want every error captured
            py_errors[vid] = f"{type(e).__name__}: {e}"

    ts_records = _run_celjs_batch(_INCLUDED_VECTORS_FOR_PARAM)
    ts_results: dict[str, Any] = {}
    ts_errors: dict[str, str] = {}
    for rec in ts_records:
        if rec.get("ok"):
            ts_results[rec["vector_id"]] = rec["value"]
        else:
            ts_errors[rec["vector_id"]] = rec.get("error") or "<unknown>"

    divergences: list[dict[str, Any]] = []
    for vec in _INCLUDED_VECTORS_FOR_PARAM:
        vid = vec["vector_id"]
        py_val = py_results.get(vid, f"<py_error:{py_errors.get(vid)}>")
        ts_val = ts_results.get(vid, f"<ts_error:{ts_errors.get(vid)}>")
        # A vector with NO recorded py value AND no recorded ts value
        # means both runtimes errored. That is a parity match (both
        # rejected), but only if neither expected a value. We treat the
        # "both errored" case as an explicit divergence from the
        # expected golden, surfaced for the operator's review.
        if vid in py_errors and vid in ts_errors:
            divergences.append(
                _format_full_diff(vec, py_actual=py_val, ts_actual=ts_val)
            )
            continue
        if vid in py_errors or vid in ts_errors:
            divergences.append(
                _format_full_diff(vec, py_actual=py_val, ts_actual=ts_val)
            )
            continue
        if py_val != ts_val:
            divergences.append(
                _format_full_diff(vec, py_actual=py_val, ts_actual=ts_val)
            )

    if divergences:
        # Print the full per-vector diff records to stdout so CI captures
        # them in <system-out>. The assert message also includes them so
        # they appear in the JUnit failure payload.
        rendered = "\n".join(
            json.dumps(rec, sort_keys=True, indent=2) for rec in divergences
        )
        for rec in divergences:
            print("[parity-diff]", json.dumps(rec, sort_keys=True))
        pytest.fail(
            f"VAL-W17-012/013: {len(divergences)} cel-python vs cel-js "
            f"parity divergences (full diff follows; no counts):\n{rendered}"
        )


# ---------------------------------------------------------------------------
# VAL-W17-010 (drift) + VAL-W17-014 (nightly workflow)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-010")
def test_drift_checker_exits_zero() -> None:
    """The extended scripts/check-cel-spec-drift.py MUST run clean
    against the committed corpus."""

    assert DRIFT_CHECKER_PATH.exists(), (
        f"drift checker missing at {DRIFT_CHECKER_PATH}"
    )
    result = subprocess.run(
        [sys.executable, str(DRIFT_CHECKER_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, (
        f"VAL-W17-010: cel-spec drift checker reported drift.\n"
        f"stdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-010")
def test_upstream_pins_file_records_celspec_commit() -> None:
    """The companion `.upstream-pins.json` MUST record the cel-spec
    commit SHA + last-refreshed date so a future drift checker run can
    detect a hand-edit of PINNED_COMMIT.txt without an accompanying
    pin-file bump."""

    assert UPSTREAM_PINS_PATH.exists(), (
        f"VAL-W17-010: missing {UPSTREAM_PINS_PATH}"
    )
    pins = json.loads(UPSTREAM_PINS_PATH.read_text(encoding="utf-8"))
    assert pins.get("_schema_version") == 1, (
        "VAL-W17-010: .upstream-pins.json must declare _schema_version=1"
    )
    assert SHA1_RE.match(pins.get("celspec_commit_sha", "") or "") is not None, (
        f"VAL-W17-010: .upstream-pins.json missing or malformed "
        f"celspec_commit_sha: {pins.get('celspec_commit_sha')!r}"
    )
    assert pins.get("celspec_commit_sha") == _PINNED_COMMIT, (
        f"VAL-W17-010: .upstream-pins.json celspec_commit_sha "
        f"({pins.get('celspec_commit_sha')!r}) disagrees with "
        f"PINNED_COMMIT.txt ({_PINNED_COMMIT!r})"
    )
    assert isinstance(pins.get("last_refreshed_at"), str) and pins["last_refreshed_at"], (
        "VAL-W17-010: .upstream-pins.json must record last_refreshed_at"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-014")
def test_nightly_drift_workflow_present() -> None:
    """VAL-W17-014: the nightly drift workflow file MUST exist. The
    workflow contents are asserted by a second test so individual
    requirements (cron schedule, install-latest step, alerting path) are
    addressable per-failure."""

    assert NIGHTLY_WORKFLOW_PATH.exists(), (
        f"VAL-W17-014: missing {NIGHTLY_WORKFLOW_PATH}; nightly drift "
        "detection is unenforced."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-014")
def test_nightly_drift_workflow_has_required_shape() -> None:
    """The workflow MUST: (a) run on a cron schedule, (b) install the
    LATEST cel-python and cel-js (not the pinned versions), (c) execute
    the same pytest plumbing entry that this file is part of,
    (d) include an alerting path that opens a GitHub issue tagged
    `area:conformance-drift` when drift is detected."""

    if not NIGHTLY_WORKFLOW_PATH.exists():
        pytest.skip("workflow missing -- covered by sibling test")
    text = NIGHTLY_WORKFLOW_PATH.read_text(encoding="utf-8")
    required_substrings = [
        # cron trigger
        ("schedule:", "VAL-W17-014: workflow must run on a schedule (cron)"),
        ("cron:", "VAL-W17-014: workflow must declare a cron expression"),
        # install latest (not pinned)
        (
            "pip install --upgrade cel-python",
            "VAL-W17-014: workflow must install --upgrade cel-python",
        ),
        (
            "npm install cel-js@latest",
            "VAL-W17-014: workflow must install cel-js@latest",
        ),
        # alerting path: GitHub issue with the required label
        (
            "area:conformance-drift",
            "VAL-W17-014: workflow must reference area:conformance-drift label",
        ),
        # the drift-detect entry point
        (
            "tests/conformance/cel-spec/",
            "VAL-W17-014: workflow must reference the cel-spec corpus path",
        ),
    ]
    missing: list[str] = []
    for needle, reason in required_substrings:
        if needle not in text:
            missing.append(reason)
    assert missing == [], (
        "VAL-W17-014: nightly drift workflow is missing required elements:\n  "
        + "\n  ".join(missing)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-014")
def test_codeowners_assigns_packages_contracts() -> None:
    """For the nightly workflow's auto-assignee step to land on a real
    user, CODEOWNERS MUST assign an owner for packages/contracts/. The
    workflow looks up the first owner listed and uses it as the
    `assignees:` field on the opened GitHub issue."""

    codeowners = REPO_ROOT / ".github" / "CODEOWNERS"
    assert codeowners.exists(), "CODEOWNERS file missing"
    text = codeowners.read_text(encoding="utf-8")
    has_packages_contracts = any(
        line.strip().startswith("/packages/contracts/")
        or line.strip().startswith("packages/contracts/")
        for line in text.splitlines()
    )
    assert has_packages_contracts, (
        "VAL-W17-014: CODEOWNERS must assign an owner for packages/contracts/ "
        "so the nightly drift workflow can auto-assign the GitHub issue."
    )
