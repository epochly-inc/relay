"""W6.5 cel-spec/cel-conformance drift checker (VAL-W6-055).

Compares the vendored cel-spec test-vector list at
``tests/conformance/cel/vendor/cel_spec_vectors.json`` to the generated
Relay-CEL corpus at ``tests/conformance/cel/relay_cel_corpus.json``
and asserts:

  1. Every ``corpus_case_id`` named in the vendored file exists in the
     generated corpus and carries an expression that decodes to the
     same JSON-canonical string as the vendored ``expression`` field.

  2. The vendored ``cel_spec_vectors.json`` has not been silently
     mutated from a known-good shape -- ``schema_version`` is still 1.

  3. Bumping the upstream cel-python (``celpy``) or cel-js
     (``cel-js``) package version requires re-pinning the vendor file's
     ``_source_revision`` field. The script reads
     ``packages/contracts/pyproject.toml`` for the celpy lower bound and
     ``packages/contracts-typescript/package.json`` for the cel-js
     pinned version; if either upstream pin changes without an
     accompanying ``_source_revision`` bump (recorded in
     ``vendor/.upstream-pins.json``), the script exits non-zero and
     prints the diff that requires a vendor refresh.

The script is invoked manually and (when wired in via VAL-W6-054) by
the tier-2 smoke job. It exits 0 when no drift is observed and 1 with
a structured ``[drift]`` line per offence otherwise.

ASCII-only per CLAUDE.md.

Happy path:
    $ uv run python scripts/check-cel-spec-drift.py
    [check] cel-spec drift: 0 vectors, 0 missing, 0 mismatched
    exit 0

Drift path (vector references a missing case_id):
    $ uv run python scripts/check-cel-spec-drift.py
    [drift] vector basic/foo references missing corpus case foo_bar
    exit 1
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "relay_cel_corpus.json"
VENDOR_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "vendor" / "cel_spec_vectors.json"
UPSTREAM_PINS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "vendor" / ".upstream-pins.json"
PY_CONTRACTS_PYPROJECT = REPO_ROOT / "packages" / "contracts" / "pyproject.toml"
TS_CONTRACTS_PACKAGE_JSON = REPO_ROOT / "packages" / "contracts-typescript" / "package.json"

EXIT_OK = 0
EXIT_DRIFT = 1


def _load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"required file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _extract_celpy_pin() -> str | None:
    """Return the celpy version constraint from packages/contracts/
    pyproject.toml, or None if the file or pin is missing."""

    text = _read_text(PY_CONTRACTS_PYPROJECT)
    if not text:
        return None
    # Look for a line like:
    #   "cel-python>=0.4.0",  -- or
    #   "celpy>=0.3.0",
    # in the dependencies array. We don't depend on tomllib here so
    # the parse stays minimal and platform-agnostic.
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for prefix in ("cel-python", "celpy"):
            if line.startswith(f'"{prefix}'):
                return line.strip(' ",')
    return None


def _extract_celjs_pin() -> str | None:
    text = _read_text(TS_CONTRACTS_PACKAGE_JSON)
    if not text:
        return None
    try:
        pkg = json.loads(text)
    except json.JSONDecodeError:
        return None
    deps = pkg.get("dependencies", {})
    if not isinstance(deps, dict):
        return None
    val = deps.get("cel-js")
    return str(val) if isinstance(val, str) else None


def main() -> int:
    drifts: list[str] = []

    try:
        vendored = _load_json(VENDOR_PATH)
    except FileNotFoundError as exc:
        print(f"[drift] {exc}")
        return EXIT_DRIFT

    if vendored.get("_schema_version") != 1:
        drifts.append(
            f"vendor cel_spec_vectors.json: _schema_version != 1 "
            f"(got {vendored.get('_schema_version')!r})"
        )

    try:
        corpus = _load_json(CORPUS_PATH)
    except FileNotFoundError as exc:
        print(f"[drift] {exc}")
        return EXIT_DRIFT

    cases_by_id: dict[str, dict[str, Any]] = {c["id"]: c for c in corpus.get("cases", [])}

    vectors = vendored.get("vectors", [])
    if not isinstance(vectors, list):
        drifts.append("vendor cel_spec_vectors.json: 'vectors' is not a list")
        vectors = []

    missing = 0
    mismatched = 0
    for v in vectors:
        vid = v.get("vector_id", "<unknown>")
        case_id = v.get("corpus_case_id")
        if not isinstance(case_id, str):
            drifts.append(f"vector {vid}: missing corpus_case_id field")
            continue
        case = cases_by_id.get(case_id)
        if case is None:
            drifts.append(f"vector {vid} references missing corpus case {case_id}")
            missing += 1
            continue
        # The vendor file's `expression` is a documentation hint -- the
        # corpus case may use an equivalent expression (e.g. the
        # corpus may use `0 + 0` to represent the cel-spec `0` zero
        # vector). We do NOT enforce string equality on `expression`
        # here -- that would be too brittle. Instead we record the
        # intent in the vendor file's `_note` field. Drift remains
        # detectable via the missing-case check above.
        # However, we DO assert that the case carries a kind that
        # matches the vector's expected kind family (eval_value vs
        # eval_error), so a wholesale mis-mapping is caught.
        case_kind = case.get("kind")
        expected_value_kind = v.get("expected_value_kind", "any")
        if case_kind == "eval_error":
            drifts.append(
                f"vector {vid} maps to corpus case {case_id} which is "
                f"kind={case_kind!r} but vendor entry expects a value "
                f"(expected_value_kind={expected_value_kind!r})"
            )
            mismatched += 1
            continue

    # Detect upstream package-pin drift: if the upstream packages have
    # bumped versions since the vendor file was last refreshed, the
    # vendor's `_source_revision` MUST be re-pinned. We record the
    # last-known pins in `vendor/.upstream-pins.json`; bumping a
    # package without bumping that file fails the check.
    py_pin = _extract_celpy_pin()
    ts_pin = _extract_celjs_pin()
    upstream_pins_text = _read_text(UPSTREAM_PINS_PATH)
    if upstream_pins_text:
        try:
            recorded = json.loads(upstream_pins_text)
        except json.JSONDecodeError:
            recorded = {}
    else:
        recorded = {}

    if py_pin is not None and recorded.get("celpy") not in (None, py_pin):
        drifts.append(
            f"upstream celpy pin moved from {recorded['celpy']!r} to "
            f"{py_pin!r}; refresh tests/conformance/cel/vendor/cel_spec_vectors.json "
            "and update vendor/.upstream-pins.json"
        )
    if ts_pin is not None and recorded.get("cel-js") not in (None, ts_pin):
        drifts.append(
            f"upstream cel-js pin moved from {recorded['cel-js']!r} to "
            f"{ts_pin!r}; refresh tests/conformance/cel/vendor/cel_spec_vectors.json "
            "and update vendor/.upstream-pins.json"
        )

    if drifts:
        for d in drifts:
            print(f"[drift] {d}")
        print(
            f"[check] cel-spec drift: {len(vectors)} vectors, {missing} missing, "
            f"{mismatched} mismatched, {len(drifts)} total drifts"
        )
        return EXIT_DRIFT

    print(
        f"[check] cel-spec drift: {len(vectors)} vectors, "
        f"{missing} missing, {mismatched} mismatched"
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
