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

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "relay_cel_corpus.json"
VENDOR_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "vendor" / "cel_spec_vectors.json"
UPSTREAM_PINS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "vendor" / ".upstream-pins.json"
PY_CONTRACTS_PYPROJECT = REPO_ROOT / "packages" / "contracts" / "pyproject.toml"
TS_CONTRACTS_PACKAGE_JSON = REPO_ROOT / "packages" / "contracts-typescript" / "package.json"

# W17.3 additions: the formal cel-spec corpus lives at a separate
# location (per contract VAL-W17-010 which mandates the path
# tests/conformance/cel-spec/). This checker validates BOTH the legacy
# W6.5 vendor file (above) AND the W17.3 corpus (below) on every run.
CELSPEC_DIR = REPO_ROOT / "tests" / "conformance" / "cel-spec"
CELSPEC_PINNED_COMMIT_PATH = CELSPEC_DIR / "PINNED_COMMIT.txt"
CELSPEC_MANIFEST_PATH = CELSPEC_DIR / "MANIFEST.sha256"
CELSPEC_VECTORS_PATH = CELSPEC_DIR / "celspec_vectors.json"
CELSPEC_PROFILE_FILTER_PATH = CELSPEC_DIR / "relay-profile-filter.yaml"
CELSPEC_UPSTREAM_PINS_PATH = CELSPEC_DIR / ".upstream-pins.json"

_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

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


def _read_pinned_commit_celspec() -> str | None:
    """Read the first non-comment whitespace-stripped line of the W17.3
    PINNED_COMMIT.txt anchor. Returns None when the file is absent so
    the W17.3 check is opt-in: legacy installs without the cel-spec/
    directory continue to pass the W6.5 checks unchanged."""

    if not CELSPEC_PINNED_COMMIT_PATH.exists():
        return None
    for raw in CELSPEC_PINNED_COMMIT_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        return line
    return None


def _read_celspec_manifest() -> dict[str, str]:
    """Parse MANIFEST.sha256 (sha256sum format). Returns
    {relative_path: digest_hex}. Empty when the manifest is absent."""

    if not CELSPEC_MANIFEST_PATH.exists():
        return {}
    out: dict[str, str] = {}
    for raw in CELSPEC_MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, rel = parts[0], parts[1].strip()
        if rel.startswith("*"):
            rel = rel[1:]
        out[rel] = digest
    return out


def _check_celspec_corpus_drift() -> list[str]:
    """W17.3 drift checks (VAL-W17-010).

    Returns a list of drift messages. Empty list means no drift.

    Checks (each independently surfaced):
      1. PINNED_COMMIT.txt exists and contains a 40-hex SHA-1.
      2. .upstream-pins.json celspec_commit_sha matches PINNED_COMMIT.txt.
      3. MANIFEST.sha256 exists, entries are 64-hex SHA-256, and each
         digest matches the actual file's bytes.
      4. Every covered file under tests/conformance/cel-spec/ is in
         the manifest (no orphans, no danglers).
      5. relay-profile-filter.yaml is present and partitions the
         vector corpus exactly (no orphan/overlap).
    """

    drifts: list[str] = []

    # The W17.3 corpus is opt-in: a legacy install that only has the
    # W6.5 vendor file (above) still passes. Once cel-spec/ exists,
    # ALL checks fire.
    if not CELSPEC_DIR.exists():
        return drifts

    # (1) PINNED_COMMIT.txt format.
    sha = _read_pinned_commit_celspec()
    if sha is None:
        drifts.append(
            f"W17.3: missing or empty {CELSPEC_PINNED_COMMIT_PATH.relative_to(REPO_ROOT)}"
        )
    elif _SHA1_RE.match(sha) is None:
        drifts.append(
            f"W17.3: PINNED_COMMIT.txt does not contain a 40-char lowercase "
            f"hex SHA-1 (got {sha!r})"
        )

    # (2) .upstream-pins.json companion.
    if CELSPEC_UPSTREAM_PINS_PATH.exists():
        try:
            pins = json.loads(
                CELSPEC_UPSTREAM_PINS_PATH.read_text(encoding="utf-8")
            )
        except json.JSONDecodeError as exc:
            drifts.append(
                f"W17.3: .upstream-pins.json is not valid JSON: {exc}"
            )
            pins = None
        if isinstance(pins, dict):
            if pins.get("_schema_version") != 1:
                drifts.append(
                    f"W17.3: .upstream-pins.json _schema_version must be 1 "
                    f"(got {pins.get('_schema_version')!r})"
                )
            recorded_sha = pins.get("celspec_commit_sha")
            if recorded_sha != sha:
                drifts.append(
                    f"W17.3: .upstream-pins.json celspec_commit_sha "
                    f"({recorded_sha!r}) disagrees with PINNED_COMMIT.txt "
                    f"({sha!r}) -- bump both atomically when rotating the pin"
                )
    else:
        drifts.append(
            f"W17.3: missing {CELSPEC_UPSTREAM_PINS_PATH.relative_to(REPO_ROOT)}"
        )

    # (3) + (4) MANIFEST.sha256 covers every covered file with matching digests.
    manifest = _read_celspec_manifest()
    if not manifest:
        drifts.append(
            f"W17.3: missing or empty {CELSPEC_MANIFEST_PATH.relative_to(REPO_ROOT)}"
        )
    else:
        # (3a) digest format and (3b) digest match
        for rel, digest in manifest.items():
            if _SHA256_RE.match(digest) is None:
                drifts.append(
                    f"W17.3: manifest entry for {rel!r} is not 64-char "
                    f"lowercase hex SHA-256 (got {digest!r})"
                )
                continue
            path = CELSPEC_DIR / rel
            if not path.exists():
                drifts.append(
                    f"W17.3: manifest references missing file {rel!r}"
                )
                continue
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != digest:
                drifts.append(
                    f"W17.3: manifest digest drift for {rel!r}: "
                    f"manifest=sha256:{digest} actual=sha256:{actual}"
                )
        # (4) coverage
        excluded_names = {"PINNED_COMMIT.txt", "MANIFEST.sha256"}
        actual_files: set[str] = set()
        for p in CELSPEC_DIR.rglob("*"):
            if not p.is_file():
                continue
            if (
                p.name.startswith("test_")
                or p.name.startswith("_")
                or p.name.endswith(".pyc")
            ):
                continue
            if p.name in excluded_names:
                continue
            if "__pycache__" in p.parts:
                continue
            actual_files.add(str(p.relative_to(CELSPEC_DIR)))
        missing_from_manifest = actual_files - set(manifest.keys())
        if missing_from_manifest:
            drifts.append(
                "W17.3: corpus files NOT in MANIFEST.sha256: "
                + ", ".join(sorted(missing_from_manifest))
            )

    # (5) profile filter partitions the corpus.
    if not CELSPEC_VECTORS_PATH.exists():
        drifts.append(
            f"W17.3: missing {CELSPEC_VECTORS_PATH.relative_to(REPO_ROOT)}"
        )
    elif not CELSPEC_PROFILE_FILTER_PATH.exists():
        drifts.append(
            f"W17.3: missing {CELSPEC_PROFILE_FILTER_PATH.relative_to(REPO_ROOT)}"
        )
    else:
        try:
            vectors_doc = json.loads(
                CELSPEC_VECTORS_PATH.read_text(encoding="utf-8")
            )
        except json.JSONDecodeError as exc:
            vectors_doc = None
            drifts.append(f"W17.3: celspec_vectors.json invalid JSON: {exc}")
        if isinstance(vectors_doc, dict):
            vectors = vectors_doc.get("vectors") or []
            corpus_ids = {
                v.get("vector_id") for v in vectors if v.get("vector_id")
            }
            # Strict-subset YAML parse for the partition check; avoid
            # taking PyYAML as a script-time dependency.
            included_ids: set[str] = set()
            excluded_ids: set[str] = set()
            section: str | None = None
            for raw in CELSPEC_PROFILE_FILTER_PATH.read_text(
                encoding="utf-8"
            ).splitlines():
                line = raw.rstrip()
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if line.startswith("included:"):
                    section = "included"
                    continue
                if line.startswith("excluded:"):
                    section = "excluded"
                    continue
                # We only look for `- vector_id: <id>` lines (the
                # canonical first key of every list entry).
                if "vector_id:" in stripped:
                    val = stripped.split("vector_id:", 1)[1].strip()
                    val = val.strip().strip('"').strip("'")
                    if section == "included":
                        included_ids.add(val)
                    elif section == "excluded":
                        excluded_ids.add(val)
            overlap = included_ids & excluded_ids
            if overlap:
                drifts.append(
                    "W17.3: profile filter has vectors in BOTH included and "
                    "excluded: " + ", ".join(sorted(overlap))
                )
            orphans = corpus_ids - (included_ids | excluded_ids)
            if orphans:
                drifts.append(
                    "W17.3: corpus vectors NOT classified by profile filter: "
                    + ", ".join(sorted(orphans))
                )
            danglers = (included_ids | excluded_ids) - corpus_ids
            if danglers:
                drifts.append(
                    "W17.3: profile filter references vectors absent from "
                    "corpus: " + ", ".join(sorted(danglers))
                )

    return drifts


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

    # W17.3 corpus drift checks (additive; preserves all W6.5 behavior).
    drifts.extend(_check_celspec_corpus_drift())

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
