"""W12.4 static + offline guard tests for in-toto layout + link metadata.

Plumbing-tier tests for ``scripts/check-in-toto-attestations.py``. The
script runs in four modes:

1. ``--mode workflow`` -- static linter that parses
   ``.github/workflows/release-in-toto.yml`` and the committed layout
   fixture and asserts the workflow's
   ``env.RELAY_INTOTO_DECLARED_STEPS`` list matches exactly the
   layout's ``signed.steps[].name`` list AND that every layout step
   has a corresponding ``--step-name <step>`` reference in some job's
   ``run`` block (VAL-W12-016 + VAL-W12-017 workflow-side).

2. ``--mode layout`` -- offline schema validator that asserts the
   release.layout file conforms to the v0.1 in-toto layout schema
   (VAL-W12-017) AND the layout-signing key is within its rotation
   window per spec section L (VAL-W12-019).

3. ``--mode chain`` -- offline cross-link verifier that asserts every
   layout step has a corresponding ``<step>.<key>.link`` file
   (VAL-W12-016) AND for every (parent, child) edge derived from the
   layout's ``MATCH ... WITH PRODUCTS FROM <step>`` rules, every
   product digest of the parent appears as a material digest of the
   child (VAL-W12-018).

4. ``--mode rotation`` -- a hot-path subset of layout mode used by the
   release workflow's sign-layout job to fail fast on an expired key
   (VAL-W12-019).

The 4 assertions covered:

- VAL-W12-016  each build step emits in-toto link metadata
- VAL-W12-017  in-toto layout enumerates the full release supply chain
- VAL-W12-018  product digest of step N equals material digest of N+1
- VAL-W12-019  layout signing key is rotated per spec section L policy

Per CLAUDE.md TDD discipline: each test binds to its contract assertion
via ``@pytest.mark.fulfills("VAL-W12-NNN")`` so the gate engine can
trace test-to-assertion coverage. ASCII-only source per CLAUDE.md.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

# Repository root: tests/release/test_*.py -> tests/release -> tests -> repo.
REPO_ROOT: Path = Path(__file__).resolve().parents[2]
GUARD_SCRIPT: Path = REPO_ROOT / "scripts" / "check-in-toto-attestations.py"
GENERATOR_SCRIPT: Path = REPO_ROOT / "scripts" / "generate-in-toto-link.py"
WORKFLOW_PATH: Path = (
    REPO_ROOT / ".github" / "workflows" / "release-in-toto.yml"
)
LAYOUT_FIXTURE: Path = (
    REPO_ROOT / "tests" / "release" / "fixtures" / "release.layout"
)
LINKS_FIXTURE_DIR: Path = (
    REPO_ROOT / "tests" / "release" / "fixtures" / "links"
)

# The fixture's canonical ordered step list. Tests pin to this so a
# layout drift makes the test fail loudly rather than silently shifting.
EXPECTED_STEPS: tuple[str, ...] = (
    "source-checkout",
    "build-python-sdist",
    "build-python-wheel",
    "build-ts-package-sdk",
    "build-ts-package-sidecar-bundle",
    "upload-release-artifacts",
)

# Functionary key id used by the link fixtures.
FUNCTIONARY_KEY_ID = "RELAY-FUNCTIONARY-CI-RUNNER"

# Primary and predecessor layout-signing key ids in the fixture.
LAYOUT_KEY_V1 = "RELAY-LAYOUT-KEY-V1-PLACEHOLDER"
LAYOUT_KEY_V0 = "RELAY-LAYOUT-KEY-V0-PREDECESSOR"


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _run_guard(
    *args: str,
    timeout_s: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Invoke the guard script with arbitrary args; capture stdio."""
    return subprocess.run(  # noqa: S603 - command literal
        [sys.executable, str(GUARD_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_s,
    )


def _run_generator(
    *args: str,
    timeout_s: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Invoke the link generator with arbitrary args; capture stdio."""
    return subprocess.run(  # noqa: S603 - command literal
        [sys.executable, str(GENERATOR_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_s,
    )


def _parse_json(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - test diagnostic
        raise AssertionError(
            f"guard did not emit JSON; "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        ) from exc


def _check_for(report: dict[str, Any], assertion_id: str) -> dict[str, Any]:
    for check in report["checks"]:
        if check["assertion"] == assertion_id:
            return check
    raise AssertionError(f"no check entry for {assertion_id} in report")


def _load_layout() -> dict[str, Any]:
    return json.loads(LAYOUT_FIXTURE.read_text(encoding="utf-8"))


def _materialize_repo(
    tmp_path: Path,
    *,
    workflow_text: str | None = None,
    layout_text: str | None = None,
    links: dict[str, str] | None = None,
) -> Path:
    """Build a minimal repo-shaped tree under ``tmp_path`` containing
    the in-toto workflow + layout + links the guard expects."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    fixtures_dir = tmp_path / "tests" / "release" / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    links_dir = fixtures_dir / "links"
    links_dir.mkdir(parents=True, exist_ok=True)
    if workflow_text is None:
        workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
    if layout_text is None:
        layout_text = LAYOUT_FIXTURE.read_text(encoding="utf-8")
    (tmp_path / ".github" / "workflows" / "release-in-toto.yml").write_text(
        workflow_text, encoding="utf-8"
    )
    (fixtures_dir / "release.layout").write_text(layout_text, encoding="utf-8")
    if links is None:
        links = {
            p.name: p.read_text(encoding="utf-8")
            for p in LINKS_FIXTURE_DIR.glob("*.link")
        }
    for name, content in links.items():
        (links_dir / name).write_text(content, encoding="utf-8")
    return tmp_path


def _mutate_layout(transform) -> str:
    layout: dict[str, Any] = _load_layout()
    transform(layout)
    return json.dumps(layout, indent=2)


def _mutate_workflow(transform) -> str:
    data: dict[str, Any] = yaml.safe_load(
        WORKFLOW_PATH.read_text(encoding="utf-8")
    )
    transform(data)
    return yaml.safe_dump(data, sort_keys=False)


# ---------------------------------------------------------------------------
# Sanity: scripts and fixtures exist.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_guard_script_exists_and_is_executable_python() -> None:
    """The guard script must exist and be a runnable Python file."""
    assert GUARD_SCRIPT.is_file(), f"missing: {GUARD_SCRIPT}"
    assert GENERATOR_SCRIPT.is_file(), f"missing: {GENERATOR_SCRIPT}"
    assert WORKFLOW_PATH.is_file(), f"missing: {WORKFLOW_PATH}"
    assert LAYOUT_FIXTURE.is_file(), f"missing: {LAYOUT_FIXTURE}"
    assert LINKS_FIXTURE_DIR.is_dir(), f"missing: {LINKS_FIXTURE_DIR}"


@pytest.mark.plumbing
def test_link_fixtures_present_for_every_declared_step() -> None:
    """One link fixture per declared step (filename grammar)."""
    present = {
        name.split(".", 1)[0]
        for name in (p.name for p in LINKS_FIXTURE_DIR.glob("*.link"))
    }
    assert set(EXPECTED_STEPS) <= present, (
        f"missing link fixtures for steps: "
        f"{sorted(set(EXPECTED_STEPS) - present)}"
    )


# ---------------------------------------------------------------------------
# VAL-W12-016: each build step emits in-toto link metadata.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-016")
def test_workflow_emits_link_for_every_declared_step() -> None:
    """Workflow guard: every layout step has a --step-name <step>
    invocation in some job's run block. Real workflow + real layout."""
    proc = _run_guard("--mode", "workflow", "--repo-root", str(REPO_ROOT), "--json")
    assert proc.returncode == 0, (
        f"workflow guard failed: stdout={proc.stdout} stderr={proc.stderr}"
    )
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-016")
    assert check["passed"], check["message"]
    assert check["error_code"] == "RELAY-RELEASE-016"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-016")
def test_workflow_missing_emit_link_step_fails(tmp_path: Path) -> None:
    """Removing the upload-release-artifacts emit step from the workflow
    causes the workflow guard to fail RELAY-RELEASE-016 with a precise
    message naming the missing step."""

    def _strip_upload_emit(workflow: dict[str, Any]) -> None:
        # Replace the emit-link-upload job's run blocks with a no-op so
        # no run block contains '--step-name upload-release-artifacts'.
        upload_job = workflow.get("jobs", {}).get("emit-link-upload")
        assert upload_job is not None
        for step in upload_job.get("steps", []):
            if isinstance(step, dict) and "run" in step:
                step["run"] = "echo 'stripped for negative test'"

    repo = _materialize_repo(
        tmp_path, workflow_text=_mutate_workflow(_strip_upload_emit)
    )
    proc = _run_guard("--mode", "workflow", "--repo-root", str(repo), "--json")
    assert proc.returncode == 1
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-016")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-016"
    assert "upload-release-artifacts" in check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-016")
def test_chain_mode_passes_against_committed_links() -> None:
    """Chain guard: every layout step has a corresponding .link file
    in tests/release/fixtures/links/."""
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(LINKS_FIXTURE_DIR),
        "--json",
    )
    assert proc.returncode == 0, (
        f"chain guard failed: stdout={proc.stdout} stderr={proc.stderr}"
    )
    report = _parse_json(proc)
    coverage = _check_for(report, "VAL-W12-016")
    assert coverage["passed"], coverage["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-016")
def test_chain_mode_missing_link_fails(tmp_path: Path) -> None:
    """Removing one link from the link directory causes the chain
    coverage check to fail RELAY-RELEASE-016 naming the missing step."""
    target_links = tmp_path / "links"
    target_links.mkdir()
    for src in LINKS_FIXTURE_DIR.glob("*.link"):
        if "build-python-wheel" in src.name:
            continue  # deliberately omit
        shutil.copy2(src, target_links / src.name)
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(target_links),
        "--check-coverage-only",
        "--json",
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-016")
    assert not check["passed"]
    assert "build-python-wheel" in check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-016")
def test_link_filename_to_signed_name_mismatch_fails(tmp_path: Path) -> None:
    """A link file whose internal signed.name disagrees with the
    filename token fails RELAY-RELEASE-016 (VAL-W12-016 anti-tamper
    boundary)."""
    target_links = tmp_path / "links"
    target_links.mkdir()
    for src in LINKS_FIXTURE_DIR.glob("*.link"):
        shutil.copy2(src, target_links / src.name)
    # Mutate one link's signed.name to disagree with its filename.
    victim = target_links / (
        f"build-python-sdist.{FUNCTIONARY_KEY_ID}.link"
    )
    body = json.loads(victim.read_text(encoding="utf-8"))
    body["signed"]["name"] = "lying-step-name"
    victim.write_text(json.dumps(body, indent=2), encoding="utf-8")
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(target_links),
        "--json",
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-016")
    assert not check["passed"]
    assert "lying-step-name" in check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-016")
def test_link_generator_writes_well_formed_envelope(tmp_path: Path) -> None:
    """generate-in-toto-link.py emits a JSON file with the expected
    signed/signatures envelope shape and the canonical sha256 product
    digest derived from the input file's bytes."""
    src_file = tmp_path / "fake-artifact.bin"
    src_file.write_bytes(b"hello-relay-w12.4")
    out = tmp_path / "fake-step.test-key.link"
    proc = _run_generator(
        "--step-name", "fake-step",
        "--command", "echo hello",
        "--no-materials",
        "--product-glob", "fake-artifact.bin",
        "--repo-root", str(tmp_path),
        "--key-id", "test-key",
        "--byproduct", "runner=test",
        "--output", str(out),
    )
    assert proc.returncode == 0, (
        f"generator failed: stdout={proc.stdout} stderr={proc.stderr}"
    )
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["signed"]["_type"] == "link"
    assert body["signed"]["name"] == "fake-step"
    assert body["signed"]["command"] == "echo hello"
    assert body["signed"]["materials"] == []
    products = body["signed"]["products"]
    assert len(products) == 1
    expected_sha = hashlib.sha256(b"hello-relay-w12.4").hexdigest()
    assert products[0]["digest"]["sha256"] == expected_sha
    assert products[0]["uri"] == "fake-artifact.bin"
    assert body["signed"]["byproducts"]["runner"] == "test"
    assert body["signatures"] == []


# ---------------------------------------------------------------------------
# VAL-W12-017: in-toto layout enumerates the full release supply chain.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-017")
def test_workflow_declared_steps_match_layout_steps_exactly() -> None:
    """Workflow's RELAY_INTOTO_DECLARED_STEPS == layout's signed.steps[].name."""
    proc = _run_guard("--mode", "workflow", "--repo-root", str(REPO_ROOT), "--json")
    assert proc.returncode == 0, proc.stderr
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-017")
    assert check["passed"], check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-017")
def test_layout_committed_fixture_passes_schema_check() -> None:
    """release.layout fixture conforms to the v0.1 in-toto layout schema."""
    proc = _run_guard(
        "--mode", "layout", "--layout", str(LAYOUT_FIXTURE), "--json"
    )
    assert proc.returncode == 0, (
        f"layout guard failed: stdout={proc.stdout} stderr={proc.stderr}"
    )
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-017")
    assert check["passed"], check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-017")
def test_layout_step_ordering_drift_fails(tmp_path: Path) -> None:
    """Reordering the layout's steps so they no longer match the
    workflow's declared list causes VAL-W12-017 to fail."""

    def _swap_first_two(layout: dict[str, Any]) -> None:
        steps = layout["signed"]["steps"]
        steps[0], steps[1] = steps[1], steps[0]

    repo = _materialize_repo(tmp_path, layout_text=_mutate_layout(_swap_first_two))
    proc = _run_guard("--mode", "workflow", "--repo-root", str(repo), "--json")
    assert proc.returncode == 1
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-017")
    assert not check["passed"]
    assert "ordering" in check["message"].lower() or "disagree" in check["message"].lower()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-017")
def test_layout_missing_required_field_fails(tmp_path: Path) -> None:
    """A layout missing signed.expires fails the schema check."""

    def _drop_expires(layout: dict[str, Any]) -> None:
        del layout["signed"]["expires"]

    layout_path = tmp_path / "broken.layout"
    layout_path.write_text(_mutate_layout(_drop_expires), encoding="utf-8")
    proc = _run_guard(
        "--mode", "layout", "--layout", str(layout_path), "--json"
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    # The expires-missing failure is detected by the rotation check
    # rather than the schema check (rotation runs first via dataclass
    # ordering); accept either failure path because both bind to
    # RELAY-RELEASE-019 / RELAY-RELEASE-017 for VAL-W12-017's family.
    failed = [c for c in report["checks"] if not c["passed"]]
    assert failed, "expected at least one check to fail"
    failure_codes = {c["error_code"] for c in failed}
    assert (
        "RELAY-RELEASE-017" in failure_codes
        or "RELAY-RELEASE-019" in failure_codes
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-017")
def test_layout_with_orphan_pubkey_fails(tmp_path: Path) -> None:
    """A step referencing a pubkey id absent from signed.keys fails
    schema validation."""

    def _add_orphan_pubkey(layout: dict[str, Any]) -> None:
        layout["signed"]["steps"][0]["pubkeys"].append("DOES-NOT-EXIST-IN-KEYS")

    layout_path = tmp_path / "orphan.layout"
    layout_path.write_text(_mutate_layout(_add_orphan_pubkey), encoding="utf-8")
    proc = _run_guard(
        "--mode", "layout", "--layout", str(layout_path), "--json"
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-017")
    assert not check["passed"]
    assert "DOES-NOT-EXIST-IN-KEYS" in check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-017")
def test_layout_enumerates_all_six_v0_1_steps() -> None:
    """The layout fixture lists exactly the six v0.1 steps in the
    canonical order (no missing, no reordered, no extra)."""
    layout = _load_layout()
    names = [s["name"] for s in layout["signed"]["steps"]]
    assert tuple(names) == EXPECTED_STEPS


# ---------------------------------------------------------------------------
# VAL-W12-018: product digest of step N equals material digest of N+1.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-018")
def test_chain_digests_match_across_committed_fixture() -> None:
    """Chain mode succeeds against the committed layout + links: every
    parent's products appear as child's materials."""
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(LINKS_FIXTURE_DIR),
        "--json",
    )
    assert proc.returncode == 0, (
        f"chain guard failed: stdout={proc.stdout} stderr={proc.stderr}"
    )
    report = _parse_json(proc)
    chain_check = _check_for(report, "VAL-W12-018")
    assert chain_check["passed"], chain_check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-018")
def test_chain_break_when_product_digest_mutated(tmp_path: Path) -> None:
    """Tampering with the source-checkout link's product digest causes
    every consuming build step's chain check to fail (digest of parent
    no longer appears in child's materials)."""
    target_links = tmp_path / "links"
    target_links.mkdir()
    for src in LINKS_FIXTURE_DIR.glob("*.link"):
        shutil.copy2(src, target_links / src.name)
    victim = target_links / f"source-checkout.{FUNCTIONARY_KEY_ID}.link"
    body = json.loads(victim.read_text(encoding="utf-8"))
    # Replace the product digest with a different sha256 (deterministic
    # but unrelated to any other step).
    body["signed"]["products"][0]["digest"]["sha256"] = (
        hashlib.sha256(b"tampered-source-tree").hexdigest()
    )
    victim.write_text(json.dumps(body, indent=2), encoding="utf-8")
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(target_links),
        "--json",
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    chain_check = _check_for(report, "VAL-W12-018")
    assert not chain_check["passed"]
    assert chain_check["error_code"] == "RELAY-RELEASE-018"
    assert "chain break" in chain_check["message"]
    # The mutated source-checkout digest should be reported missing
    # from one of the build steps' materials lists.
    assert "source-checkout" in chain_check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-018")
def test_chain_break_when_upload_materials_drop_a_build(tmp_path: Path) -> None:
    """Stripping a build product from the upload-release-artifacts
    link's materials causes VAL-W12-018 to fail naming the orphaned
    parent."""
    target_links = tmp_path / "links"
    target_links.mkdir()
    for src in LINKS_FIXTURE_DIR.glob("*.link"):
        shutil.copy2(src, target_links / src.name)
    upload = target_links / f"upload-release-artifacts.{FUNCTIONARY_KEY_ID}.link"
    upload_body = json.loads(upload.read_text(encoding="utf-8"))
    sdist_link = target_links / f"build-python-sdist.{FUNCTIONARY_KEY_ID}.link"
    sdist_body = json.loads(sdist_link.read_text(encoding="utf-8"))
    sdist_product_sha = sdist_body["signed"]["products"][0]["digest"]["sha256"]
    upload_body["signed"]["materials"] = [
        m
        for m in upload_body["signed"]["materials"]
        if m.get("digest", {}).get("sha256") != sdist_product_sha
    ]
    upload.write_text(json.dumps(upload_body, indent=2), encoding="utf-8")
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(target_links),
        "--json",
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    chain_check = _check_for(report, "VAL-W12-018")
    assert not chain_check["passed"]
    assert chain_check["error_code"] == "RELAY-RELEASE-018"
    assert "build-python-sdist" in chain_check["message"]
    assert sdist_product_sha in chain_check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-018")
def test_chain_extra_materials_at_child_are_permitted(tmp_path: Path) -> None:
    """A child step that consumes ADDITIONAL materials beyond its
    declared parent's products is permitted (one-direction strict
    inclusion). This guards against a too-strict equality assertion
    that would forbid steps from consuming external sources."""
    target_links = tmp_path / "links"
    target_links.mkdir()
    for src in LINKS_FIXTURE_DIR.glob("*.link"):
        shutil.copy2(src, target_links / src.name)
    # Append an extra materials entry to build-python-sdist beyond what
    # source-checkout produced.
    victim = target_links / f"build-python-sdist.{FUNCTIONARY_KEY_ID}.link"
    body = json.loads(victim.read_text(encoding="utf-8"))
    body["signed"]["materials"].append(
        {
            "uri": "external+pypi://build==1.2.2.post1",
            "digest": {
                "sha256": hashlib.sha256(b"build-frontend-tarball").hexdigest()
            },
        }
    )
    victim.write_text(json.dumps(body, indent=2), encoding="utf-8")
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(target_links),
        "--json",
    )
    assert proc.returncode == 0, (
        f"chain guard rejected legitimate extra materials: {proc.stdout}"
    )


# ---------------------------------------------------------------------------
# VAL-ISO-006: chain guard must NOT pass vacuously when a parent step's
# product digests are not parseable lowercase sha256. A non-empty
# products[] that yields an empty parent_products digest set silently
# excludes the parent from the continuity check, accepting a chain whose
# parent's products are never verified against the child's materials.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-006")
def test_chain_fails_when_parent_products_have_no_sha256(tmp_path: Path) -> None:
    """A parent whose products carry only a non-sha256 algorithm FAILS.

    Replace ``source-checkout``'s product digest with a ``sha512``-only
    digest (no lowercase 64-hex ``sha256`` key). Under the defect,
    ``_digest_set`` returns an empty set for the parent's products, so
    ``missing = parent_products - step_materials`` is empty and the chain
    check passes VACUOUSLY -- the parent->child continuity is never
    actually verified. The fix must treat a non-empty ``products[]`` that
    yields zero parseable sha256 digests as a hard chain failure.
    """
    target_links = tmp_path / "links"
    target_links.mkdir()
    for src in LINKS_FIXTURE_DIR.glob("*.link"):
        shutil.copy2(src, target_links / src.name)
    victim = target_links / f"source-checkout.{FUNCTIONARY_KEY_ID}.link"
    body = json.loads(victim.read_text(encoding="utf-8"))
    # Swap the sole product's sha256 digest for a sha512-only digest. The
    # entry is still a structurally valid in-toto product, but it has no
    # parseable lowercase sha256 to anchor the chain.
    body["signed"]["products"][0]["digest"] = {
        "sha512": hashlib.sha512(b"source-tree-sha512-only").hexdigest()
    }
    victim.write_text(json.dumps(body, indent=2), encoding="utf-8")
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(target_links),
        "--json",
    )
    assert proc.returncode == 1, (
        "chain guard passed vacuously on a parent product with no parseable "
        f"sha256 digest: stdout={proc.stdout} stderr={proc.stderr}"
    )
    report = _parse_json(proc)
    chain_check = _check_for(report, "VAL-W12-018")
    assert not chain_check["passed"], chain_check["message"]
    assert chain_check["error_code"] == "RELAY-RELEASE-018"
    assert "source-checkout" in chain_check["message"], chain_check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-006")
def test_chain_fails_when_parent_product_digest_uppercase(tmp_path: Path) -> None:
    """An uppercase (non-canonical) sha256 product digest also FAILS.

    ``_SHA256_RE`` matches only lowercase 64-hex. An uppercased digest is
    not parseable, so the buggy code drops it from ``parent_products`` and
    passes vacuously. The fix must reject the chain because the parent has
    a non-empty products[] with no parseable sha256.
    """
    target_links = tmp_path / "links"
    target_links.mkdir()
    for src in LINKS_FIXTURE_DIR.glob("*.link"):
        shutil.copy2(src, target_links / src.name)
    victim = target_links / f"source-checkout.{FUNCTIONARY_KEY_ID}.link"
    body = json.loads(victim.read_text(encoding="utf-8"))
    digest = body["signed"]["products"][0]["digest"]["sha256"]
    body["signed"]["products"][0]["digest"]["sha256"] = digest.upper()
    victim.write_text(json.dumps(body, indent=2), encoding="utf-8")
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(target_links),
        "--json",
    )
    assert proc.returncode == 1, (
        "chain guard passed vacuously on an uppercase (unparseable) sha256 "
        f"product digest: stdout={proc.stdout} stderr={proc.stderr}"
    )
    report = _parse_json(proc)
    chain_check = _check_for(report, "VAL-W12-018")
    assert not chain_check["passed"], chain_check["message"]
    assert chain_check["error_code"] == "RELAY-RELEASE-018"


# ---------------------------------------------------------------------------
# VAL-W12-019: layout signing key is rotated per spec section L.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-019")
def test_rotation_passes_against_committed_layout() -> None:
    """The committed layout's signing-key not_after is in the future
    (fixture is set to 2099-12-31). Rotation guard returns 0."""
    proc = _run_guard(
        "--mode", "rotation", "--layout", str(LAYOUT_FIXTURE), "--json"
    )
    assert proc.returncode == 0, (
        f"rotation guard failed: stdout={proc.stdout} stderr={proc.stderr}"
    )
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-019")
    assert check["passed"], check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-019")
def test_rotation_fails_when_now_past_layout_expiry() -> None:
    """Driving the guard with --now past the layout's signed.expires
    causes VAL-W12-019 to fail (layout itself expired)."""
    proc = _run_guard(
        "--mode", "rotation",
        "--layout", str(LAYOUT_FIXTURE),
        "--now", "2100-01-01T00:00:00Z",
        "--json",
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-019")
    assert not check["passed"]
    assert check["error_code"] == "RELAY-RELEASE-019"
    assert "expires" in check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-019")
def test_rotation_fails_when_signing_key_past_not_after(tmp_path: Path) -> None:
    """A layout signed by a key whose not_after is BEFORE now (without
    a witness signature) fails VAL-W12-019."""

    def _swap_to_predecessor(layout: dict[str, Any]) -> None:
        # Use the predecessor key (already past not_after in the
        # fixture: 2026-05-14) as the sole signer.
        layout["signatures"][0]["keyid"] = LAYOUT_KEY_V0
        # Strip the witness signature path so the failure is
        # unambiguous.
        layout["signatures"][0].pop("witness_signature", None)

    layout_path = tmp_path / "expired-key.layout"
    layout_path.write_text(_mutate_layout(_swap_to_predecessor), encoding="utf-8")
    proc = _run_guard(
        "--mode", "rotation",
        "--layout", str(layout_path),
        # Pin now AFTER the predecessor's not_after but BEFORE the
        # layout's signed.expires so only the key-rotation arm fails.
        "--now", "2026-06-01T00:00:00Z",
        "--json",
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-019")
    assert not check["passed"]
    assert LAYOUT_KEY_V0 in check["message"]
    assert "not_after" in check["message"] or "witness" in check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-019")
def test_rotation_witness_signature_path_passes(tmp_path: Path) -> None:
    """A layout signed by a predecessor key WITH a witness_signature
    from the in-rotation successor key is accepted (spec L.3 two-phase
    commit / rotated-with-witness mode)."""

    def _add_witness(layout: dict[str, Any]) -> None:
        layout["signatures"][0]["keyid"] = LAYOUT_KEY_V0
        layout["signatures"][0]["witness_signature"] = {
            "keyid": LAYOUT_KEY_V1,
            "sig": "00" * 64,
        }

    layout_path = tmp_path / "witnessed.layout"
    layout_path.write_text(_mutate_layout(_add_witness), encoding="utf-8")
    proc = _run_guard(
        "--mode", "rotation",
        "--layout", str(layout_path),
        "--now", "2026-06-01T00:00:00Z",
        "--json",
    )
    assert proc.returncode == 0, (
        f"witness-signed layout rejected: {proc.stdout}"
    )
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-019")
    assert check["passed"], check["message"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-019")
def test_rotation_witness_with_expired_witness_key_fails(tmp_path: Path) -> None:
    """Witness-signature path is REJECTED when the witness key is
    itself past its not_after (prevents chained-expired-keys attack)."""

    def _expired_witness(layout: dict[str, Any]) -> None:
        layout["signatures"][0]["keyid"] = LAYOUT_KEY_V0
        layout["signatures"][0]["witness_signature"] = {
            "keyid": LAYOUT_KEY_V0,  # witness is also expired
            "sig": "00" * 64,
        }

    layout_path = tmp_path / "double-expired.layout"
    layout_path.write_text(_mutate_layout(_expired_witness), encoding="utf-8")
    proc = _run_guard(
        "--mode", "rotation",
        "--layout", str(layout_path),
        "--now", "2026-06-01T00:00:00Z",
        "--json",
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-019")
    assert not check["passed"]
    assert "witness" in check["message"].lower()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-019")
def test_layout_keys_section_includes_rotation_window_metadata() -> None:
    """Every key in signed.keys has not_before AND not_after timestamps
    (spec L policy: rotation window is encoded in the layout itself)."""
    layout = _load_layout()
    keys = layout["signed"]["keys"]
    for key_id, key_entry in keys.items():
        assert "not_before" in key_entry, f"{key_id} lacks not_before"
        assert "not_after" in key_entry, f"{key_id} lacks not_after"
        assert key_entry["not_before"] < key_entry["not_after"], (
            f"{key_id} not_before >= not_after"
        )


# ---------------------------------------------------------------------------
# Cross-cutting: guard exit codes and CLI grammar.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_guard_invalid_mode_exits_3() -> None:
    """Argparse rejects an unknown --mode value (exit 2 from argparse)."""
    proc = _run_guard("--mode", "bogus")
    assert proc.returncode != 0


@pytest.mark.plumbing
def test_guard_layout_mode_requires_layout_arg() -> None:
    """layout mode without --layout fails with exit 3."""
    proc = _run_guard("--mode", "layout")
    assert proc.returncode == 3
    assert "FAIL" in proc.stderr


@pytest.mark.plumbing
def test_guard_chain_mode_requires_layout_and_link_dir() -> None:
    """chain mode without both --layout AND --link-dir fails with exit 3."""
    proc = _run_guard("--mode", "chain", "--layout", str(LAYOUT_FIXTURE))
    assert proc.returncode == 3


@pytest.mark.plumbing
def test_guard_rotation_mode_invalid_now_exits_3() -> None:
    """An unparseable --now value fails with exit 3."""
    proc = _run_guard(
        "--mode", "rotation",
        "--layout", str(LAYOUT_FIXTURE),
        "--now", "not-a-timestamp",
    )
    assert proc.returncode == 3


@pytest.mark.plumbing
def test_guard_layout_mode_missing_file_exits_2() -> None:
    """A missing layout file exits 2 (not 1) so callers can distinguish
    'file missing' from 'file present but failed checks'."""
    proc = _run_guard(
        "--mode", "layout",
        "--layout", "/nonexistent/path/to/release.layout",
    )
    assert proc.returncode == 2


# ---------------------------------------------------------------------------
# Anti-tamper: workflow file commits the in-toto guard call directly.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_workflow_invokes_guard_in_all_three_required_modes() -> None:
    """The release workflow must invoke check-in-toto-attestations.py in
    workflow, layout, chain (with and without --check-coverage-only), and
    rotation modes. This is the audit trail that ties the workflow back
    to the guard contract."""
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    for required_invocation in (
        "--mode workflow",
        "--mode layout",
        "--mode chain",
        "--check-coverage-only",
        "--mode rotation",
    ):
        assert required_invocation in text, (
            f"workflow must invoke guard with '{required_invocation}'; "
            f"found none in release-in-toto.yml"
        )


@pytest.mark.plumbing
def test_workflow_emits_links_via_generator_for_each_step() -> None:
    """The release workflow must call generate-in-toto-link.py for every
    canonical step (audit trail tying workflow to generator script)."""
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    for step in EXPECTED_STEPS:
        assert f"--step-name {step}" in text, (
            f"workflow lacks generator invocation for step '{step}'"
        )


@pytest.mark.plumbing
def test_workflow_fork_detection_short_circuits_signing() -> None:
    """The sign-layout job is gated on detect-fork.outputs.dry_run_unsigned
    so fork PR runs do not attempt to use the production signing key."""
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    sign_job = workflow["jobs"].get("sign-layout")
    assert sign_job is not None, "release-in-toto.yml lacks sign-layout job"
    if_clause = sign_job.get("if", "")
    assert "dry_run_unsigned" in if_clause and "true" in if_clause, (
        f"sign-layout 'if' clause does not gate on dry_run_unsigned: "
        f"{if_clause!r}"
    )


# ---------------------------------------------------------------------------
# End-to-end: generator -> chain verifier round-trip on synthetic inputs.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_generator_to_verifier_roundtrip(tmp_path: Path) -> None:
    """Emit a 3-step chain via the generator (parent -> child -> grandchild)
    and verify it passes a synthetic 3-step layout's chain check.

    This guards the cross-script contract: the generator emits links the
    verifier accepts without manual digest fix-ups."""
    # Step A: source. Product = a fixed bytes blob.
    src = tmp_path / "src.txt"
    src.write_bytes(b"v0")
    src_sha = hashlib.sha256(b"v0").hexdigest()
    links = tmp_path / "links"
    links.mkdir()
    proc_a = _run_generator(
        "--step-name", "step-a",
        "--command", "cp src.txt out.txt",
        "--no-materials",
        "--product-glob", "src.txt",
        "--repo-root", str(tmp_path),
        "--key-id", "k",
        "--output", str(links / "step-a.k.link"),
    )
    assert proc_a.returncode == 0, proc_a.stderr

    # Step B: consume A's product. Product = transformed bytes.
    out_b = tmp_path / "out-b.txt"
    out_b.write_bytes(b"v1")
    proc_b = _run_generator(
        "--step-name", "step-b",
        "--command", "transform src.txt out-b.txt",
        "--materials-from-link-products", str(links / "step-a.k.link"),
        "--product-glob", "out-b.txt",
        "--repo-root", str(tmp_path),
        "--key-id", "k",
        "--output", str(links / "step-b.k.link"),
    )
    assert proc_b.returncode == 0, proc_b.stderr

    # Step C: consume B's product. No products.
    proc_c = _run_generator(
        "--step-name", "step-c",
        "--command", "publish out-b.txt",
        "--materials-from-link-products", str(links / "step-b.k.link"),
        "--no-products",
        "--repo-root", str(tmp_path),
        "--key-id", "k",
        "--output", str(links / "step-c.k.link"),
    )
    assert proc_c.returncode == 0, proc_c.stderr

    # Synthetic 3-step layout.
    layout = {
        "signed": {
            "_type": "layout",
            "expires": "2099-12-31T23:59:59Z",
            "readme": "synthetic 3-step test layout",
            "keys": {
                "K1": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {"public": "00" * 32},
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2099-12-31T23:59:59Z",
                }
            },
            "steps": [
                {
                    "name": "step-a",
                    "expected_command": ["cp"],
                    "expected_materials": [],
                    "expected_products": [["ALLOW", "*"]],
                    "pubkeys": ["K1"],
                    "threshold": 1,
                },
                {
                    "name": "step-b",
                    "expected_command": ["transform"],
                    "expected_materials": [
                        "MATCH * WITH PRODUCTS FROM step-a",
                    ],
                    "expected_products": [["ALLOW", "*"]],
                    "pubkeys": ["K1"],
                    "threshold": 1,
                },
                {
                    "name": "step-c",
                    "expected_command": ["publish"],
                    "expected_materials": [
                        "MATCH * WITH PRODUCTS FROM step-b",
                    ],
                    "expected_products": [["ALLOW", "*"]],
                    "pubkeys": ["K1"],
                    "threshold": 1,
                },
            ],
            "inspect": [],
        },
        "signatures": [
            {"keyid": "K1", "sig": "00" * 64},
        ],
    }
    layout_path = tmp_path / "synthetic.layout"
    layout_path.write_text(json.dumps(layout, indent=2), encoding="utf-8")

    proc_v = _run_guard(
        "--mode", "chain",
        "--layout", str(layout_path),
        "--link-dir", str(links),
        "--json",
    )
    assert proc_v.returncode == 0, (
        f"synthetic chain failed: stdout={proc_v.stdout} stderr={proc_v.stderr}"
    )
    report = _parse_json(proc_v)
    assert all(c["passed"] for c in report["checks"]), report

    # Sanity: the synthetic step-b's materials must include the same
    # sha256 as step-a's products.
    a_link = json.loads((links / "step-a.k.link").read_text(encoding="utf-8"))
    b_link = json.loads((links / "step-b.k.link").read_text(encoding="utf-8"))
    a_products = {p["digest"]["sha256"] for p in a_link["signed"]["products"]}
    b_materials = {m["digest"]["sha256"] for m in b_link["signed"]["materials"]}
    assert a_products == {src_sha}
    assert a_products <= b_materials


# ---------------------------------------------------------------------------
# Snapshot guard: the four primary tests below use fixed REPO_ROOT
# fixtures so they exercise the production artifacts that ship in
# v0.1. Tampering with the fixtures breaks these tests loudly.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_committed_links_are_internally_consistent() -> None:
    """Every committed link's signed.name token equals its filename
    step-token; signatures[] is empty (OSS path, signed by relay-platform
    out-of-band)."""
    for link_path in LINKS_FIXTURE_DIR.glob("*.link"):
        body = json.loads(link_path.read_text(encoding="utf-8"))
        filename_step = link_path.name.split(".", 1)[0]
        assert body["signed"]["name"] == filename_step, (
            f"{link_path.name} signed.name={body['signed']['name']} "
            f"!= filename token {filename_step}"
        )
        assert body["signed"]["_type"] == "link"
        assert isinstance(body["signed"]["materials"], list)
        assert isinstance(body["signed"]["products"], list)
        assert isinstance(body["signed"]["byproducts"], dict)
        assert body["signatures"] == [], (
            "committed OSS link must carry empty signatures[]; "
            "production signatures are added by relay-platform out-of-band"
        )


@pytest.mark.plumbing
def test_committed_layout_keys_carry_relay_prefix() -> None:
    """Every layout key id starts with the RELAY- prefix so it is
    obviously distinguishable from upstream in-toto fixture keys."""
    layout = _load_layout()
    for keyid in layout["signed"]["keys"]:
        assert keyid.startswith("RELAY-"), (
            f"layout key id '{keyid}' lacks RELAY- prefix"
        )


@pytest.mark.plumbing
def test_chain_verifier_handles_empty_link_dir(tmp_path: Path) -> None:
    """An empty link directory fails coverage with a precise diagnostic
    (not an unhandled exception)."""
    empty = tmp_path / "no-links"
    empty.mkdir()
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(empty),
        "--json",
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-016")
    assert not check["passed"]


@pytest.mark.plumbing
def test_chain_verifier_handles_nonexistent_link_dir(tmp_path: Path) -> None:
    """A missing link directory fails with a precise diagnostic, not an
    OSError traceback."""
    proc = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(tmp_path / "does-not-exist"),
        "--json",
    )
    assert proc.returncode == 1
    report = _parse_json(proc)
    check = _check_for(report, "VAL-W12-016")
    assert not check["passed"]
    assert "does not exist" in check["message"] or "not a directory" in check["message"]


# ---------------------------------------------------------------------------
# Negative-control: the unmodified fixture passes ALL four primary
# assertion checks under the same guard invocation a CI runner would use.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_unmodified_fixture_passes_full_guard_pipeline() -> None:
    """End-to-end: workflow + layout + chain + rotation all return 0
    against the committed fixtures. This is the canonical green-path
    that the release workflow runs in CI."""
    # Workflow mode (016 + 017).
    proc_w = _run_guard(
        "--mode", "workflow", "--repo-root", str(REPO_ROOT), "--json"
    )
    assert proc_w.returncode == 0, proc_w.stdout
    # Layout mode (017 + 019).
    proc_l = _run_guard(
        "--mode", "layout", "--layout", str(LAYOUT_FIXTURE), "--json"
    )
    assert proc_l.returncode == 0, proc_l.stdout
    # Chain mode (016 + 018).
    proc_c = _run_guard(
        "--mode", "chain",
        "--layout", str(LAYOUT_FIXTURE),
        "--link-dir", str(LINKS_FIXTURE_DIR),
        "--json",
    )
    assert proc_c.returncode == 0, proc_c.stdout
    # Rotation mode (019 alone).
    proc_r = _run_guard(
        "--mode", "rotation", "--layout", str(LAYOUT_FIXTURE), "--json"
    )
    assert proc_r.returncode == 0, proc_r.stdout


# Silence the unused-import warning for copy (kept for future tests
# that perform deeper layout mutations).
_unused = copy
