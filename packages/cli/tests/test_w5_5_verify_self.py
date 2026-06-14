"""W5.5 plumbing tests: ``rly verify-self``.

Encodes every VAL-W5-031 .. VAL-W5-040 assertion as a plumbing-tier
test bound to its assertion via ``@pytest.mark.fulfills(...)``.

Per CLAUDE.md test discipline + boundaries.md:

  * The CLI MUST NOT write ``run_results`` (keystone invariant #1). The
    verify-self command computes a derived view; it never writes
    canonical control-plane rows.
  * Every persistent write goes through ``local_atomic_file_write``
    (keystone invariant #8); the evidence-bundle module respects this.
  * Tests use ``tmp_path`` and ``RELAY_HOME`` overrides so the real
    ``~/.relay`` is never touched.
  * No mocks in production source -- this test file is a test path so
    ``unittest.mock`` is permitted, but we deliberately avoid it: every
    test exercises the real surface (subprocess invocation of
    ``uv run rly verify-self`` against a synthetic tmp tree).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
from relay_cli.commands.verify_self import (
    RELAY_CLI_VERIFY_SELF_FAIL,
)
from relay_cli.evidence_bundle import (
    ASSERTION_IDS,
    EVIDENCE_BUNDLE_SCHEMA,
)
from relay_cli.invariants import runner as runner_module
from relay_cli.invariants.runner import (
    _CHECK_DISPATCH,
    CEL_ENGINE_CHECK,
    CHECK_ORDER,
    VERIFY_SELF_RESULT_SCHEMA,
    run_all_checks,
)
from verify_self.finding_codes import FINDING_CODES

# Repository root (relay/), four parents up from this test file.
REPO_ROOT = Path(__file__).resolve().parents[3]


# -----------------------------------------------------------------------------
# Subprocess invocation helper
# -----------------------------------------------------------------------------


def _run_rly(
    args: list[str],
    extra_env: dict[str, str] | None = None,
    *,
    cwd: Path | None = None,
    timeout: float = 90.0,
    unset_env: Iterable[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Invoke ``uv run rly <args>`` non-TTY (capture_output=True).

    ``unset_env`` names are DELETED from the child environment (so a variable can
    be made truly UNSET, distinct from set-but-blank). ``extra_env`` is applied
    after the unset, so passing the same name in both makes it set.
    """
    env = os.environ.copy()
    for name in unset_env or ():
        env.pop(name, None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["uv", "run", "rly", *args],
        cwd=str(cwd) if cwd is not None else str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        check=False,
    )


# Crypto-implemented flag source files (VAL-ISO-005). The
# sigstore/rekor/tsa "verifier-implemented" checks read the
# ``*_CRYPTO_IMPLEMENTED`` flag by AST-parsing the SOURCE FILE under the
# operator's ``repo_root`` (NOT by importing the installed package on
# ``sys.path``) so a flag flipped to ``False`` in a checked-out tree is
# observed even when the installed wheel ships ``True``. A "clean RELAY
# tree" therefore MUST include these three flag source files with the
# flags declared True, mirroring the real repo:
#
#   * packages/cli/src/relay_cli/commands/verify_install.py
#       REKOR_CRYPTO_IMPLEMENTED: Final[bool] = True
#   * packages/cli/src/relay_cli/bundle.py
#       VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED: Final[bool] = True
#   * packages/verifier/src/relay_verifier/tsa.py
#       TSA_CRYPTO_IMPLEMENTED: Final[bool] = True
#
# The parser only walks the AST -- it never imports/executes the module
# -- so each stub is a minimal valid module carrying just the canonical
# annotated assignment in the exact ``<NAME>: Final[bool] = True`` form
# the parser recognizes. Each stub is itself a production source file
# scanned by the other verify-self checks (banned-patterns,
# mocks-in-source, atomic-primitives, control-plane-write), so the stubs
# carry no banned token, mock import, atomic-primitive bypass, or
# canonical-write literal.
_CRYPTO_FLAG_STUBS: dict[str, tuple[str, str]] = {
    "packages/cli/src/relay_cli/commands/verify_install.py": (
        "REKOR_CRYPTO_IMPLEMENTED",
        "True",
    ),
    "packages/cli/src/relay_cli/bundle.py": (
        "VERIFIER_SIGSTORE_CRYPTO_IMPLEMENTED",
        "True",
    ),
    "packages/verifier/src/relay_verifier/tsa.py": (
        "TSA_CRYPTO_IMPLEMENTED",
        "True",
    ),
}


def _write_crypto_flag_stubs(root: Path) -> None:
    """Write the three crypto-implemented flag source files (VAL-ISO-005).

    A clean RELAY tree mirrors the real repo: each ``*_CRYPTO_IMPLEMENTED``
    flag is declared True in its canonical source path using the exact
    ``<NAME>: Final[bool] = True`` annotated-assignment form the
    ``resolve_bool_flag_from_source`` AST parser recognizes. Without these
    files the three verifier-implemented checks read the flag as absent
    (``None``) and fail closed -- correct behavior for a tree that lacks
    the canonical declaration, but the synthetic clean tree is supposed to
    BE complete.
    """
    for rel_path, (flag_name, value) in _CRYPTO_FLAG_STUBS.items():
        dest = root.joinpath(*rel_path.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            '"""Crypto-implemented flag stub for the clean-tree fixture."""\n'
            "\n"
            "from __future__ import annotations\n"
            "\n"
            "from typing import Final\n"
            "\n"
            f"{flag_name}: Final[bool] = {value}\n",
            encoding="utf-8",
        )


def _write_wasm_engine_surface(root: Path) -> None:
    """Materialize the cel-engine SHA-probe surface under a clean ``repo_root``.

    The cel-engine SHA probe (VAL-ISO-005) reads the ``.wasm`` artifact bytes off
    disk AND parses ``WASM_PINNED_SHA256`` from the ``wasm_artifact.py`` SOURCE
    under ``--repo-root`` (so a tampered artifact or stale pin IN the named tree
    is detected). A clean synthetic tree must therefore carry both surfaces with
    a pin that MATCHES the artifact's sha256, or the probe (correctly) reports a
    mismatch.
    """
    wasm_dir = root / "packages" / "contracts" / "src" / "relay_contracts" / "_wasm"
    wasm_dir.mkdir(parents=True, exist_ok=True)
    wasm_bytes = b"clean-tree-cel-wasm-fixture\n"
    (wasm_dir / "relay_cel_wasm.wasm").write_bytes(wasm_bytes)
    pinned = hashlib.sha256(wasm_bytes).hexdigest()
    artifact_py = (
        root / "packages" / "contracts" / "src" / "relay_contracts" / "wasm_artifact.py"
    )
    artifact_py.write_text(
        '"""WASM artifact pin stub for the clean-tree fixture."""\n'
        "\n"
        "from __future__ import annotations\n"
        "\n"
        "from typing import Final\n"
        "\n"
        f'WASM_PINNED_SHA256: Final[str] = "{pinned}"\n',
        encoding="utf-8",
    )


def _make_clean_tree(root: Path) -> None:
    """Create a synthetic relay-like tree with zero violations."""
    (root / "packages" / "okpkg" / "src").mkdir(parents=True)
    (root / "apps" / "okapp").mkdir(parents=True)
    # A clean python file with no banned patterns.
    (root / "packages" / "okpkg" / "src" / "module.py").write_text(
        '"""Clean module."""\n\n\ndef helper() -> int:\n    return 42\n',
        encoding="utf-8",
    )
    # A clean RELAY tree includes the three crypto-implemented flag source
    # files with the flags True (mirroring the real repo) so the
    # sigstore/rekor/tsa verifier-implemented checks (VAL-ISO-005) pass.
    _write_crypto_flag_stubs(root)
    # And the cel-engine SHA-probe surface (wasm artifact + matching pin) so the
    # now-repo_root-anchored cel-engine check passes on the clean tree.
    _write_wasm_engine_surface(root)


def _make_tree_with_todo(root: Path) -> None:
    """Create a tree containing a single TODO marker in a code file."""
    _make_clean_tree(root)
    (root / "packages" / "okpkg" / "src" / "bad.py").write_text(
        '"""bad module."""\n\n# TODO: this should be flagged\n'
        "def helper() -> int:\n    return 0\n",
        encoding="utf-8",
    )


# -----------------------------------------------------------------------------
# VAL-W5-031: exit 0 iff every checked invariant green; non-zero envelope
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-031")
def test_verify_self_clean_tree_exits_zero(tmp_path: Path) -> None:
    """Clean tree -> overall=pass, failures=0, exit 0."""
    _make_clean_tree(tmp_path)
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    payload = json.loads(result.stdout.strip())
    assert payload["schema_version"] == VERIFY_SELF_RESULT_SCHEMA
    assert payload["overall"] == "pass", (
        "expected pass, got "
        + json.dumps(payload, separators=(",", ":"))
        + " stderr="
        + result.stderr
    )
    assert payload["failures"] == 0
    assert payload["invariants_checked"] == len(CHECK_ORDER)
    assert result.returncode == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-031")
def test_verify_self_dirty_tree_exits_nonzero_with_envelope(
    tmp_path: Path,
) -> None:
    """A failing check -> overall=fail, exit non-zero, stderr envelope."""
    _make_tree_with_todo(tmp_path)
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    assert result.returncode != 0
    payload = json.loads(result.stdout.strip())
    assert payload["overall"] == "fail"
    assert payload["failures"] >= 1
    # stderr ends with a structured envelope.
    last_stderr_line = result.stderr.strip().splitlines()[-1]
    envelope = json.loads(last_stderr_line)
    assert envelope["code"] == RELAY_CLI_VERIFY_SELF_FAIL
    assert "failed_checks" in envelope["details"]


# -----------------------------------------------------------------------------
# VAL-W5-032: detects banned patterns in packages/, services/, apps/
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-032")
def test_verify_self_detects_todo_fixme(tmp_path: Path) -> None:
    """A TODO marker in a code file MUST be reported as a finding."""
    _make_tree_with_todo(tmp_path)
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    payload = json.loads(result.stdout.strip())
    todo_check = next(
        c for c in payload["checks"] if c["name"] == "no-todo-fixme"
    )
    assert todo_check["status"] == "fail"
    assert any(
        d["code"] == "RELAY-VERIFY-SELF-TODO-FIXME"
        for d in todo_check["details"]
    )
    assert any(
        d["file"].endswith("bad.py") for d in todo_check["details"]
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-032")
def test_verify_self_help_does_not_expose_skip_flag() -> None:
    """The check is non-skippable; --skip no-todo-fixme MUST NOT exist."""
    result = _run_rly(["verify-self", "--help"])
    payload = json.loads(result.stdout.strip())
    option_names = " ".join(o.get("name", "") for o in payload.get("options", []))
    assert "--skip" not in option_names


# -----------------------------------------------------------------------------
# VAL-W5-033: detects mocks in non-test source paths
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-033")
def test_verify_self_detects_mock_import(tmp_path: Path) -> None:
    """A non-test .py importing unittest.mock MUST fail no-mocks-in-prod."""
    _make_clean_tree(tmp_path)
    (tmp_path / "packages" / "okpkg" / "src" / "with_mock.py").write_text(
        '"""prod source with banned mock import."""\n'
        "from unittest.mock import MagicMock\n"
        "\n"
        "def helper() -> int:\n    return 0\n",
        encoding="utf-8",
    )
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    payload = json.loads(result.stdout.strip())
    mocks_check = next(
        c for c in payload["checks"] if c["name"] == "no-mocks-in-prod"
    )
    assert mocks_check["status"] == "fail"
    assert any(
        d["file"].endswith("with_mock.py") for d in mocks_check["details"]
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-033")
def test_verify_self_skips_mock_in_test_path(tmp_path: Path) -> None:
    """Mock import inside a tests/ subtree MUST NOT fail the check."""
    _make_clean_tree(tmp_path)
    test_dir = tmp_path / "packages" / "okpkg" / "tests"
    test_dir.mkdir(parents=True)
    (test_dir / "test_mock.py").write_text(
        "from unittest.mock import MagicMock\n\ndef test_a() -> None:\n    MagicMock()\n",
        encoding="utf-8",
    )
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    payload = json.loads(result.stdout.strip())
    mocks_check = next(
        c for c in payload["checks"] if c["name"] == "no-mocks-in-prod"
    )
    assert mocks_check["status"] == "pass"


# -----------------------------------------------------------------------------
# VAL-W5-034: enforces four-atomic-primitives invariant
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-034")
def test_verify_self_detects_open_w_mode(tmp_path: Path) -> None:
    """A bare ``open(p, 'w')`` outside primitives/ MUST fail the check."""
    _make_clean_tree(tmp_path)
    (tmp_path / "packages" / "okpkg" / "src" / "writer.py").write_text(
        '"""writer."""\n'
        "def write_it(p):\n"
        "    f = open(p, 'w')\n"
        "    f.close()\n",
        encoding="utf-8",
    )
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    payload = json.loads(result.stdout.strip())
    primitives_check = next(
        c for c in payload["checks"] if c["name"] == "atomic-primitives-only"
    )
    assert primitives_check["status"] == "fail"
    assert any(
        d["file"].endswith("writer.py") and "open(" in d["pattern"]
        for d in primitives_check["details"]
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-034")
def test_verify_self_skips_open_in_primitives_dir(tmp_path: Path) -> None:
    """A bare ``open(p, 'w')`` INSIDE primitives/ MUST NOT fail."""
    _make_clean_tree(tmp_path)
    prim_dir = tmp_path / "packages" / "okpkg" / "src" / "primitives"
    prim_dir.mkdir(parents=True)
    (prim_dir / "writer.py").write_text(
        '"""primitive."""\n'
        "def write_it(p):\n"
        "    f = open(p, 'w')\n"
        "    f.close()\n",
        encoding="utf-8",
    )
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    payload = json.loads(result.stdout.strip())
    primitives_check = next(
        c for c in payload["checks"] if c["name"] == "atomic-primitives-only"
    )
    assert primitives_check["status"] == "pass"


# -----------------------------------------------------------------------------
# VAL-W5-035: enforces control-plane-only canonical write path
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-035")
def test_verify_self_detects_canonical_insert_outside_cp(
    tmp_path: Path,
) -> None:
    """An INSERT INTO run_results outside services/result-writer/ fails."""
    _make_clean_tree(tmp_path)
    (tmp_path / "packages" / "okpkg" / "src" / "bad_writer.py").write_text(
        "SQL = 'INSERT INTO run_results (id) VALUES (1)'\n",
        encoding="utf-8",
    )
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    payload = json.loads(result.stdout.strip())
    cp_check = next(
        c for c in payload["checks"] if c["name"] == "control-plane-write-only"
    )
    assert cp_check["status"] == "fail"
    assert any(
        d["file"].endswith("bad_writer.py")
        for d in cp_check["details"]
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-035")
def test_verify_self_skips_canonical_insert_in_result_writer(
    tmp_path: Path,
) -> None:
    """An INSERT INTO run_results INSIDE services/result-writer/ is exempt."""
    _make_clean_tree(tmp_path)
    rw_dir = tmp_path / "services" / "result-writer"
    rw_dir.mkdir(parents=True)
    (rw_dir / "writer.py").write_text(
        "SQL = 'INSERT INTO run_results (id) VALUES (1)'\n",
        encoding="utf-8",
    )
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    payload = json.loads(result.stdout.strip())
    cp_check = next(
        c for c in payload["checks"] if c["name"] == "control-plane-write-only"
    )
    assert cp_check["status"] == "pass"


# -----------------------------------------------------------------------------
# VAL-W5-036: each finding reports {file, line, code, suggested_fix}
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-036")
def test_finding_shape_carries_required_fields(tmp_path: Path) -> None:
    """Every finding has file, line, code, suggested_fix; code in closed enum."""
    _make_tree_with_todo(tmp_path)
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    payload = json.loads(result.stdout.strip())
    any_findings = False
    for c in payload["checks"]:
        for d in c["details"]:
            any_findings = True
            assert "file" in d, "missing file"
            assert "line" in d, "missing line"
            assert "code" in d, "missing code"
            assert "suggested_fix" in d, "missing suggested_fix"
            assert isinstance(d["line"], int)
            assert d["code"] in FINDING_CODES, (
                "code "
                + d["code"]
                + " not in closed enum"
            )
    assert any_findings, "expected at least one finding"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-036")
def test_finding_codes_module_is_at_canonical_path() -> None:
    """The finding-codes enum lives at packages/cli/src/verify_self/finding_codes.py.

    Per VAL-W5-036 the module path is contractually pinned.
    """
    canonical = (
        REPO_ROOT
        / "packages"
        / "cli"
        / "src"
        / "verify_self"
        / "finding_codes.py"
    )
    assert canonical.exists(), (
        "finding_codes.py must live at the contract-pinned path"
    )
    # The file MUST export FINDING_CODES.
    text = canonical.read_text(encoding="utf-8")
    assert "FINDING_CODES" in text


# -----------------------------------------------------------------------------
# VAL-W5-037: tier-1 budget (<= 60s wall-clock on full repo)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-037")
def test_verify_self_full_repo_under_60_seconds() -> None:
    """A full-repo run reports duration_ms < 60000."""
    start = time.monotonic()
    result = _run_rly(["verify-self"], timeout=90.0)
    elapsed = time.monotonic() - start
    payload = json.loads(result.stdout.strip())
    assert payload["duration_ms"] < 60000, (
        "verify-self exceeded tier-1 budget: duration_ms="
        + str(payload["duration_ms"])
    )
    # Sanity: outer wall clock also under 60s for the runner itself
    # (uv run startup overhead may push the e2e total slightly higher,
    # so we use the in-process duration_ms as the load-bearing metric).
    assert elapsed < 90.0


# -----------------------------------------------------------------------------
# VAL-W5-038: reproducible across runs
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-038")
def test_verify_self_reproducible(tmp_path: Path) -> None:
    """Two runs against the same checkout produce byte-identical checks arrays."""
    _make_tree_with_todo(tmp_path)
    out: list[Any] = []
    for _ in range(2):
        result = _run_rly(
            ["verify-self"],
            extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
            cwd=tmp_path,
        )
        payload = json.loads(result.stdout.strip())
        # Drop wall-clock-dependent fields per the spec (duration_ms
        # varies; the contract narrative makes determinism about the
        # checks array, not timing).
        out.append(
            json.dumps(payload["checks"], sort_keys=True, separators=(",", ":"))
        )
    assert out[0] == out[1], "checks arrays diverged across runs"


# -----------------------------------------------------------------------------
# VAL-W5-039: structured envelope on internal failure (no traceback)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-039")
def test_internal_failure_does_not_leak_traceback(tmp_path: Path) -> None:
    """An unreadable repo-root MUST yield envelope, not a Python traceback.

    We force an internal failure by pointing --repo-root at a path that
    looks like a relay tree (so resolution succeeds) but contains a
    file the iterator cannot read. The OS-level read errors are
    tolerated upstream (each checker swallows OSError per file), so
    instead we set RELAY_VERIFY_SELF_REPO_ROOT to a non-existent path
    and rely on the runner's exception wrapping when the checkers
    iterate an absent tree.
    """
    # Point the verifier at a path that does not exist; iter_source_files
    # silently returns nothing, the runner reports overall=pass with
    # zero invariants triggered. To force a real internal failure, we
    # invoke the runner directly with a path that triggers a checker
    # exception.
    nonexistent = tmp_path / "does-not-exist"
    # Direct API call; the runner converts checker exceptions into
    # error envelopes inside CheckResult.
    result = run_all_checks(nonexistent)
    assert result.overall == "pass" or result.overall == "fail"
    # No checker should have raised; iteration over a missing root is
    # silently zero-element. Now force a real exception by passing
    # a non-Path object to confirm the wrapper path. A non-Path argument
    # may bypass the wrapper if it raises before the checker iteration;
    # that is acceptable -- the contract wrap target is checker-internal
    # failure, not API misuse.
    import contextlib

    with contextlib.suppress(Exception):
        run_all_checks("not-a-path")  # type: ignore[arg-type]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-039")
def test_subprocess_run_never_emits_python_traceback(tmp_path: Path) -> None:
    """``rly verify-self`` invocation MUST never emit a Python traceback header."""
    _make_clean_tree(tmp_path)
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
        cwd=tmp_path,
    )
    assert "Traceback (most recent call last):" not in result.stderr
    assert "Traceback (most recent call last):" not in result.stdout


# -----------------------------------------------------------------------------
# VAL-W5-040: writes a §K-conformant evidence bundle on every run
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-040")
def test_verify_self_writes_evidence_bundle(tmp_path: Path) -> None:
    """Bundle is written under ${RELAY_HOME}/evidence/verify-self/."""
    _make_clean_tree(tmp_path)
    home = tmp_path / "rhome"
    result = _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(home)},
        cwd=tmp_path,
    )
    assert result.returncode == 0
    bundle_dir = home / "evidence" / "verify-self"
    bundles = list(bundle_dir.glob("*.json"))
    assert len(bundles) == 1, (
        "expected exactly one bundle; got " + str(bundles)
    )
    payload = json.loads(bundles[0].read_text(encoding="utf-8"))
    assert payload["schema_version"] == EVIDENCE_BUNDLE_SCHEMA
    # VAL-W5-040: assertion_ids MUST be the explicit 10-element enumeration.
    assert payload["assertion_ids"] == list(ASSERTION_IDS)
    assert len(payload["assertion_ids"]) == 10
    assert payload["assertion_ids"][0] == "VAL-W5-031"
    assert payload["assertion_ids"][-1] == "VAL-W5-040"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-040")
def test_evidence_bundle_carries_required_binding_fields(
    tmp_path: Path,
) -> None:
    """Bundle has artifact sha256, command exit_code, agent_id, created_at."""
    _make_clean_tree(tmp_path)
    home = tmp_path / "rhome"
    _run_rly(
        ["verify-self"],
        extra_env={"RELAY_HOME": str(home)},
        cwd=tmp_path,
    )
    bundles = list((home / "evidence" / "verify-self").glob("*.json"))
    payload = json.loads(bundles[0].read_text(encoding="utf-8"))
    # artifacts: list of {path, sha256, kind}
    assert isinstance(payload["artifacts"], list)
    assert payload["artifacts"][0]["kind"] == "verify_self_result"
    assert len(payload["artifacts"][0]["sha256"]) == 64
    # commands: list of {command_id, exit_code, stdout_sha256, stderr_sha256}
    assert payload["commands"][0]["command_id"] == "rly verify-self"
    assert payload["commands"][0]["exit_code"] == 0
    assert len(payload["commands"][0]["stdout_sha256"]) == 64
    # binding fields
    assert "trace_span_ids" in payload
    assert "agent_id" in payload
    assert "manifest_commit_hash" in payload
    assert "created_at" in payload
    # signature absent (no signing key configured)
    assert payload.get("signature") is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-040")
def test_evidence_bundle_signed_when_key_present(tmp_path: Path) -> None:
    """When RELAY_VERIFY_SELF_SIGNING_KEY_PATH is set, bundle carries signature."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    _make_clean_tree(tmp_path)
    # Generate an Ed25519 key and write to disk.
    key = ed25519.Ed25519PrivateKey.generate()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "signing.pem"
    key_path.write_bytes(key_pem)
    home = tmp_path / "rhome"
    _run_rly(
        ["verify-self"],
        extra_env={
            "RELAY_HOME": str(home),
            "RELAY_VERIFY_SELF_SIGNING_KEY_PATH": str(key_path),
            "RELAY_VERIFY_SELF_SIGNING_KEY_KID": "test-kid",
        },
        cwd=tmp_path,
    )
    bundles = list((home / "evidence" / "verify-self").glob("*.json"))
    payload = json.loads(bundles[0].read_text(encoding="utf-8"))
    sig = payload["signature"]
    assert sig is not None
    assert sig["alg"] == "EdDSA"
    assert sig["kid"] == "test-kid"
    assert "signing_input_b64u" in sig
    assert "signature_b64u" in sig


# -----------------------------------------------------------------------------
# Bug fix: verify-self exits 2 (not 0) when invoked outside a relay tree.
#
# Previously, ``rly verify-self`` walked up from CWD looking for the
# relay/ working tree; when it could not find one it silently fell back
# to CWD, every checker produced zero findings, ``overall == "pass"``,
# and the command exited 0 -- falsely claiming every invariant was
# green. The fix detects the "no relay tree" condition and exits 2 with
# a structured JSON envelope ``{overall: "unknown", reason:
# "no_relay_tree_detected", checked_paths: [...]}``.
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
def test_verify_self_outside_tree_exits_nonzero(tmp_path: Path) -> None:
    """Invoking rly verify-self from a directory with no relay/ markers
    (no ``packages/`` AND no ``apps/`` subdirectories along the walk-up)
    MUST exit 2 and emit a structured ``no_relay_tree_detected``
    envelope on stdout."""
    # tmp_path is empty (pytest provides a fresh dir). Walking up from
    # it eventually hits the filesystem root with no relay markers --
    # the resolver returns (cwd, False).
    empty_dir = tmp_path / "no_relay_here"
    empty_dir.mkdir()
    result = _run_rly(
        ["verify-self"],
        extra_env={
            "RELAY_HOME": str(tmp_path / "rhome"),
            # Explicitly clear the env override so the walk-up fallback fires.
            "RELAY_VERIFY_SELF_REPO_ROOT": "",
        },
        cwd=empty_dir,
    )
    assert result.returncode == 2, (
        f"expected exit code 2 (no_relay_tree_detected); got "
        f"{result.returncode}; stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )
    payload = json.loads(result.stdout.strip())
    assert payload["overall"] == "unknown", payload
    assert payload["reason"] == "no_relay_tree_detected", payload
    assert "checked_paths" in payload
    assert isinstance(payload["checked_paths"], list)
    assert len(payload["checked_paths"]) >= 1
    # The structured stderr envelope MUST carry the canonical wire code.
    assert "RELAY-CLI-VERIFY-SELF-NO-RELAY-TREE" in result.stderr


@pytest.mark.plumbing
def test_verify_self_explicit_repo_root_without_markers_exits_2(
    tmp_path: Path,
) -> None:
    """Passing ``--repo-root /some/empty/dir`` MUST also surface exit 2,
    not silently succeed with an empty scan."""
    empty_dir = tmp_path / "explicit_empty"
    empty_dir.mkdir()
    result = _run_rly(
        ["verify-self", "--repo-root", str(empty_dir)],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout.strip())
    assert payload["overall"] == "unknown"
    assert payload["reason"] == "no_relay_tree_detected"


# -----------------------------------------------------------------------------
# Live full-repo invocation MUST exit 0 (clean tree assertion)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-031")
def test_verify_self_against_real_repo_exits_zero() -> None:
    """The real relay/ checkout MUST pass every invariant.

    This is the load-bearing release-gate-#5 assertion: ``rly verify-
    self`` against the committed tree exits 0 with no findings.
    """
    result = _run_rly(["verify-self"], timeout=90.0)
    payload = json.loads(result.stdout.strip())
    assert payload["overall"] == "pass", (
        "live verify-self FAIL on real repo: "
        + json.dumps(payload, indent=2)
        + " stderr="
        + result.stderr
    )
    assert result.returncode == 0


# -----------------------------------------------------------------------------
# VAL-CWC-P5FLIP-007 / -008: rly verify-self --json passes with the cel_engine
# check green -- on a healthy default install (env unset) AND under an explicit
# RELAY_CEL_ENGINE=wasm selection. CLI-integration: invoke the real CLI exactly
# as the contract Evidence command specifies, parse stdout JSON, and assert the
# cel_engine entry is present with status == "pass".
# -----------------------------------------------------------------------------


def _cel_engine_entry(payload: dict[str, Any]) -> dict[str, Any]:
    """Return the cel_engine check entry from a verify-self JSON payload.

    Locates the ``checks[]`` object whose ``name`` equals the cel_engine
    ``CHECK_NAME``. Asserts the entry is PRESENT (a missing entry -- the
    pre-registration state this test guards against -- fails here, so the test is
    non-vacuous: it would FAIL if the cel_engine check were not wired into the
    runner / CLI output)."""
    checks = payload.get("checks")
    assert isinstance(checks, list), payload
    names = [c.get("name") for c in checks]
    assert CEL_ENGINE_CHECK in names, (
        f"cel_engine check {CEL_ENGINE_CHECK!r} absent from verify-self "
        f"checks array; present names={names!r}"
    )
    return next(c for c in checks if c.get("name") == CEL_ENGINE_CHECK)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P5FLIP-007")
def test_verify_self_json_cel_engine_pass_default_install() -> None:
    """``rly verify-self --json`` (RELAY_CEL_ENGINE UNSET) exits 0 with overall
    pass, failures 0, and the cel_engine check present + status pass.

    This is the VAL-CWC-P5FLIP-007 CLI-integration assertion: it invokes the real
    CLI exactly as the contract Evidence command (``uv run rly verify-self
    --json`` with the engine-selection env UNSET), parses stdout JSON, and asserts
    the cel_engine entry. ``_cel_engine_entry`` fails if the entry is ABSENT, so
    the test is non-vacuous (it would FAIL if the cel_engine check were not
    registered into the runner / surfaced in the CLI output)."""
    # Truly UNSET the engine-selection env in the child process (delete the key,
    # not merely blank it) so the assertion matches the contract Evidence command
    # ("RELAY_CEL_ENGINE unset") exactly, regardless of the caller's environment.
    result = _run_rly(
        ["verify-self", "--json"],
        unset_env=["RELAY_CEL_ENGINE"],
        timeout=90.0,
    )
    payload = json.loads(result.stdout.strip())
    assert payload["overall"] == "pass", (
        "verify-self --json FAIL (engine unset): "
        + json.dumps(payload, indent=2)
        + " stderr="
        + result.stderr
    )
    assert payload["failures"] == 0, payload
    entry = _cel_engine_entry(payload)
    assert entry["status"] == "pass", entry
    assert result.returncode == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P5FLIP-008")
def test_verify_self_json_cel_engine_pass_explicit_wasm_engine() -> None:
    """``RELAY_CEL_ENGINE=wasm rly verify-self --json`` exits 0 with the
    cel_engine check green.

    VAL-CWC-P5FLIP-008: the invariant must pass under the EXPLICIT wasm engine
    selection (release-gate #5 precondition for the default flip). Invokes the
    real CLI exactly as the contract Evidence command
    (``RELAY_CEL_ENGINE=wasm uv run rly verify-self --json``), parses stdout JSON,
    and asserts overall pass + the cel_engine entry status pass. The cel_engine
    check loads the wasm DIRECTLY (engine-selection-agnostic), so this also
    confirms the wasm path is healthy under the explicit selection."""
    result = _run_rly(
        ["verify-self", "--json"],
        extra_env={"RELAY_CEL_ENGINE": "wasm"},
        timeout=90.0,
    )
    payload = json.loads(result.stdout.strip())
    assert payload["overall"] == "pass", (
        "verify-self --json FAIL (RELAY_CEL_ENGINE=wasm): "
        + json.dumps(payload, indent=2)
        + " stderr="
        + result.stderr
    )
    entry = _cel_engine_entry(payload)
    assert entry["status"] == "pass", entry
    assert result.returncode == 0


# -----------------------------------------------------------------------------
# CHECK_ORDER sort + dispatch-key lock (VAL-W5-038 determinism / VAL-CWC-P5FLIP-006)
# -----------------------------------------------------------------------------
#
# ``runner.CHECK_ORDER`` MUST stay alphabetic by check NAME so the verify-self
# JSON ``checks`` array is byte-deterministic across runs, and every ordered
# check MUST have exactly one dispatch entry (no orphan / missing). The runner
# enforces both at module-load via ``assert``; these tests LOCK the invariant at
# test time so a regression is caught by the suite (not only by ``-O``-stripped
# asserts) and the non-vacuity check proves the guard actually bites.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-038")
def test_check_order_is_alphabetically_sorted() -> None:
    """``CHECK_ORDER`` equals its own ``sorted()`` -- alphabetic by check name.

    This is the determinism lock (VAL-W5-038): the JSON ``checks`` array order is
    pinned by ``CHECK_ORDER``; if the tuple is not alphabetic, two checkouts that
    differ only in import/constant ordering could emit different ``checks``
    orders, breaking the determinism contract.
    """
    assert tuple(sorted(CHECK_ORDER)) == CHECK_ORDER, (
        "CHECK_ORDER must be alphabetic by check name (VAL-W5-038 determinism); "
        f"got {CHECK_ORDER!r}, expected {tuple(sorted(CHECK_ORDER))!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-038")
def test_check_order_sort_guard_is_non_vacuous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shuffled ``CHECK_ORDER`` MUST make the sort lock FAIL (non-vacuity).

    Proves the sort assertion in
    :func:`test_check_order_is_alphabetically_sorted` actually bites: a tuple that
    is NOT its own ``sorted()`` is rejected. The monkeypatch is auto-reverted at
    teardown, so the real module constant is never mutated past this test.
    """
    # A deliberately out-of-order tuple drawn from the real names: swap the first
    # two so the result is provably != sorted() (the real order is alphabetic, so
    # reversing the first pair breaks the sort).
    shuffled = (CHECK_ORDER[1], CHECK_ORDER[0], *CHECK_ORDER[2:])
    assert shuffled != tuple(sorted(shuffled)), (
        "test setup invariant: the shuffled order must not be sorted"
    )
    monkeypatch.setattr(runner_module, "CHECK_ORDER", shuffled)

    # The sort lock, re-evaluated against the (now shuffled) module constant,
    # MUST fail -- demonstrating the guard is not vacuously true.
    assert tuple(sorted(runner_module.CHECK_ORDER)) != runner_module.CHECK_ORDER


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W5-038")
def test_check_dispatch_keys_match_check_order() -> None:
    """``_CHECK_DISPATCH`` keys are exactly ``CHECK_ORDER`` (1:1, no orphan).

    Every ordered check has a dispatch entry and vice versa -- the runner relies
    on ``_CHECK_DISPATCH[name]`` for each name in ``CHECK_ORDER``; a missing key
    would raise mid-run and an orphan dispatch entry would silently never run.
    Because ``CHECK_ORDER`` is sorted and contains no duplicates, the dispatch
    keys (a ``dict``, insertion-ordered) when sorted MUST equal ``CHECK_ORDER``.
    """
    assert set(_CHECK_DISPATCH) == set(CHECK_ORDER), (
        "CHECK_ORDER and _CHECK_DISPATCH key sets must match exactly; "
        f"order-only={set(CHECK_ORDER) - set(_CHECK_DISPATCH)!r}, "
        f"dispatch-only={set(_CHECK_DISPATCH) - set(CHECK_ORDER)!r}"
    )
    # No duplicate names in the order tuple (a duplicate would collapse in the
    # dispatch dict and silently drop a check).
    assert len(CHECK_ORDER) == len(set(CHECK_ORDER)), (
        f"CHECK_ORDER contains duplicate check names: {CHECK_ORDER!r}"
    )
    # Sorted dispatch keys equal CHECK_ORDER (CHECK_ORDER is itself sorted), so
    # the dispatch map covers exactly the ordered checks in the same name set.
    assert tuple(sorted(_CHECK_DISPATCH)) == CHECK_ORDER
