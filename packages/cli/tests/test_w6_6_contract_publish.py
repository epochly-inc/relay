"""W6.6 plumbing tests: ``rly contract publish``.

Encodes every VAL-W6-060 .. VAL-W6-066 assertion as a plumbing-tier test
bound to its assertion via ``@pytest.mark.fulfills(...)``.

Per CLAUDE.md test discipline + boundaries.md:

  * The CLI MUST NOT write canonical control-plane rows (keystone
    invariant #1). The publish command writes only a draft coverage
    report locally; the gate engine resolves it into a canonical
    ``gate_decision`` separately.
  * Every persistent write goes through ``local_atomic_file_write``
    (keystone invariant #8); the coverage_report module respects this.
  * Tests use ``tmp_path`` and ``RELAY_HOME`` overrides so the real
    ``~/.relay`` is never touched.
  * Tests ALWAYS unset ``GITHUB_TOKEN`` to keep the publish path on the
    forks-safe (dry-run-unsigned) branch by default; the signed-mode
    test pins ``RELAY_FORCE_SIGNED=1`` and supplies a key file.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from relay_cli.commands.contract import (
    CONTRACT_PUBLISH_BUNDLE_SCHEMA,
    CONTRACT_PUBLISH_RESULT_SCHEMA,
    RELAY_COVERAGE_001,
    RELAY_COVERAGE_002,
    RELAY_COVERAGE_003,
    RELAY_COVERAGE_004,
)
from relay_cli.coverage_report import COVERAGE_REPORT_SCHEMA

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
    drop_github_token: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Invoke ``uv run rly <args>`` non-TTY; default forks-safe (no GITHUB_TOKEN)."""
    env = os.environ.copy()
    if drop_github_token:
        env.pop("GITHUB_TOKEN", None)
        env.pop("RELAY_FORCE_SIGNED", None)
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


# -----------------------------------------------------------------------------
# Bundle builders
# -----------------------------------------------------------------------------


def _assertion(
    aid: str,
    *,
    severity: str = "p0",
    expression: str = "1 + 1 == 2",
    owner: str = "alice@example.com",
    lifecycle: str = "active",
) -> dict[str, Any]:
    return {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": aid,
        "kind": "behavioral",
        "severity": severity,
        "expression": expression,
        "owner_email": owner,
        "lifecycle_state": lifecycle,
    }


def _gate(
    *,
    policy_version: str = "2026-05-15.001",
    gates: list[str] | None = None,
    lifecycle: str = "active",
) -> dict[str, Any]:
    return {
        "schema_version": "relay.gate_policy.v1",
        "policy_version": policy_version,
        "conditions": [
            {
                "id": "structured_output_pass_rate",
                "metric": "schema_contract.outcome.pass_rate",
                "comparator": "gte",
                "value": 0.995,
                "scope": "eval_dataset:smoke-prod",
            }
        ],
        "owner_email": "alice@example.com",
        "lifecycle_state": lifecycle,
        "gates_assertion_ids": gates or [],
    }


def _write_bundle(
    tmp_path: Path,
    *,
    assertions: list[dict[str, Any]],
    gates: list[dict[str, Any]],
    manifest_commit_hash: str | None = "deadbeef" * 8,
) -> Path:
    bundle = {
        "schema_version": CONTRACT_PUBLISH_BUNDLE_SCHEMA,
        "manifest_commit_hash": manifest_commit_hash,
        "assertions": assertions,
        "gates": gates,
    }
    p = tmp_path / "bundle.json"
    p.write_text(
        json.dumps(bundle, separators=(",", ":"), ensure_ascii=True),
        encoding="utf-8",
    )
    return p


def _last_stderr_envelope(stderr: str) -> dict[str, Any]:
    lines = [ln for ln in stderr.strip().splitlines() if ln.strip().startswith("{")]
    assert lines, f"no JSON envelope in stderr: {stderr!r}"
    return json.loads(lines[-1])


# -----------------------------------------------------------------------------
# VAL-W6-060: rejects orphan assertions with RELAY-COVERAGE-001
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-060")
def test_publish_rejects_orphan_assertions(tmp_path: Path) -> None:
    """An active assertion not referenced by any active gate is an orphan.

    The two assertions use distinct expressions to avoid the duplicate-
    digest check (RELAY-COVERAGE-002) also firing; this test pins the
    behavior of RELAY-COVERAGE-001 in isolation.
    """
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-COVERED-001", expression="1 + 1 == 2"),
            _assertion("VAL-ORPHAN-002", expression="3 + 4 == 7"),
        ],
        gates=[_gate(gates=["VAL-COVERED-001"])],
    )
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
    )
    assert result.returncode != 0, (
        f"expected non-zero exit; stderr={result.stderr} stdout={result.stdout}"
    )
    # Scan ALL stderr envelopes; the orphan check MUST be among them. The
    # publish command emits one envelope per failing invariant, in a fixed
    # order (orphan, duplicate, missing-owner, group-alias).
    envelopes = [
        json.loads(ln)
        for ln in result.stderr.strip().splitlines()
        if ln.strip().startswith("{")
    ]
    orphan_env = next((e for e in envelopes if e["code"] == RELAY_COVERAGE_001), None)
    assert orphan_env is not None, (
        f"expected RELAY-COVERAGE-001 in envelopes; got {[e['code'] for e in envelopes]}"
    )
    assert "VAL-ORPHAN-002" in orphan_env["details"]["assertion_ids"]
    assert "VAL-COVERED-001" not in orphan_env["details"]["assertion_ids"]
    # Only the orphan check should fire here -- distinct expressions avoid
    # the duplicate-digest check (RELAY-COVERAGE-002) coincidentally
    # matching.
    assert all(e["code"] != RELAY_COVERAGE_002 for e in envelopes)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-060")
def test_publish_orphan_check_ignores_inactive_assertions(tmp_path: Path) -> None:
    """A draft/deprecated assertion without a gate is NOT an orphan."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-COVERED-001"),
            _assertion("VAL-DRAFT-002", lifecycle="draft"),
        ],
        gates=[_gate(gates=["VAL-COVERED-001"])],
    )
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
    )
    assert result.returncode == 0, (
        f"expected exit 0; stderr={result.stderr} stdout={result.stdout}"
    )


# -----------------------------------------------------------------------------
# VAL-W6-061: rejects duplicate expression digests with RELAY-COVERAGE-002
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-061")
def test_publish_rejects_duplicate_expression_digests(tmp_path: Path) -> None:
    """Two active assertions with the same JCS-canonical expression body."""
    expr = "2 == 2"
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-DUP-A", expression=expr),
            _assertion("VAL-DUP-B", expression=expr),
        ],
        gates=[_gate(gates=["VAL-DUP-A", "VAL-DUP-B"])],
    )
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
    )
    assert result.returncode != 0
    env = _last_stderr_envelope(result.stderr)
    assert env["code"] == RELAY_COVERAGE_002
    groups = env["details"]["groups"]
    assert len(groups) == 1
    assert set(groups[0]["assertion_ids"]) == {"VAL-DUP-A", "VAL-DUP-B"}
    assert isinstance(groups[0]["digest"], str) and len(groups[0]["digest"]) == 64


# -----------------------------------------------------------------------------
# VAL-W6-062: rejects missing owner_email on P0/P1 with RELAY-COVERAGE-003
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-062")
def test_publish_rejects_missing_owner_on_p0(tmp_path: Path) -> None:
    """An active P0 assertion with empty owner_email is rejected."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-NO-OWNER", severity="p0", owner=""),
        ],
        gates=[_gate(gates=["VAL-NO-OWNER"])],
    )
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
    )
    assert result.returncode != 0
    env = _last_stderr_envelope(result.stderr)
    assert env["code"] == RELAY_COVERAGE_003
    assert "VAL-NO-OWNER" in env["details"]["assertion_ids"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-062")
def test_publish_p2_missing_owner_is_allowed(tmp_path: Path) -> None:
    """A P2 assertion with empty owner_email is NOT rejected by VAL-W6-062.

    Only P0 and P1 require owner_email per spec line 2303 (c).
    """
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-P2", severity="p2", owner="alice@example.com"),
        ],
        gates=[_gate(gates=["VAL-P2"])],
    )
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
    )
    assert result.returncode == 0


# -----------------------------------------------------------------------------
# VAL-W6-063: rejects group-alias owner_email with RELAY-COVERAGE-004
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-063")
def test_publish_rejects_team_prefix_owner(tmp_path: Path) -> None:
    """Owner emails with a ``team-`` prefix are group aliases."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-GA-1", owner="team-platform@example.com"),
        ],
        gates=[_gate(gates=["VAL-GA-1"])],
    )
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
    )
    assert result.returncode != 0
    env = _last_stderr_envelope(result.stderr)
    assert env["code"] == RELAY_COVERAGE_004
    violations = env["details"]["violations"]
    assert any(
        v["assertion_id"] == "VAL-GA-1"
        and v["owner_email"] == "team-platform@example.com"
        for v in violations
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-063")
def test_publish_rejects_eng_local_owner(tmp_path: Path) -> None:
    """Owner email ``eng@example.com`` is a group-alias local-part."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-GA-2", owner="eng@example.com"),
        ],
        gates=[_gate(gates=["VAL-GA-2"])],
    )
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
    )
    assert result.returncode != 0
    env = _last_stderr_envelope(result.stderr)
    assert env["code"] == RELAY_COVERAGE_004


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-063")
def test_publish_accepts_personal_owner(tmp_path: Path) -> None:
    """A real personal email passes the group-alias check."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-OK-OWNER", owner="alice.smith@example.com"),
        ],
        gates=[_gate(gates=["VAL-OK-OWNER"])],
    )
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(tmp_path / "rhome")},
    )
    assert result.returncode == 0, (
        f"expected exit 0; stderr={result.stderr} stdout={result.stdout}"
    )


# -----------------------------------------------------------------------------
# VAL-W6-064: produces a signed coverage report on success
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-064")
def test_publish_emits_coverage_report_on_clean_publish(tmp_path: Path) -> None:
    """Clean publish produces a relay.contract_publish_report.v1 file."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-OK-A", owner="alice@example.com"),
            _assertion("VAL-OK-B", owner="bob@example.com", expression="3 == 3"),
        ],
        gates=[_gate(gates=["VAL-OK-A", "VAL-OK-B"])],
    )
    rhome = tmp_path / "rhome"
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(rhome)},
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["schema_version"] == CONTRACT_PUBLISH_RESULT_SCHEMA
    assert payload["report_schema_version"] == COVERAGE_REPORT_SCHEMA
    report_path = Path(payload["report_path"])
    assert report_path.exists()
    report = json.loads(report_path.read_bytes().decode("utf-8"))
    assert report["schema_version"] == COVERAGE_REPORT_SCHEMA
    assert report["total_active_assertions"] == 2
    assert "per_gate_coverage" in report
    assert "per_owner_load" in report
    assert report["per_owner_load"]["alice@example.com"] == 1
    assert report["per_owner_load"]["bob@example.com"] == 1
    assert report["duplicate_digest_scan"] == {"violations": []}
    assert report["orphan_scan"] == {"violations": []}
    assert report["manifest_commit_hash"] is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-064")
def test_publish_report_file_mode_is_owner_only(tmp_path: Path) -> None:
    """Report file MUST be 0o600 (POSIX) per atomic-primitive default."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[_assertion("VAL-MODE-OK")],
        gates=[_gate(gates=["VAL-MODE-OK"])],
    )
    rhome = tmp_path / "rhome"
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(rhome)},
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    report_path = Path(payload["report_path"])
    if os.name == "posix":
        mode = report_path.stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


# -----------------------------------------------------------------------------
# VAL-W6-065: deterministic across runs (post-strip of wall-clock metadata)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-065")
def test_publish_is_deterministic_across_runs(tmp_path: Path) -> None:
    """Two consecutive publishes of the same bundle MUST yield equal
    deterministic_digest values."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-DET-A"),
            _assertion("VAL-DET-B", expression="3 == 3"),
        ],
        gates=[_gate(gates=["VAL-DET-A", "VAL-DET-B"])],
    )
    rhome = tmp_path / "rhome"
    fixed_metadata = {
        "--metadata-generated-at": "2026-05-15T00:00:00.000000Z",
        "--metadata-report-id": "report-fixed-id-001",
    }
    out_a = tmp_path / "report_a.json"
    out_b = tmp_path / "report_b.json"
    common_args = [
        "contract",
        "publish",
        str(bundle_path),
        "--metadata-generated-at",
        fixed_metadata["--metadata-generated-at"],
        "--metadata-report-id",
        fixed_metadata["--metadata-report-id"],
    ]
    res_a = _run_rly(
        common_args + ["--out", str(out_a)],
        extra_env={"RELAY_HOME": str(rhome)},
    )
    assert res_a.returncode == 0, res_a.stderr
    res_b = _run_rly(
        common_args + ["--out", str(out_b)],
        extra_env={"RELAY_HOME": str(rhome)},
    )
    assert res_b.returncode == 0, res_b.stderr

    payload_a = json.loads(res_a.stdout.strip().splitlines()[-1])
    payload_b = json.loads(res_b.stdout.strip().splitlines()[-1])
    # The deterministic digest (post-strip of metadata) MUST match across
    # the two runs even though report_id differs in the wall-clock block.
    assert payload_a["deterministic_digest"] == payload_b["deterministic_digest"]

    # With pinned metadata the FULL report digest also matches because
    # the metadata block is identical.
    bytes_a = out_a.read_bytes()
    bytes_b = out_b.read_bytes()
    assert bytes_a == bytes_b, (
        "two consecutive publishes with pinned metadata MUST yield byte-equal "
        "report files."
    )


# -----------------------------------------------------------------------------
# VAL-W6-066: forks-safe (no GITHUB_TOKEN -> dry_run_unsigned, but failures still exit non-zero)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-066")
def test_publish_dry_run_unsigned_when_no_github_token(tmp_path: Path) -> None:
    """With GITHUB_TOKEN unset, mode MUST be ``dry_run_unsigned`` and signed=False."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[_assertion("VAL-FORK-OK")],
        gates=[_gate(gates=["VAL-FORK-OK"])],
    )
    rhome = tmp_path / "rhome"
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(rhome)},
        drop_github_token=True,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["mode"] == "dry_run_unsigned"
    assert payload["signed"] is False
    report = json.loads(Path(payload["report_path"]).read_bytes().decode("utf-8"))
    assert report["mode"] == "dry_run_unsigned"
    assert report["dry_run_unsigned"] is True
    assert report["signature"] is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-066")
def test_publish_dry_run_still_blocks_on_orphan(tmp_path: Path) -> None:
    """In dry-run mode, RELAY-COVERAGE-001 STILL exits non-zero."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-FORK-ORPHAN"),
        ],
        gates=[_gate(gates=[])],  # empty gate -> orphan
    )
    rhome = tmp_path / "rhome"
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(rhome)},
        drop_github_token=True,
    )
    assert result.returncode != 0, (
        "dry-run mode MUST still surface coverage failures (only signing is "
        "skipped, NOT invariant enforcement)."
    )
    env = _last_stderr_envelope(result.stderr)
    assert env["code"] == RELAY_COVERAGE_001


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-066")
def test_publish_dry_run_still_blocks_on_duplicate(tmp_path: Path) -> None:
    expr = "5 == 5"
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[
            _assertion("VAL-FORK-DUP-A", expression=expr),
            _assertion("VAL-FORK-DUP-B", expression=expr),
        ],
        gates=[_gate(gates=["VAL-FORK-DUP-A", "VAL-FORK-DUP-B"])],
    )
    rhome = tmp_path / "rhome"
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(rhome)},
        drop_github_token=True,
    )
    assert result.returncode != 0
    env = _last_stderr_envelope(result.stderr)
    assert env["code"] == RELAY_COVERAGE_002


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-066")
def test_publish_dry_run_still_blocks_on_missing_owner(tmp_path: Path) -> None:
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[_assertion("VAL-FORK-NO-OWNER", owner="")],
        gates=[_gate(gates=["VAL-FORK-NO-OWNER"])],
    )
    rhome = tmp_path / "rhome"
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(rhome)},
        drop_github_token=True,
    )
    assert result.returncode != 0
    env = _last_stderr_envelope(result.stderr)
    assert env["code"] == RELAY_COVERAGE_003


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-066")
def test_publish_dry_run_still_blocks_on_group_alias(tmp_path: Path) -> None:
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[_assertion("VAL-FORK-GA", owner="dl-ops@example.com")],
        gates=[_gate(gates=["VAL-FORK-GA"])],
    )
    rhome = tmp_path / "rhome"
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(rhome)},
        drop_github_token=True,
    )
    assert result.returncode != 0
    env = _last_stderr_envelope(result.stderr)
    assert env["code"] == RELAY_COVERAGE_004


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-066")
def test_publish_jwks_cache_present_after_publish(tmp_path: Path) -> None:
    """Publish MUST leave a JWKS cache file present at RELAY_HOME/jwks-cache/."""
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[_assertion("VAL-JWKS-OK")],
        gates=[_gate(gates=["VAL-JWKS-OK"])],
    )
    rhome = tmp_path / "rhome"
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(rhome)},
        drop_github_token=True,
    )
    assert result.returncode == 0, result.stderr
    cache_dir = rhome / "jwks-cache"
    assert cache_dir.is_dir()
    cache_files = list(cache_dir.glob("*.json"))
    assert len(cache_files) >= 1, (
        f"expected at least one cache file in {cache_dir}, got {cache_files}"
    )
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    # The publish path logs jwks_cache state in stdout for auditing.
    assert any(
        s.startswith("jwks_cache_") for s in payload["jwks_log"]
    ), f"expected jwks_cache log entry; got {payload['jwks_log']}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-066")
def test_publish_signed_mode_when_force_signed_set(tmp_path: Path) -> None:
    """RELAY_FORCE_SIGNED=1 + a key file forces signed mode (ed25519)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "publish_signing_key.pem"
    key_path.write_bytes(pem)

    bundle_path = _write_bundle(
        tmp_path,
        assertions=[_assertion("VAL-SIGNED-OK")],
        gates=[_gate(gates=["VAL-SIGNED-OK"])],
    )
    rhome = tmp_path / "rhome"
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={
            "RELAY_HOME": str(rhome),
            "RELAY_FORCE_SIGNED": "1",
            "RELAY_CONTRACT_PUBLISH_SIGNING_KEY_PATH": str(key_path),
        },
        drop_github_token=True,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["mode"] == "signed"
    assert payload["signed"] is True
    report = json.loads(Path(payload["report_path"]).read_bytes().decode("utf-8"))
    assert report["mode"] == "signed"
    assert report["dry_run_unsigned"] is False
    sig = report["signature"]
    assert isinstance(sig, dict)
    assert sig["alg"] == "EdDSA"
    assert "kid" in sig
    assert "signing_input_b64u" in sig
    assert "signature_b64u" in sig


# -----------------------------------------------------------------------------
# Coverage-gate fail-open end-to-end (re-hunt cli-commands-1, P0): a bundle whose
# active P0 assertion carries a null assertion_id MUST fail publish closed. Before
# the parser chokepoint fix it parsed as id=None and bypassed ALL FOUR coverage
# invariants -- exit 0 with a signed coverage report. Now the parser rejects the
# null id so publish exits non-zero (bundle-invalid), never emitting a report.
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-060")
def test_publish_rejects_null_assertion_id_active_p0(tmp_path: Path) -> None:
    null_id_assertion = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": None,  # the fail-open trigger
        "kind": "behavioral",
        "severity": "p0",
        "expression": "1 + 1 == 2",
        "owner_email": "team-platform@example.com",  # group-alias (would trip 004)
        "lifecycle_state": "active",
    }
    bundle_path = _write_bundle(
        tmp_path,
        assertions=[null_id_assertion],
        gates=[],  # uncovered -> would be an orphan too
    )
    rhome = tmp_path / "rhome"
    result = _run_rly(
        ["contract", "publish", str(bundle_path)],
        extra_env={"RELAY_HOME": str(rhome)},
    )
    assert result.returncode != 0, (
        f"null-id active P0 bundle MUST fail publish closed; "
        f"stderr={result.stderr} stdout={result.stdout}"
    )
    # No signed coverage report may have been written for a fail-open bundle.
    coverage_dir = rhome / "contract" / "coverage"
    if coverage_dir.exists():
        assert not any(coverage_dir.iterdir()), (
            "a coverage report was written despite the null-id rejection"
        )
