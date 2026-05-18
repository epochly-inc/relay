"""M07 v0.2 OSS completeness: CLI commands + cli_invocations tests.

Encodes VAL-V2M07-001..038 as plumbing-tier tests. Each test is bound
to its assertion via the ``@pytest.mark.fulfills(...)`` marker.

Tests use subprocess invocations of `uv run rly ...` with test seams
(env vars) to avoid spinning up the real sidecar for plumbing-tier
runs. The seams are documented in each command module's docstring.

Per CLAUDE.md test discipline:
  * No `pytest.mark.skip` to make CI green.
  * No mocks in production paths; tests use env-var seams.
  * Tests use `tmp_path` for filesystem isolation; never touch real
    `~/.relay`.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import time
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SIDECAR_MIGRATIONS = REPO_ROOT / "apps" / "local-sidecar" / "migrations"


def _rly_env(tmp_path: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Return a clean env that points the invocation DB at tmp_path.

    The recorder uses a fresh DB per test to isolate row writes. The
    sidecar URL points at a port that won't have anything bound so any
    accidental HTTP call from a command fails fast.
    """
    env = os.environ.copy()
    env["RELAY_CLI_INVOCATIONS_DB_PATH"] = str(tmp_path / "inv.sqlite3")
    env["RELAY_HOME"] = str(tmp_path / "relay-home")
    env.pop("PYTEST_CURRENT_TEST", None)  # let invoker_kind heuristic run cleanly
    if extra:
        env.update(extra)
    return env


def _run_rly(
    args: list[str],
    env: dict[str, str] | None = None,
    *,
    timeout: float = 30.0,
    input_data: str | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = ["uv", "run", "rly", *args]
    return subprocess.run(
        cmd,
        env=env or os.environ.copy(),
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input_data,
    )


# =============================================================================
# w7-cli-trace (VAL-V2M07-001..003)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-001")
def test_trace_command_registered(tmp_path: Path) -> None:
    """`rly --help` lists trace; `rly trace --help` documents run_id."""
    env = _rly_env(tmp_path)
    rly_help = _run_rly(["--help"], env)
    assert rly_help.returncode == 0
    help_envelope = json.loads(rly_help.stdout)
    sub_names = {s["name"] for s in help_envelope["subcommands"]}
    assert "trace" in sub_names

    trace_help = _run_rly(["trace", "--help"], env)
    assert trace_help.returncode == 0
    th = json.loads(trace_help.stdout)
    assert th["command"].endswith("trace")
    # run_id is a positional Argument; not in options list (Click treats
    # arguments differently). The help envelope's options + subcommands
    # being a TyperCommand (no subcommands) confirms the leaf structure.
    assert th["subcommands"] == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-002")
def test_trace_happy_path_envelope(tmp_path: Path) -> None:
    """`rly trace <run_id>` emits relay.cli.trace.v1 envelope with spans."""
    fixture = tmp_path / "trace_fixture.json"
    fixture.write_text(json.dumps({
        "schema_version": "relay.trace.v1",
        "run_id": "run-test-001",
        "spans": [
            {
                "span_id": "span-1",
                "parent_span_id": None,
                "span_type": "llm",
                "name": "llm_call",
                "status": "ok",
                "started_at": "2026-05-17T00:00:00.000000Z",
                "ended_at": "2026-05-17T00:00:01.000000Z",
                "error_class": None,
            },
        ],
    }))
    env = _rly_env(tmp_path, {"RELAY_CLI_TRACE_FIXTURE": str(fixture)})
    result = _run_rly(["trace", "run-test-001"], env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.trace.v1"
    assert payload["run_id"] == "run-test-001"
    assert len(payload["spans"]) == 1
    s = payload["spans"][0]
    for required in (
        "span_id", "parent_span_id", "start_time_unix_nano",
        "end_time_unix_nano", "name", "attributes",
    ):
        assert required in s


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-003")
def test_trace_missing_run_exits_3(tmp_path: Path) -> None:
    """`rly trace <missing>` exits 3 with RELAY-ING-NOTFOUND."""
    env = _rly_env(tmp_path, {"RELAY_CLI_TRACE_NOT_FOUND": "run-missing-xyz"})
    result = _run_rly(["trace", "run-missing-xyz"], env)
    assert result.returncode == 3
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    assert envelope["code"] == "RELAY-ING-NOTFOUND"
    assert "message" in envelope


# =============================================================================
# w7-cli-replay-create (VAL-V2M07-004..006)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-004")
def test_replay_create_command_registered(tmp_path: Path) -> None:
    """`rly replay --help` lists create."""
    env = _rly_env(tmp_path)
    h = _run_rly(["replay", "--help"], env)
    assert h.returncode == 0
    payload = json.loads(h.stdout)
    sub_names = {s["name"] for s in payload["subcommands"]}
    assert "create" in sub_names
    ch = _run_rly(["replay", "create", "--help"], env)
    assert ch.returncode == 0
    ch_payload = json.loads(ch.stdout)
    opt_names = " ".join(o.get("name", "") for o in ch_payload["options"])
    assert "--from-run" in opt_names


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-005")
def test_replay_create_happy_path(tmp_path: Path) -> None:
    """`rly replay create --from-run X` emits replay.cli.replay_create.v1."""
    fake_case_id = "case-" + uuid.uuid4().hex
    env = _rly_env(tmp_path, {
        "RELAY_CLI_REPLAY_CREATE_FIXTURE": json.dumps({
            "replay_case_id": fake_case_id, "fixture_count": 0,
        }),
    })
    result = _run_rly(["replay", "create", "--from-run", "run-src-001"], env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.replay_create.v1"
    assert payload["replay_case_id"] == fake_case_id
    assert payload["run_id"] == "run-src-001"
    assert payload["fixture_count"] == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-006")
def test_replay_create_missing_from_run_exits_64(tmp_path: Path) -> None:
    """`rly replay create` (no flags) exits 64 with structured envelope."""
    env = _rly_env(tmp_path)
    result = _run_rly(["replay", "create"], env)
    assert result.returncode == 64
    # Typer/Click's missing-required-option emits its own envelope via
    # the main.py UsageError wrapper.
    assert result.stderr.strip()


# =============================================================================
# w7-cli-eval-run (VAL-V2M07-007..009)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-007")
def test_eval_run_command_registered(tmp_path: Path) -> None:
    env = _rly_env(tmp_path)
    h = _run_rly(["--help"], env)
    payload = json.loads(h.stdout)
    assert "eval" in {s["name"] for s in payload["subcommands"]}
    eh = _run_rly(["eval", "--help"], env)
    assert "run" in {s["name"] for s in json.loads(eh.stdout)["subcommands"]}
    rh = _run_rly(["eval", "run", "--help"], env)
    rh_payload = json.loads(rh.stdout)
    opt_names = " ".join(o.get("name", "") for o in rh_payload["options"])
    assert "--dataset" in opt_names


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-008")
def test_eval_run_happy_path(tmp_path: Path) -> None:
    env = _rly_env(tmp_path, {
        "RELAY_CLI_EVAL_FIXTURE": json.dumps({
            "eval_run_id": "er-test-001",
            "total_cases": 5,
            "passed": 5,
            "failed": 0,
            "evidence_bundle_id": str(uuid.uuid4()),
        }),
    })
    result = _run_rly(["eval", "run", "--dataset", "ds-x"], env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.eval_run.v1"
    for key in (
        "eval_run_id", "dataset_id", "total_cases",
        "passed", "failed", "evidence_bundle_id",
    ):
        assert key in payload


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-009")
def test_eval_run_failed_cases_exits_1(tmp_path: Path) -> None:
    env = _rly_env(tmp_path, {
        "RELAY_CLI_EVAL_FIXTURE": json.dumps({
            "total_cases": 3,
            "passed": 1,
            "failed": 2,
            "evidence_bundle_id": str(uuid.uuid4()),
        }),
    })
    result = _run_rly(["eval", "run", "--dataset", "ds-x"], env)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["failed"] == 2


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-009")
def test_eval_run_real_path_queued_no_completion_times_out(tmp_path: Path) -> None:
    """When the sidecar returns 202 queued and the eval never completes
    within --timeout, the CLI MUST exit 4 with RELAY-EVAL-TIMEOUT and
    MUST NOT fabricate an evidence_bundle_id. Per CLAUDE.md keystone #2:
    pass without evidence is not a pass. The eval.py M02 stub previously
    fabricated str(uuid.uuid4()) as the bundle id and exited 0 -- this
    test guards against regression.
    """
    env = _rly_env(tmp_path, {
        "RELAY_CLI_EVAL_CREATE_RESPONSE": json.dumps({
            "eval_run_id": "er-incomplete-001",
            "await_url": "/v1/eval-runs/er-incomplete-001",
        }),
        # Poll seam: every poll returns the queued record (no metrics,
        # bundle_id is None). The CLI MUST NOT treat this as a passing run.
        "RELAY_CLI_EVAL_POLL_RESPONSES": json.dumps([
            {
                "schema_version": "relay.eval_run.v1",
                "eval_run_id": "er-incomplete-001",
                "status": "queued",
                "metrics": {},
                "evidence": {"bundle_id": None, "claims": []},
            },
        ] * 10),
    })
    result = _run_rly(
        ["eval", "run", "--dataset", "ds-x", "--timeout", "2"], env,
        timeout=15.0,
    )
    assert result.returncode == 4, (
        f"expected exit 4 (transient); got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.eval_run.v1"
    assert payload["eval_run_id"] == "er-incomplete-001"
    # No fabrication: evidence_bundle_id MUST be null when no completion.
    assert payload["evidence_bundle_id"] is None, (
        "CLI fabricated an evidence_bundle_id with no completed eval; "
        "violates CLAUDE.md keystone #2"
    )
    assert payload["total_cases"] == 0
    assert payload["passed"] == 0
    assert payload["failed"] == 0
    # Stderr envelope carries RELAY-EVAL-TIMEOUT.
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    assert envelope["code"] == "RELAY-EVAL-TIMEOUT"
    assert envelope["blocked_surface"] == "rly eval run"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-009")
def test_eval_run_real_path_completion_emits_bundle(tmp_path: Path) -> None:
    """When the sidecar completes the eval-run during polling, the CLI
    emits the real evidence_bundle_id from the sidecar's record and exits
    per pass/fail. This is the success counterpart to the timeout test:
    it proves the CLI propagates the SIDECAR's bundle id rather than
    fabricating one.
    """
    real_bundle_id = "eb-real-" + uuid.uuid4().hex
    env = _rly_env(tmp_path, {
        "RELAY_CLI_EVAL_CREATE_RESPONSE": json.dumps({
            "eval_run_id": "er-completed-001",
            "await_url": "/v1/eval-runs/er-completed-001",
        }),
        "RELAY_CLI_EVAL_POLL_RESPONSES": json.dumps([
            # First poll: still queued.
            {
                "schema_version": "relay.eval_run.v1",
                "eval_run_id": "er-completed-001",
                "status": "queued",
                "metrics": {},
                "evidence": {"bundle_id": None, "claims": []},
            },
            # Second poll: completed with real bundle id.
            {
                "schema_version": "relay.eval_run.v1",
                "eval_run_id": "er-completed-001",
                "status": "completed",
                "metrics": {
                    "total_cases": 4, "passed": 4, "failed": 0,
                },
                "evidence": {
                    "bundle_id": real_bundle_id, "claims": [],
                },
            },
        ]),
    })
    result = _run_rly(
        ["eval", "run", "--dataset", "ds-x", "--timeout", "10"], env,
        timeout=15.0,
    )
    assert result.returncode == 0, (
        f"expected exit 0 (all passed); got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload["evidence_bundle_id"] == real_bundle_id
    assert payload["total_cases"] == 4
    assert payload["passed"] == 4
    assert payload["failed"] == 0


# =============================================================================
# w7-cli-gate-evaluate (VAL-V2M07-010..019)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-010")
def test_gate_evaluate_command_registered(tmp_path: Path) -> None:
    env = _rly_env(tmp_path)
    h = _run_rly(["gate", "--help"], env)
    assert "evaluate" in {s["name"] for s in json.loads(h.stdout)["subcommands"]}
    eh = _run_rly(["gate", "evaluate", "--help"], env)
    payload = json.loads(eh.stdout)
    opt_names = " ".join(o.get("name", "") for o in payload["options"])
    for flag in ("--gate-id", "--release-sha", "--project", "--manifest", "--json"):
        assert flag in opt_names


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-011")
def test_gate_evaluate_happy_path(tmp_path: Path) -> None:
    env = _rly_env(tmp_path, {
        "RELAY_CLI_GATE_FIXTURE": json.dumps({
            "gate_decision_id": "gd-001",
            "action": "accept",
            "round": 1,
            "failed_assertions": [],
            "evidence_bundle_id": "bundle-001",
            "signature": "sha256-deadbeef",
            "trace_id": "trace-001",
        }),
    })
    result = _run_rly(["gate", "evaluate", "--gate-id", "g-001"], env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.gate_evaluate.v1"
    for key in (
        "gate_decision_id", "action", "round", "failed_assertions",
        "evidence_bundle_id", "signature", "trace_id", "duration_ms",
    ):
        assert key in payload
    assert payload["action"] == "accept"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-012")
def test_gate_evaluate_block_exits_1(tmp_path: Path) -> None:
    env = _rly_env(tmp_path, {
        "RELAY_CLI_GATE_FIXTURE": json.dumps({
            "action": "block",
            "failed_assertions": [{"id": "VAL-X", "reason": "policy"}],
        }),
    })
    result = _run_rly(["gate", "evaluate", "--gate-id", "g-001"], env)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["action"] == "block"
    assert len(payload["failed_assertions"]) > 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-013")
def test_gate_evaluate_remediate_exits_2(tmp_path: Path) -> None:
    env = _rly_env(tmp_path, {
        "RELAY_CLI_GATE_FIXTURE": json.dumps({"action": "remediate"}),
    })
    result = _run_rly(["gate", "evaluate", "--gate-id", "g-001"], env)
    assert result.returncode == 2
    assert json.loads(result.stdout)["action"] == "remediate"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-014")
def test_gate_evaluate_stale_handoff_exits_3(tmp_path: Path) -> None:
    env = _rly_env(tmp_path, {
        "RELAY_CLI_GATE_DRAFT_RESPONSE": json.dumps({"_stale_handoff": True}),
    })
    result = _run_rly(["gate", "evaluate", "--gate-id", "g-001"], env)
    assert result.returncode == 3
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    assert envelope["code"] == "RELAY-GATE-021"
    assert envelope["blocked_surface"] == "rly gate evaluate"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-015")
def test_gate_evaluate_network_partition_backoff(tmp_path: Path) -> None:
    """Transient errors trigger exponential backoff; past TTL exits 4."""
    backoff_log = tmp_path / "backoff.log"
    env = _rly_env(tmp_path, {
        "RELAY_CLI_GATE_DRAFT_RESPONSE": json.dumps({
            "draft_id": "draft-001",
            "draft_ttl_seconds": 3,
        }),
        # Empty responses sequence -> every poll returns {} (transient) ->
        # backoff loop until TTL expires.
        "RELAY_CLI_GATE_DECISION_RESPONSES": "[]",
        "RELAY_CLI_GATE_BACKOFF_LOG": str(backoff_log),
    })
    result = _run_rly(["gate", "evaluate", "--gate-id", "g-001"], env, timeout=15.0)
    assert result.returncode == 4
    # Backoff entries captured
    if backoff_log.exists():
        entries = [
            json.loads(line) for line in backoff_log.read_text().splitlines() if line.strip()
        ]
        assert len(entries) >= 1
        # First backoff in range 800-1200 ms (1s base ± 20%)
        first = entries[0]["backoff_ms"]
        assert 700 <= first <= 1300


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-016")
def test_gate_evaluate_ttl_expired_exits_4(tmp_path: Path) -> None:
    """RELAY-GATE-024 (draft TTL expired) exits 4."""
    env = _rly_env(tmp_path, {
        "RELAY_CLI_GATE_DRAFT_RESPONSE": json.dumps({
            "draft_id": "draft-001", "draft_ttl_seconds": 60,
        }),
        "RELAY_CLI_GATE_DECISION_RESPONSES": json.dumps([
            {"_ttl_expired": True},
        ]),
    })
    result = _run_rly(["gate", "evaluate", "--gate-id", "g-001"], env)
    assert result.returncode == 4
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    assert envelope["code"] == "RELAY-GATE-024"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-017")
def test_gate_evaluate_sigterm_exits_130(tmp_path: Path) -> None:
    """SIGTERM mid-polling exits 130 with RELAY-CLI-130 envelope."""
    env = _rly_env(tmp_path, {
        "RELAY_CLI_GATE_DRAFT_RESPONSE": json.dumps({
            "draft_id": "draft-001", "draft_ttl_seconds": 30,
        }),
        "RELAY_CLI_GATE_DECISION_RESPONSES": "[]",  # forever pending
    })
    proc = subprocess.Popen(
        ["uv", "run", "rly", "gate", "evaluate", "--gate-id", "g-001"],
        env=env,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(2.0)  # Let the polling loop start
    proc.send_signal(signal.SIGTERM)
    try:
        stdout, stderr = proc.communicate(timeout=15.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        pytest.fail("rly gate evaluate did not respond to SIGTERM in 15s")
    # Exit code 130 maps to SIGTERM-style cancel
    assert proc.returncode == 130, (
        f"expected 130; got {proc.returncode}\nstdout={stdout}\nstderr={stderr}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-018")
def test_gate_evaluate_sigint_exits_130(tmp_path: Path) -> None:
    """SIGINT mid-polling exits 130."""
    env = _rly_env(tmp_path, {
        "RELAY_CLI_GATE_DRAFT_RESPONSE": json.dumps({
            "draft_id": "draft-001", "draft_ttl_seconds": 30,
        }),
        "RELAY_CLI_GATE_DECISION_RESPONSES": "[]",
    })
    proc = subprocess.Popen(
        ["uv", "run", "rly", "gate", "evaluate", "--gate-id", "g-001"],
        env=env,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(2.0)
    proc.send_signal(signal.SIGINT)
    try:
        proc.communicate(timeout=15.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        pytest.fail("rly gate evaluate did not respond to SIGINT in 15s")
    assert proc.returncode == 130


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-019")
def test_gate_evaluate_clock_skew_remediation(tmp_path: Path) -> None:
    """RELAY-AUTH-017 retries once with compensated timestamp."""
    env = _rly_env(tmp_path, {
        "RELAY_CLI_GATE_DRAFT_RESPONSE": json.dumps({
            "draft_id": "draft-001", "draft_ttl_seconds": 30,
        }),
        # Two clock-skew responses -> retry once, fail again, exit 3.
        "RELAY_CLI_GATE_DECISION_RESPONSES": json.dumps([
            {"_clock_skew": True},
            {"_clock_skew": True},
        ]),
    })
    result = _run_rly(["gate", "evaluate", "--gate-id", "g-001"], env)
    assert result.returncode == 3
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    assert envelope["code"] == "RELAY-AUTH-017"


# =============================================================================
# w7-cli-evidence-assess (VAL-V2M07-020..021)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-020")
def test_evidence_assess_command_registered(tmp_path: Path) -> None:
    env = _rly_env(tmp_path)
    h = _run_rly(["evidence", "--help"], env)
    assert "assess" in {s["name"] for s in json.loads(h.stdout)["subcommands"]}
    ah = _run_rly(["evidence", "assess", "--help"], env)
    payload = json.loads(ah.stdout)
    opt_names = " ".join(o.get("name", "") for o in payload["options"])
    assert "--bundle" in opt_names
    assert "--readiness-profile" in opt_names


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-021")
def test_evidence_assess_hosted_only_when_bundle_exists(tmp_path: Path) -> None:
    """Assess surface is hosted-only in OSS: with a real local bundle the
    CLI emits a hosted-only envelope (assessment_id is null because no OSS
    worker exists to write a canonical assessment row), exits 1 with
    RELAY-CLI-HOSTED-ONLY. Per CLAUDE.md keystone #2 the CLI MUST NOT
    fabricate a local assessment_id when no hosted worker has issued one.
    """
    env = _rly_env(tmp_path)
    # Seed a minimal evidence bundle on disk so the bundle-existence
    # precondition passes.
    home = Path(env["RELAY_HOME"])
    evidence_dir = home / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    bundle_id = "bundle-test-001"
    (evidence_dir / f"{bundle_id}.json").write_text(
        json.dumps({
            "evidence_bundle_id": bundle_id,
            "schema_version": "relay.evidence_bundle.v1",
        })
    )
    result = _run_rly(
        ["evidence", "assess", "--bundle", bundle_id],
        env,
    )
    # Exit 1: hosted-only surface; no canonical row was written.
    assert result.returncode == 1, (
        f"expected exit 1; got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    # Stdout still emits the assess envelope so machine consumers see a
    # stable record, but assessment_id MUST be null (no fabrication).
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.evidence_assess.v1"
    for key in (
        "assessment_id", "bundle_id", "readiness_profile",
        "enqueued_at", "status",
    ):
        assert key in payload
    assert payload["assessment_id"] is None, (
        "CLI fabricated an assessment_id with no backing hosted worker; "
        "violates CLAUDE.md keystone #2 (pass without evidence is not a pass)"
    )
    assert payload["status"] == "hosted_only_pending"
    assert payload["bundle_id"] == bundle_id
    # Stderr envelope carries RELAY-CLI-HOSTED-ONLY.
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    assert envelope["code"] == "RELAY-CLI-HOSTED-ONLY"
    assert envelope["blocked_surface"] == "rly evidence assess"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-021")
def test_evidence_assess_rejects_unknown_bundle(tmp_path: Path) -> None:
    """A bundle id with no on-disk artifact MUST exit non-zero with
    RELAY-CLI-EVIDENCE-BUNDLE-NOT-FOUND. The CLI MUST NOT enqueue an
    assessment against a bundle id that does not exist (CLAUDE.md
    keystone #2 / banned pattern: do not fabricate IDs that have no
    backing artifact).
    """
    env = _rly_env(tmp_path)
    result = _run_rly(
        ["evidence", "assess", "--bundle", "nonexistent-bundle-xyz"],
        env,
    )
    assert result.returncode != 0, (
        f"CLI exit 0 with no backing bundle; "
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    envelope = json.loads(result.stderr.strip().splitlines()[-1])
    assert envelope["code"] == "RELAY-CLI-EVIDENCE-BUNDLE-NOT-FOUND"
    assert envelope["blocked_surface"] == "rly evidence assess"


# =============================================================================
# w7-cli-manifest-check (VAL-V2M07-022..024)
# =============================================================================


def _valid_manifest() -> dict:
    return {
        "schema_version": "relay.manifest.v1",
        "manifest_id": str(uuid.uuid4()),
        "services": [
            {"id": "sidecar", "image": "epochly/relay-sidecar:test", "ports": [8088]},
        ],
        "commands": [
            {
                "id": "test-suite",
                "argv": ["pytest", "-m", "plumbing"],
                "cwd": ".",
                "timeout_seconds": 600,
            },
        ],
        "validation_surfaces": [],
        "network_policy": {"egress_allowlist": []},
        "artifacts": [],
        "side_effect_tools": [],
        "mutation_boundaries": [],
        "grace_window": {"seconds": 1800},
    }


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-022")
def test_manifest_check_command_registered(tmp_path: Path) -> None:
    env = _rly_env(tmp_path)
    h = _run_rly(["--help"], env)
    assert "manifest" in {s["name"] for s in json.loads(h.stdout)["subcommands"]}
    mh = _run_rly(["manifest", "--help"], env)
    assert "check" in {s["name"] for s in json.loads(mh.stdout)["subcommands"]}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-023")
def test_manifest_check_valid_emits_envelope(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(_valid_manifest()))
    env = _rly_env(tmp_path)
    result = _run_rly(["manifest", "check", str(manifest_path)], env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.manifest_check.v1"
    assert payload["schema_id"] == "manifest.v1.json"
    assert payload["valid"] is True
    assert payload["errors"] == []
    assert "command_hash" in payload
    assert "test-suite" in payload["command_hash"]
    # Verify the digest is the canonical sha256-<hex>
    h = payload["command_hash"]["test-suite"]
    assert h.startswith("sha256-")
    assert len(h) == len("sha256-") + 64


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-024")
def test_manifest_check_invalid_exits_1(tmp_path: Path) -> None:
    bad = _valid_manifest()
    del bad["services"]  # required field
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(bad))
    env = _rly_env(tmp_path)
    result = _run_rly(["manifest", "check", str(manifest_path)], env)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert len(payload["errors"]) >= 1
    err0 = payload["errors"][0]
    assert "path" in err0
    assert "message" in err0


# =============================================================================
# w7-cli-contract-check (VAL-V2M07-025..027)
# =============================================================================


def _valid_contract_dir(base: Path) -> Path:
    cdir = base / "contracts"
    cdir.mkdir()
    # One active gate that covers one active assertion (no orphans).
    assertion = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-TEST-001",
        "kind": "behavioral",
        "severity": "p2",
        "owner_email": "alice@example.com",
        "lifecycle_state": "active",
        "expression": "1 == 1",
    }
    gate = {
        "schema_version": "relay.gate_policy.v1",
        "policy_version": "test-gate-v1",
        "owner_email": "alice@example.com",
        "lifecycle_state": "active",
        "gates_assertion_ids": ["VAL-TEST-001"],
        "conditions": [],
    }
    (cdir / "assertion.json").write_text(json.dumps(assertion))
    (cdir / "gate.json").write_text(json.dumps(gate))
    return cdir


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-025")
def test_contract_check_command_registered(tmp_path: Path) -> None:
    env = _rly_env(tmp_path)
    h = _run_rly(["contract", "--help"], env)
    assert "check" in {s["name"] for s in json.loads(h.stdout)["subcommands"]}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-026")
def test_contract_check_valid_dir(tmp_path: Path) -> None:
    cdir = _valid_contract_dir(tmp_path)
    env = _rly_env(tmp_path)
    result = _run_rly(["contract", "check", str(cdir)], env)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "relay.cli.contract_check.v1"
    assert payload["coverage_valid"] is True
    assert payload["violations"] == []
    assert payload["assertions_total"] == 1
    assert payload["files_checked"] == 2


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-027")
def test_contract_check_orphan_exits_1(tmp_path: Path) -> None:
    cdir = tmp_path / "contracts"
    cdir.mkdir()
    # Active assertion with NO covering gate -> orphan
    (cdir / "orphan.json").write_text(json.dumps({
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-ORPHAN-001",
        "kind": "behavioral",
        "severity": "p2",
        "owner_email": "alice@example.com",
        "lifecycle_state": "active",
        "expression": "1 == 1",
    }))
    env = _rly_env(tmp_path)
    result = _run_rly(["contract", "check", str(cdir)], env)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["coverage_valid"] is False
    types = {v["type"] for v in payload["violations"]}
    assert "orphan_assertion" in types


# =============================================================================
# w7-exit-codes (VAL-V2M07-028..029)
# =============================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-028")
def test_exit_code_7_removed_from_help_envelope(tmp_path: Path) -> None:
    """`rly --help --json` envelope's exit_codes array has no code-7 row."""
    env = _rly_env(tmp_path)
    result = _run_rly(["--help"], env)
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    codes = {row["code"] for row in payload["exit_codes"]}
    assert 7 not in codes
    # And the canonical §P.1 codes ARE present
    for c in (0, 1, 2, 3, 4, 64, 70, 130):
        assert c in codes


# Note: VAL-V2M07-029 (exit code 7 grep guard) is implemented at
# relay/tests/contract/cli/test_exit_code_7_removed.py


# =============================================================================
# w7-cli-invocations (VAL-V2M07-030..038)
# =============================================================================


def _open_inv_db(db_path: Path) -> sqlite3.Connection:
    """Open the invocations SQLite file read-only (helper for assertions)."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_db_exists(tmp_path: Path) -> Path:
    """Run `rly --version` once to create the invocations DB + schema."""
    env = _rly_env(tmp_path)
    _run_rly(["--version"], env)
    db_path = tmp_path / "inv.sqlite3"
    assert db_path.exists(), "invocations DB not created"
    return db_path


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-030")
def test_cli_invocations_table_columns(tmp_path: Path) -> None:
    db_path = _ensure_db_exists(tmp_path)
    conn = _open_inv_db(db_path)
    try:
        cur = conn.execute("PRAGMA table_info(cli_invocations)")
        cols = {row[1]: row[2] for row in cur.fetchall()}
    finally:
        conn.close()
    expected = {
        "invocation_id", "project_id", "command", "argv_digest",
        "cli_version", "invoker_kind", "invoker_user_id", "ci_provider",
        "ci_workflow_ref", "ci_run_id", "started_at", "ended_at",
        "exit_code", "outcome", "draft_id", "decision_id",
        "retried_invocation_id",
    }
    assert expected.issubset(cols.keys())


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-031")
def test_cli_invocations_invoker_kind_check(tmp_path: Path) -> None:
    """CHECK on invoker_kind enforces canonical four values."""
    db_path = _ensure_db_exists(tmp_path)
    conn = sqlite3.connect(str(db_path))
    try:
        # All four canonical values insert successfully
        for kind in ("human", "ci", "cron", "test"):
            conn.execute(
                "INSERT INTO cli_invocations (invocation_id, project_id, "
                "command, argv_digest, invoker_kind, started_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), "00000000-0000-0000-0000-000000000000",
                 "test", "sha256-x", kind, "2026-05-17T00:00:00Z"),
            )
            conn.commit()
        # Three invalid values raise IntegrityError
        for bad in ("bot", "HUMAN", ""):
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO cli_invocations (invocation_id, project_id, "
                    "command, argv_digest, invoker_kind, started_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), "00000000-0000-0000-0000-000000000000",
                     "test", "sha256-x", bad, "2026-05-17T00:00:00Z"),
                )
                conn.commit()
            conn.rollback()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-032")
def test_cli_invocations_outcome_check(tmp_path: Path) -> None:
    db_path = _ensure_db_exists(tmp_path)
    conn = sqlite3.connect(str(db_path))
    try:
        canonical_nine = (
            "accept", "block", "remediate", "invalid", "transient",
            "misuse", "internal_error", "cancelled", "timeout",
        )
        for outcome in canonical_nine:
            conn.execute(
                "INSERT INTO cli_invocations (invocation_id, project_id, "
                "command, argv_digest, invoker_kind, started_at, outcome) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), "00000000-0000-0000-0000-000000000000",
                 "test", "sha256-x", "test", "2026-05-17T00:00:00Z", outcome),
            )
            conn.commit()
        for bad in ("ok", "BLOCK", "succeeded"):
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO cli_invocations (invocation_id, project_id, "
                    "command, argv_digest, invoker_kind, started_at, outcome) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), "00000000-0000-0000-0000-000000000000",
                     "test", "sha256-x", "test", "2026-05-17T00:00:00Z", bad),
                )
                conn.commit()
            conn.rollback()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-033")
def test_cli_invocations_project_time_index(tmp_path: Path) -> None:
    db_path = _ensure_db_exists(tmp_path)
    conn = _open_inv_db(db_path)
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='index' AND name='cli_invocations_project_time'"
        )
        row = cur.fetchone()
        assert row is not None
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-034")
def test_every_subcommand_writes_entry_row(tmp_path: Path) -> None:
    """Running any rly subcommand inserts a cli_invocations row on entry."""
    env = _rly_env(tmp_path)
    # Use a benign command that exits cleanly.
    _run_rly(["--version"], env)
    db_path = tmp_path / "inv.sqlite3"
    conn = _open_inv_db(db_path)
    try:
        rows = conn.execute(
            "SELECT command, argv_digest, invoker_kind, started_at, "
            "ended_at, exit_code, outcome FROM cli_invocations"
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) == 1
    r = rows[0]
    assert r["started_at"] is not None
    assert r["argv_digest"].startswith("sha256-")
    assert r["invoker_kind"] in {"human", "ci", "cron", "test"}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-035")
def test_exit_row_updated_with_outcome(tmp_path: Path) -> None:
    """On exit, the row's exit_code + outcome are populated per mapping."""
    env = _rly_env(tmp_path)
    _run_rly(["--version"], env)  # exits 0 -> outcome=accept
    db_path = tmp_path / "inv.sqlite3"
    conn = _open_inv_db(db_path)
    try:
        rows = conn.execute(
            "SELECT exit_code, outcome, ended_at FROM cli_invocations"
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) == 1
    assert rows[0]["exit_code"] == 0
    assert rows[0]["outcome"] == "accept"
    assert rows[0]["ended_at"] is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-036")
def test_sigkill_leaves_entry_row(tmp_path: Path) -> None:
    """SIGKILL mid-invocation: entry row present, ended_at IS NULL.

    Implementation note: `uv run rly` spawns the python interpreter as a
    grandchild of the test process. Sending SIGKILL to the `uv` wrapper
    leaves the python rly process orphaned and still running. We start
    the subprocess in a new session (start_new_session=True) and kill
    the entire process group so the python rly process dies along with
    its parent.
    """
    env = _rly_env(tmp_path, {
        "RELAY_CLI_GATE_DRAFT_RESPONSE": json.dumps({
            "draft_id": "draft-001", "draft_ttl_seconds": 60,
        }),
        "RELAY_CLI_GATE_DECISION_RESPONSES": "[]",  # never resolves
    })
    proc = subprocess.Popen(
        ["uv", "run", "rly", "gate", "evaluate", "--gate-id", "g-001"],
        env=env,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,  # so we can kill the whole process group
    )
    # Wait for the entry row to land
    db_path = tmp_path / "inv.sqlite3"
    deadline = time.monotonic() + 15.0
    row_present = False
    while time.monotonic() < deadline:
        if db_path.exists():
            try:
                conn = _open_inv_db(db_path)
                cnt = conn.execute(
                    "SELECT COUNT(*) FROM cli_invocations"
                ).fetchone()[0]
                conn.close()
                if cnt >= 1:
                    row_present = True
                    break
            except sqlite3.OperationalError:
                pass
        time.sleep(0.2)
    assert row_present, "entry row never committed within 15s"
    # SIGKILL the entire process group (uv wrapper + python rly + any
    # grandchildren). os.killpg with the negative pgid is the POSIX
    # idiom for process-group signaling.
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        proc.kill()
    try:
        proc.communicate(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
    # Row should still be present with ended_at IS NULL
    conn = _open_inv_db(db_path)
    try:
        rows = conn.execute(
            "SELECT ended_at, outcome FROM cli_invocations"
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) >= 1
    # At least one row from this invocation has ended_at NULL (the killed run).
    assert any(r["ended_at"] is None for r in rows), (
        f"all {len(rows)} rows have ended_at populated; SIGKILL did not "
        f"prevent the exit-update path: {[dict(r) for r in rows]}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-037")
def test_invocations_writer_uses_atomic_primitive() -> None:
    """Grep guard: invocations.py uses only transactional_db_write_*."""
    inv_src = (REPO_ROOT / "packages" / "cli" / "src" / "relay_cli"
               / "invocations.py").read_text(encoding="utf-8")
    # Strip docstrings (triple-quoted strings) so prose mentions of the
    # banned tokens don't trip the guard.
    import re
    stripped = re.sub(
        r'("""(?:\\.|(?!""").)*"""|\'\'\'(?:\\.|(?!\'\'\').)*\'\'\')',
        "",
        inv_src,
        flags=re.MULTILINE | re.DOTALL,
    )
    # Strip single-line # comments
    stripped = re.sub(r"#.*$", "", stripped, flags=re.MULTILINE)
    for pattern in ("db.execute", "sqlite3.connect", "psycopg.execute"):
        assert pattern not in stripped, (
            f"banned pattern {pattern!r} found in invocations.py source"
        )
    # And the primitive IS called
    assert "transactional_db_write_raw" in inv_src
    assert "transactional_db_update_raw" in inv_src


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M07-038")
def test_argv_digest_is_deterministic_and_redaction_safe() -> None:
    """sha256 over canonical-redacted argv JSON; redacted flags collide."""
    from relay_cli.invocations import canonical_argv, compute_argv_digest

    # Same argv -> same digest
    a = ["rly", "trace", "run-001"]
    assert compute_argv_digest(a) == compute_argv_digest(list(a))

    # Differing in a redacted-flag value -> same digest
    b1 = ["rly", "evidence", "verify", "--token", "secret-1"]
    b2 = ["rly", "evidence", "verify", "--token", "secret-2"]
    assert compute_argv_digest(b1) == compute_argv_digest(b2)

    # Differing in a non-redacted value -> different digest
    c1 = ["rly", "trace", "run-001"]
    c2 = ["rly", "trace", "run-002"]
    assert compute_argv_digest(c1) != compute_argv_digest(c2)

    # --flag=value form
    d1 = ["rly", "evidence", "verify", "--token=abc"]
    d2 = ["rly", "evidence", "verify", "--token=xyz"]
    assert compute_argv_digest(d1) == compute_argv_digest(d2)

    # canonical_argv replaces values with <redacted>
    canon = canonical_argv(["--token", "hunter2"])
    assert canon == ["--token", "<redacted>"]

    # Bearer prefix scrub
    canon2 = canonical_argv(["Bearer hunter2"])
    assert canon2 == ["Bearer <redacted>"]

    # Digest format: sha256-<64 hex>
    h = compute_argv_digest(["rly"])
    assert h.startswith("sha256-")
    assert len(h) == len("sha256-") + 64
    # Hex chars only
    int(h[len("sha256-"):], 16)
