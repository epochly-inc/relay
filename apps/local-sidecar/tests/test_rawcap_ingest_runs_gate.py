"""Default-deny raw_capture gate on POST /v1/ingest/runs (bug-hunt 2026-05-28).

Reproduces the keystone-#7 bypass tracked as VAL-RAWCAP-001 (HIGH) and
VAL-RAWCAP-002 (MED): the ``v1_ingest_runs`` handler docstring lists step 7
as "Defense-in-depth raw_capture rejection (M08 W8)" but the handler body
never called ``evaluate_raw_capture_on_request``. A runs envelope carrying a
root-level raw-eligible field (e.g. ``model_call.input``) under a non-raw
policy (or no policy at all) therefore returned 201 instead of being DENIED
with RELAY-INGEST-RAWCAPTURE-DENIED / 422.

These tests are RED at base commit 6a5b38b (the gate call is absent) and
GREEN after the single gate call is added to ``v1_ingest_runs`` -- mirroring
``v1_ingest_spans_batch`` exactly.

The fixtures reuse the same manifest-seeded ASGI transport pattern as
``test_v2m02_ingest.py`` (the canonical valid-runs-envelope path that returns
201), so the new raw_capture gate is the only thing under test.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiosqlite
import httpx
import pytest
import pytest_asyncio
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app
from relay_sidecar.validation.raw_capture import RAW_CAPTURE_DENIED_CODE

_FAKE_MANIFEST_HASH = "sha256-" + ("0" * 64)
_DECLARED_CMD_HASH = "sha256-" + ("a" * 64)


def _make_health(port: int = 50093) -> HealthState:
    token = "test-rawcap-token"  # noqa: S105
    return HealthState(
        port=port,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


async def _register_manifest_row(db_path: Path, *, commit_hash: str) -> None:
    """Seed migrations + a manifest_versions row so the manifest anchors
    pass and the body-shape / raw_capture gates own the response.
    """
    async with aiosqlite.connect(str(db_path)) as conn:
        migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
        await conn.executescript(
            "CREATE TABLE IF NOT EXISTS __schema_migrations ("
            "  filename   TEXT PRIMARY KEY,"
            "  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ");"
        )
        for sql in sorted(migrations_dir.glob("*.sql")):
            filename = sql.name
            async with conn.execute(
                "SELECT 1 FROM __schema_migrations WHERE filename = ?",
                (filename,),
            ) as cur:
                if await cur.fetchone() is not None:
                    continue
            await conn.executescript(sql.read_text(encoding="utf-8"))
            await conn.execute(
                "INSERT INTO __schema_migrations (filename) VALUES (?)",
                (filename,),
            )
        effective_at = (
            (datetime.now(tz=UTC) - timedelta(seconds=60))
            .isoformat()
            .replace("+00:00", "Z")
        )
        await conn.execute(
            "INSERT OR REPLACE INTO manifest_versions ("
            "manifest_version_id, manifest_id, project_id, commit_hash, "
            "schema_version, effective_at, effective_until, "
            "grace_window_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"mv-rawcap-{commit_hash[-12:]}",
                "manifest-id-rawcap",
                "project-id-rawcap",
                commit_hash,
                "relay.manifest.v1",
                effective_at,
                None,
                1800,
            ),
        )
        await conn.commit()


def _well_formed_run_envelope() -> dict[str, object]:
    """Minimal well-formed relay.ingest.run.v1 envelope (returns 201)."""
    return {
        "schema_version": "relay.ingest.run.v1",
        "run_id": "01HX0000000000000000RAWCAP1",
        "project_id": "project-id-rawcap",
        "trace_id": "01HX0000000000000000RAWCAP2",
        "client_lifecycle_status": "started",
        "started_at": "2026-05-28T00:00:00.000Z",
        "sdk_version": "relay-python@0.0.0",
        "sdk_clock": "2026-05-28T00:00:00.000Z",
        "manifest_commit_hash": _FAKE_MANIFEST_HASH,
        "command_hash": _DECLARED_CMD_HASH,
        "actor_identity_hash": "sha256-" + ("c" * 64),
        "redaction_policy_version": "relay.redaction.v1@2026-05-28",
        "idempotency_key": "01HX0000000000000000RAWCAP3",
        "sequence_number": 1,
        "agent": {"name": "test-agent", "version": "0.0.0"},
        "metadata": {},
    }


def _ingest_write_headers() -> dict[str, str]:
    return {"X-Relay-Scopes": "ingest:write"}


@pytest_asyncio.fixture
async def runs_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[httpx.AsyncClient]:
    """ASGI client with manifest + command pre-registered (legacy scope
    header opt-in so the X-Relay-Scopes fixture mechanism applies)."""
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.setenv("RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER", "1")
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    await _register_manifest_row(db_path, commit_hash=_FAKE_MANIFEST_HASH)

    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client,
    ):
        app.state.runtime.manifest_registry.register_commands(
            manifest_commit_hash=_FAKE_MANIFEST_HASH,
            command_hashes=[_DECLARED_CMD_HASH],
        )
        yield client


# ---- VAL-RAWCAP-001: root raw field, NO policy -> default-deny 422 --------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-RAWCAP-001")
@pytest.mark.asyncio
async def test_ingest_runs_default_denies_root_raw_field_without_policy(
    runs_client: httpx.AsyncClient,
) -> None:
    """POST /v1/ingest/runs with a root-level raw-eligible field and NO
    applied_redaction_policy must be DENIED (keystone #7 default-deny).

    RED at base commit: the handler never calls the raw_capture gate, so a
    raw prompt at ``model_call.input`` returns 201. GREEN after the gate is
    added: 422 RELAY-INGEST-RAWCAPTURE-DENIED.
    """
    envelope = _well_formed_run_envelope()
    # Root-level raw-eligible field (RAW_ELIGIBLE_SPAN_PATHS: model_call.input)
    # carrying an unredacted prompt; NO applied_redaction_policy at all.
    envelope["model_call"] = {"input": "raw secret prompt text"}
    r = await runs_client.post(
        "/v1/ingest/runs", json=envelope, headers=_ingest_write_headers()
    )
    assert r.status_code == 422, (
        "raw_capture default-deny bypass on /v1/ingest/runs: expected 422, "
        f"got {r.status_code}: {r.text}"
    )
    assert json.loads(r.text)["code"] == RAW_CAPTURE_DENIED_CODE


# ---- VAL-RAWCAP-002: root raw field + raw_capture=false policy -> 422 -----


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-RAWCAP-002")
@pytest.mark.asyncio
async def test_ingest_runs_denies_root_raw_field_under_non_raw_policy(
    runs_client: httpx.AsyncClient,
) -> None:
    """POST /v1/ingest/runs whose root carries an unredacted raw-eligible
    field AND an applied_redaction_policy with raw_capture=false must be
    DENIED (was 201).

    RED at base commit; GREEN after the gate call mirrors spans:batch.
    """
    envelope = _well_formed_run_envelope()
    envelope["model_call"] = {"input": "another raw secret prompt"}
    envelope["applied_redaction_policy"] = {
        "policy_version": "v1",
        "raw_capture": False,
    }
    r = await runs_client.post(
        "/v1/ingest/runs", json=envelope, headers=_ingest_write_headers()
    )
    assert r.status_code == 422, (
        "raw_capture=false policy did not deny a root raw field on "
        f"/v1/ingest/runs: expected 422, got {r.status_code}: {r.text}"
    )
    assert json.loads(r.text)["code"] == RAW_CAPTURE_DENIED_CODE


# ---- No-over-deny: legitimate envelopes still return 201 ------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-RAWCAP-001")
@pytest.mark.asyncio
async def test_ingest_runs_clean_envelope_still_accepted(
    runs_client: httpx.AsyncClient,
) -> None:
    """A well-formed runs envelope with NO raw-eligible field still returns
    201 -- the gate must not over-deny the happy path."""
    envelope = _well_formed_run_envelope()
    r = await runs_client.post(
        "/v1/ingest/runs", json=envelope, headers=_ingest_write_headers()
    )
    assert r.status_code == 201, r.text
    assert json.loads(r.text)["run_id"] == envelope["run_id"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-RAWCAP-002")
@pytest.mark.asyncio
async def test_ingest_runs_raw_field_with_authorized_policy_accepted(
    runs_client: httpx.AsyncClient,
) -> None:
    """A root raw-eligible field IS permitted when the active policy grants
    raw capture with all three preconditions (raw_capture=true + dpa_ref +
    approver_user_id) -- the gate must not over-deny an authorized write."""
    envelope = _well_formed_run_envelope()
    envelope["model_call"] = {"input": "raw prompt under authorized policy"}
    envelope["applied_redaction_policy"] = {
        "policy_version": "v1",
        "raw_capture": True,
        "dpa_ref": "dpa-2026-0001",
        "approver_user_id": "user-admin-001",
    }
    r = await runs_client.post(
        "/v1/ingest/runs", json=envelope, headers=_ingest_write_headers()
    )
    assert r.status_code == 201, r.text
    assert json.loads(r.text)["run_id"] == envelope["run_id"]
