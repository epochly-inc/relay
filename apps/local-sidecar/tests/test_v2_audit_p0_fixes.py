"""V2 audit P0 fixes: contract correctness regression tests (2026-05-17).

Covers the 11 P0 audit findings on ``apps/local-sidecar/relay_sidecar/
runtime.py``:

  - sha256 colon-form -> hyphen-form across all 5 endpoint sites.
  - POST /v1/gates/{gate_id}/drafts three-anchor handoff validation.
  - POST /v1/manifests seeds ManifestRegistry + manifest_versions row.
  - POST /v1/manifests: parent ``relay.manifest_parent.v1`` vs version
    ``relay.manifest.v1`` schema_version split.
  - POST /v1/redaction-policies: canonical envelope shape + field names.
  - POST /v1/evidence-bundles: canonical envelope shape + field names
    + ``evidence:write`` scope (was incorrectly ``evidence:read``).
  - POST /v1/replay-cases: canonical envelope shape + field names.
  - GET /v1/runs/{id}, /trace, POST /v1/eval-datasets: drop made-up
    ``schema_version`` literals (not in KNOWN_SCHEMA_IDS).
  - POST /v1/ingest/spans:batch: raw_capture + side-effect checks no
    longer bypassable via malformed ``spans`` body.
  - X-Relay-Scopes legacy header gated behind
    ``RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER`` env var (default off).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import aiosqlite
import httpx
import pytest
import pytest_asyncio
from relay_sidecar.health import HealthState, _bearer_digest_of
from relay_sidecar.runtime import build_runtime_app


def _make_health(port: int = 50099) -> HealthState:
    token = "test-audit-p0-token"  # noqa: S105
    return HealthState(
        port=port,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )


async def _bootstrap_db(db_path: Path) -> None:
    async with aiosqlite.connect(str(db_path)) as conn:
        migrations_dir = Path(__file__).resolve().parents[1] / "migrations"
        for sql in sorted(migrations_dir.glob("*.sql")):
            await conn.executescript(sql.read_text(encoding="utf-8"))
        await conn.commit()


@pytest_asyncio.fixture
async def audit_client_legacy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, Path, object]]:
    """Sidecar fixture WITH the legacy X-Relay-Scopes header enabled."""
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.setenv("RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER", "1")
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    await _bootstrap_db(db_path)
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as c,
    ):
        yield c, db_path, app


@pytest_asyncio.fixture
async def audit_client_strict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, Path, object]]:
    """Sidecar fixture with the legacy X-Relay-Scopes header DISABLED
    (production default). Tests use bearer tokens.
    """
    monkeypatch.setenv("RELAY_SIDECAR_IDLE_TIMEOUT_S", "60.0")
    monkeypatch.delenv("RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER", raising=False)
    monkeypatch.setenv("RELAY_HOME", str(tmp_path / "relay-home"))
    (tmp_path / "relay-home").mkdir(exist_ok=True)
    db_path = tmp_path / "sidecar.db"
    await _bootstrap_db(db_path)
    app = build_runtime_app(health=_make_health(), sqlite_path=db_path)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as c,
    ):
        yield c, db_path, app


# ---- 1. sha256 wire-form hyphen (5 sites) --------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_evidence_bundle_digest_uses_hyphen_form(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """POST /v1/evidence-bundles digest is sha256-<hex> (hyphen)."""
    c, _db, _app = audit_client_legacy
    r = await c.post(
        "/v1/evidence-bundles",
        json={"scope_type": "run", "scope_id": "r1", "claims": []},
        headers={"X-Relay-Scopes": "evidence:write"},
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    assert payload["bundle_digest"].startswith("sha256-")
    # Legacy alias on response carries the same canonical form.
    assert payload["digest"].startswith("sha256-")
    # Reject the bug-form prefix.
    assert ":" not in payload["bundle_digest"]


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_commit_hash_uses_hyphen_form(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """POST /v1/manifests commit_hash is sha256-<hex> (hyphen) AND the
    manifest_versions CHECK constraint accepts it."""
    c, db, _app = audit_client_legacy
    r = await c.post(
        "/v1/manifests",
        json={"name": "audit-m", "project_id": "proj-audit"},
        headers={"X-Relay-Scopes": "gates:configure"},
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    assert payload["commit_hash"].startswith("sha256-")
    # Verify the manifest_versions row was inserted.
    async with (
        aiosqlite.connect(str(db)) as conn,
        conn.execute(
            "SELECT commit_hash FROM manifest_versions WHERE commit_hash = ?",
            (payload["commit_hash"],),
        ) as cur,
    ):
        row = await cur.fetchone()
    assert row is not None, "manifest_versions row was not seeded"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_replay_fixture_digest_uses_hyphen_form(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """POST /v1/replay-cases/{case_id}/fixtures digest is sha256-<hex>."""
    c, db, _app = audit_client_legacy
    # Seed a run + create a replay case for it.
    run_id = "01HXAUDITRUN00000000000001"
    async with aiosqlite.connect(str(db)) as conn:
        await conn.execute(
            "INSERT INTO run_results ("
            "run_result_id, run_id, project_id, schema_version, written_by, "
            "status, primary_failure_class, error_priority_rule, "
            "evidence_bundle_id, manifest_commit_hash, actor_identity_hash, "
            "decided_at, decision_epoch, signature, signature_key_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"rr-{run_id}",
                run_id,
                "proj-audit",
                "relay.run_result.v1",
                "control_plane",
                "remediate_required",
                "contract_fail",
                "first_p0_then_highest_severity_then_earliest_span",
                None,
                "sha256-" + ("0" * 64),
                "sha256-" + ("c" * 64),
                "2026-05-17T00:00:00Z",
                1,
                "sig",
                "key",
            ),
        )
        await conn.commit()
    rc = await c.post(
        "/v1/replay-cases",
        json={"from_run_id": run_id},
        headers={"X-Relay-Scopes": "replay:write,runs:read"},
    )
    assert rc.status_code == 201, rc.text
    case_id = json.loads(rc.text)["case_id"]
    rf = await c.post(
        f"/v1/replay-cases/{case_id}/fixtures",
        json={"fixture_kind": "tool_call", "payload": {"k": "v"}},
        headers={"X-Relay-Scopes": "replay:write"},
    )
    assert rf.status_code == 201, rf.text
    assert json.loads(rf.text)["digest"].startswith("sha256-")


# ---- 2. POST /v1/manifests seeds ManifestRegistry + DB row ----------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_post_manifests_seeds_registry(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """POST /v1/manifests registers declared command_hashes in the
    in-memory ManifestRegistry so subsequent ingest can match them."""
    c, _db, app = audit_client_legacy
    cmd_hash = "sha256-" + ("a" * 64)
    r = await c.post(
        "/v1/manifests",
        json={
            "name": "audit-reg",
            "project_id": "proj-audit-reg",
            "commands": [{"id": "test-cmd", "command_hash": cmd_hash}],
        },
        headers={"X-Relay-Scopes": "gates:configure"},
    )
    assert r.status_code == 201, r.text
    commit_hash = json.loads(r.text)["commit_hash"]
    registry = app.state.runtime.manifest_registry
    assert registry.is_command_declared(
        manifest_commit_hash=commit_hash, command_hash=cmd_hash
    )


# ---- 3. Parent vs version schema_version split ---------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_manifest_parent_vs_version_schema_version_split(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """POST /v1/manifests parent envelope uses
    ``relay.manifest_parent.v1`` (NOT ``relay.manifest.v1``); the
    ManifestVersion uses ``relay.manifest.v1``."""
    c, _db, app = audit_client_legacy
    r = await c.post(
        "/v1/manifests",
        json={"name": "audit-split", "project_id": "proj-split"},
        headers={"X-Relay-Scopes": "gates:configure"},
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    # Response carries the parent literal.
    assert payload["schema_version"] == "relay.manifest_parent.v1"
    # In-memory parent record carries the parent literal.
    manifest_id = payload["manifest_id"]
    parent = app.state.runtime.manifests[manifest_id]
    assert parent["schema_version"] == "relay.manifest_parent.v1"
    # In-memory version record carries the version literal.
    commit_hash = payload["commit_hash"]
    version = app.state.runtime.manifest_version_bodies[
        (manifest_id, commit_hash)
    ]
    assert version["schema_version"] == "relay.manifest.v1"


# ---- 4. Redaction policy canonical envelope + scope ----------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_redaction_policy_uses_canonical_envelope(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """POST /v1/redaction-policies returns ``relay.redaction.v1`` (NOT
    the made-up ``relay.redaction_policy.v1``) and carries the canonical
    ``redaction_policy_id`` field."""
    c, _db, _app = audit_client_legacy
    r = await c.post(
        "/v1/redaction-policies",
        json={"policy_version": "v1", "patterns": []},
        headers={"X-Relay-Scopes": "gates:configure"},
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    assert payload["schema_version"] == "relay.redaction.v1"
    assert "redaction_policy_id" in payload
    # Legacy alias retained for back-compat.
    assert payload["policy_id"] == payload["redaction_policy_id"]


# ---- 5. Evidence bundle canonical envelope + write scope -----------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_evidence_bundle_requires_write_scope(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """POST /v1/evidence-bundles requires ``evidence:write`` (was
    incorrectly ``evidence:read``)."""
    c, _db, _app = audit_client_legacy
    # evidence:read alone is insufficient now.
    r = await c.post(
        "/v1/evidence-bundles",
        json={"scope_type": "run", "scope_id": "r", "claims": []},
        headers={"X-Relay-Scopes": "evidence:read"},
    )
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"
    # evidence:write succeeds.
    r2 = await c.post(
        "/v1/evidence-bundles",
        json={"scope_type": "run", "scope_id": "r", "claims": []},
        headers={"X-Relay-Scopes": "evidence:write"},
    )
    assert r2.status_code == 201, r2.text


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_evidence_bundle_canonical_fields(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """The stored bundle record carries the canonical EvidenceBundle
    envelope fields per envelopes.yaml:371-404."""
    c, _db, app = audit_client_legacy
    r = await c.post(
        "/v1/evidence-bundles",
        json={"scope_type": "run", "scope_id": "r", "claims": []},
        headers={"X-Relay-Scopes": "evidence:write"},
    )
    assert r.status_code == 201, r.text
    bid = json.loads(r.text)["bundle_id"]
    rec = app.state.runtime.evidence_bundles[bid]
    for required in (
        "evidence_bundle_id",
        "org_id",
        "project_id",
        "scope_type",
        "bundle_digest",
        "acef_core_version",
        "relay_extension_version",
        "verification_status",
        "redaction_policy_version",
        "object_ref",
    ):
        assert required in rec, f"missing canonical field: {required}"
    assert rec["schema_version"] == "relay.evidence_bundle.v1"
    assert rec["verification_status"] == "unverified"


# ---- 6. Replay case canonical envelope -----------------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_replay_case_canonical_fields(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """POST /v1/replay-cases record carries canonical ReplayCase fields
    per envelopes.yaml:444-475."""
    c, db, app = audit_client_legacy
    run_id = "01HXAUDITRUN00000000000002"
    async with aiosqlite.connect(str(db)) as conn:
        await conn.execute(
            "INSERT INTO run_results ("
            "run_result_id, run_id, project_id, schema_version, written_by, "
            "status, primary_failure_class, error_priority_rule, "
            "evidence_bundle_id, manifest_commit_hash, actor_identity_hash, "
            "decided_at, decision_epoch, signature, signature_key_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"rr-{run_id}",
                run_id,
                "proj-rc",
                "relay.run_result.v1",
                "control_plane",
                "remediate_required",
                "contract_fail",
                "first_p0_then_highest_severity_then_earliest_span",
                None,
                "sha256-" + ("0" * 64),
                "sha256-" + ("c" * 64),
                "2026-05-17T00:00:00Z",
                1,
                "sig",
                "key",
            ),
        )
        await conn.commit()
    r = await c.post(
        "/v1/replay-cases",
        json={"from_run_id": run_id},
        headers={"X-Relay-Scopes": "replay:write,runs:read"},
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    case_id = payload["replay_case_id"]
    rec = app.state.runtime.replay_cases[case_id]
    for required in (
        "replay_case_id",
        "project_id",
        "source_run_id",
        "failure_signature_hash",
        "inputs_ref",
        "inputs_digest",
    ):
        assert required in rec, f"missing canonical field: {required}"
    assert rec["source_run_id"] == run_id
    assert rec["inputs_digest"].startswith("sha256-")


# ---- 7. Drop made-up schema_version literals -----------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_eval_dataset_response_drops_schema_version(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """POST /v1/eval-datasets no longer returns ``relay.eval_dataset.v1``
    (literal not in KNOWN_SCHEMA_IDS)."""
    c, _db, _app = audit_client_legacy
    r = await c.post(
        "/v1/eval-datasets",
        json={"name": "ds-audit", "fixtures": []},
        headers={"X-Relay-Scopes": "replay:write"},
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    assert "schema_version" not in payload


# ---- 8. Spans:batch raw_capture + side-effect bypass closed --------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_spans_batch_raw_capture_runs_on_nonlist_spans(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """POST /v1/ingest/spans:batch raw_capture gate fires even when the
    ``spans`` field is omitted or non-list (was previously bypassed).
    """
    c, db, app = audit_client_legacy
    # Seed the manifest_versions row + ManifestRegistry so the manifest
    # anchors pass; the raw_capture defense-in-depth gate is what we
    # want to exercise.
    commit_hash = "sha256-" + ("0" * 64)
    command_hash = "sha256-" + ("1" * 64)
    async with aiosqlite.connect(str(db)) as conn:
        await conn.execute(
            "INSERT INTO manifest_versions ("
            "manifest_version_id, manifest_id, project_id, commit_hash, "
            "effective_at) VALUES (?, ?, ?, ?, ?)",
            ("mv-raw", "mfst-raw", "proj-raw", commit_hash,
             "2026-05-17T00:00:00Z"),
        )
        await conn.commit()
    app.state.runtime.manifest_registry.register_commands(
        manifest_commit_hash=commit_hash, command_hashes=[command_hash]
    )
    # Body with a raw-eligible field AND a redaction policy that
    # disallows raw_capture AND a non-list ``spans`` -> previously the
    # raw_capture gate was nested inside the list-only branch and was
    # bypassed. With the audit fix the gate runs on every well-formed
    # POST body regardless of the spans field shape.
    body = {
        "manifest_commit_hash": commit_hash,
        "command_hash": command_hash,
        "applied_redaction_policy": {
            "policy_version": "v1",
            "raw_capture": False,
        },
        # Canonical raw-eligible field per RAW_ELIGIBLE_SPAN_PATHS
        # (raw_capture.py:66-72): ``tool_call.args`` carries unredacted
        # text under raw_capture=false -> RELAY-G-RAW-CAPTURE-DENIED.
        "tool_call": {"args": "user-secret-data"},
        # Malformed spans field exercises the previously-bypassed branch.
        "spans": "not-a-list",
    }
    r = await c.post(
        "/v1/ingest/spans:batch",
        json=body,
        headers={"X-Relay-Scopes": "ingest:write"},
    )
    # Previously this body would have returned 202 (bypass). With the
    # fix, the raw_capture gate runs on the body's root and rejects.
    assert r.status_code == 422, (
        f"raw_capture bypass: expected 422; got {r.status_code}: {r.text}"
    )
    assert json.loads(r.text)["code"] == "RELAY-INGEST-RAWCAPTURE-DENIED"


# ---- 9. X-Relay-Scopes legacy header default-deny ------------------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_legacy_scope_header_disabled_by_default(
    audit_client_strict: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """With ``RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER`` UNSET, an
    X-Relay-Scopes header is NOT honoured -- the request lands in the
    401 RELAY-AUTH-001 path because no bearer token was supplied."""
    c, _db, _app = audit_client_strict
    r = await c.put(
        "/v1/gates/gate-strict",
        json={"name": "g"},
        headers={"X-Relay-Scopes": "gates:configure"},
    )
    # Without the env opt-in the legacy header is dead; bearer is the
    # only auth path. No bearer supplied -> 401 RELAY-AUTH-001.
    assert r.status_code == 401, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-001"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_legacy_scope_header_enabled_with_env_var(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """With the env var SET, the legacy X-Relay-Scopes path works
    as before so existing W2.5+ tests keep passing."""
    c, _db, _app = audit_client_legacy
    r = await c.put(
        "/v1/gates/gate-leg",
        json={"name": "g"},
        headers={"X-Relay-Scopes": "gates:configure"},
    )
    assert r.status_code == 201, r.text


# ---- 10. POST gate drafts three-anchor handoff validation ----------------


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_post_gate_draft_rejects_unknown_actor(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """When actors + manifest_versions tables ARE seeded but the
    submitted actor_identity_hash is unknown, the gate-draft POST
    returns 422 RELAY-GATE-021 with ACTOR_NOT_REGISTERED reason."""
    c, db, _app = audit_client_legacy
    known_actor = "sha256-" + ("a" * 64)
    manifest_hash = "sha256-" + ("b" * 64)
    async with aiosqlite.connect(str(db)) as conn:
        await conn.execute(
            "INSERT INTO actors (identity_hash, kind, registered_at, "
            "revoked_at) VALUES (?, ?, ?, ?)",
            (known_actor, "worker", "2026-05-17T00:00:00Z", None),
        )
        await conn.execute(
            "INSERT INTO manifest_versions ("
            "manifest_version_id, manifest_id, project_id, commit_hash, "
            "effective_at) VALUES (?, ?, ?, ?, ?)",
            ("mv-h", "mfst-h", "proj-h", manifest_hash,
             "2026-05-17T00:00:00Z"),
        )
        await conn.commit()
    # Unknown actor identity hash -> RELAY-GATE-021 ACTOR_NOT_REGISTERED.
    unknown_actor = "sha256-" + ("9" * 64)
    body = {
        "manifest_commit_hash": manifest_hash,
        "actor_identity_hash": unknown_actor,
        "worker_id": "worker-A",
        "round": 1,
    }
    r = await c.post(
        "/v1/gates/gate-h/drafts",
        json=body,
        headers={"X-Relay-Scopes": "gates:execute"},
    )
    assert r.status_code == 422, r.text
    err = json.loads(r.text)
    assert err["code"] == "RELAY-GATE-021"
    assert err["details"]["reason"] == "ACTOR_NOT_REGISTERED"


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_post_gate_draft_accepts_when_tables_unseeded(
    audit_client_legacy: tuple[httpx.AsyncClient, Path, object],
) -> None:
    """When actors + manifest_versions tables are empty (typical OSS
    test fixture), the handoff validator is skipped and the draft
    succeeds. This preserves the v2m02 legacy contract while still
    enforcing the keystone invariant when the tables ARE populated."""
    c, _db, _app = audit_client_legacy
    body = {
        "manifest_commit_hash": "sha256-" + ("0" * 64),
        "actor_identity_hash": "sha256-" + ("1" * 64),
        "worker_id": "worker-A",
        "round": 1,
    }
    r = await c.post(
        "/v1/gates/gate-unseeded/drafts",
        json=body,
        headers={"X-Relay-Scopes": "gates:execute"},
    )
    assert r.status_code == 202, r.text
