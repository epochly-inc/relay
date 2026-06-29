"""V2 M02 W2.7 sidecar manifest endpoint tests.

Covers VAL-V2M02-057..060 (4 assertions):
  - 057 POST /v1/manifests upserts (201, commit_hash = sha256 prefix).
  - 058 POST enforces gates:configure scope.
  - 059 GET /v1/manifests/{id}/versions/{commit_hash} returns body, 404 path.
  - 060 GET enforces runs:read scope.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
import yaml
from _v2m02_w25_helpers import (
    V2M02Client,
    no_scope_header,
    scope_header,
)
from relay_schemas.envelopes import ErrorEnvelope
from relay_sidecar.errors import RelaySQLiteBusyExhausted


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-057")
@pytest.mark.asyncio
async def test_post_manifest_upserts(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    body = {"name": "manifest-x", "commands": [{"id": "test-plumbing"}]}
    r = await c.post(
        "/v1/manifests", json=body, headers=scope_header("gates:configure")
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    assert payload["manifest_id"]
    # Audit fix (2026-05-17 P0): canonical sha256 hyphen form +
    # manifest_versions CHECK constraint at migration 0006:75-76.
    assert payload["commit_hash"].startswith("sha256-")
    # Audit fix (2026-05-17 P0): parent Manifest envelope uses
    # ``relay.manifest_parent.v1`` per envelopes.yaml:847; the
    # ``relay.manifest.v1`` literal is reserved for ManifestVersion.
    assert payload["schema_version"] == "relay.manifest_parent.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-058")
@pytest.mark.asyncio
async def test_post_manifest_enforces_scope(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.post("/v1/manifests", json={}, headers=no_scope_header())
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-059")
@pytest.mark.asyncio
async def test_get_manifest_version_returns_body(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    body = {"name": "m-v", "commands": []}
    posted = await c.post(
        "/v1/manifests", json=body, headers=scope_header("gates:configure")
    )
    payload = json.loads(posted.text)
    mid = payload["manifest_id"]
    ch = payload["commit_hash"]
    r = await c.get(
        f"/v1/manifests/{mid}/versions/{ch}",
        headers=scope_header("runs:read"),
    )
    assert r.status_code == 200, r.text
    got = json.loads(r.text)
    assert got["manifest_id"] == mid
    assert got["commit_hash"] == ch
    assert got["body"]["name"] == "m-v"
    # 404 path: mismatched commit_hash (canonical hyphen-form).
    r404 = await c.get(
        f"/v1/manifests/{mid}/versions/sha256-{'9' * 64}",
        headers=scope_header("runs:read"),
    )
    assert r404.status_code == 404


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-060")
@pytest.mark.asyncio
async def test_get_manifest_version_enforces_scope(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.get(
        "/v1/manifests/x/versions/y", headers=no_scope_header()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---------------------------------------------------------------------------
# F5: the manifest_versions persistence write MUST NOT be silently swallowed.
# Before the fix it was wrapped in ``contextlib.suppress(Exception)``: a failed
# write returned HTTP 201 with the commit_hash while the DB row was absent ->
# in-memory/DB split-brain (GET works via the in-memory views, but the
# DB-backed three-anchor handoff lookup finds nothing). The fix persists the
# row FIRST as the durable gate, surfaces a structured 5xx on failure, and
# registers NOTHING in memory on failure (no split-brain in either direction).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-057")
@pytest.mark.asyncio
async def test_post_manifest_persistence_failure_surfaces_error_not_201(
    v2m02_client: V2M02Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A manifest_versions write failure -> structured 5xx, NOT a silent 201."""
    c, _db_path, app = v2m02_client
    runtime = app.state.runtime
    db = runtime.database
    assert db is not None
    orig = db.transactional_db_write_raw

    async def _boom(
        *,
        table: str,
        row: dict[str, Any],
        natural_key: str,
        natural_key_column: str,
    ) -> Any:
        if table == "manifest_versions":
            raise sqlite3.OperationalError(
                "simulated manifest_versions persistence failure"
            )
        return await orig(
            table=table,
            row=row,
            natural_key=natural_key,
            natural_key_column=natural_key_column,
        )

    monkeypatch.setattr(db, "transactional_db_write_raw", _boom)
    body = {"manifest_id": "mfst-f5-fail", "name": "m-fail", "commands": []}
    r = await c.post(
        "/v1/manifests", json=body, headers=scope_header("gates:configure")
    )
    # NOT a silent 201; the caller learns registration did not persist.
    assert r.status_code != 201, r.text
    assert r.status_code >= 500, r.text
    payload = json.loads(r.text)
    # Structured canonical envelope with a registered RELAY-* code.
    assert payload["code"].startswith("RELAY-"), payload
    assert payload["schema_version"] == "relay.error.v1", payload
    # No split-brain: the manifest was NOT registered in memory.
    assert "mfst-f5-fail" not in runtime.manifests, runtime.manifests


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-057")
def test_manifest_versions_in_allowed_tables_whitelist() -> None:
    """F5: ``manifest_versions`` is written via transactional_db_write_raw,
    so it MUST be listed in db._allowed_tables() (keystone invariant #8 --
    the writable-table allowlist is the single source of truth)."""
    from relay_sidecar.db import _allowed_tables

    assert "manifest_versions" in tuple(_allowed_tables()), (
        "manifest_versions missing from _allowed_tables(); the manifest "
        "create endpoint persists it via transactional_db_write_raw."
    )


# ---------------------------------------------------------------------------
# F5 follow-on 1 (orphan manifest_id): the durable write dedups on commit_hash,
# but migration 0006 declares UNIQUE(manifest_id, commit_hash) and an
# auto-generated manifest_id is NOT part of the dedupe key. Re-POSTing the same
# body WITHOUT a manifest_id generates a NEW random manifest_id each time; the
# raw writer finds the existing commit_hash row and inserts nothing, so the
# returned manifest_id would have no durable row (orphan). The endpoint MUST
# adopt the existing row's manifest_id so a returned id ALWAYS resolves to a
# persisted manifest_versions row.
# ---------------------------------------------------------------------------


def _manifest_versions_row_count(db_path: Path, manifest_id: str) -> int:
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute(
            "SELECT COUNT(*) FROM manifest_versions WHERE manifest_id = ?",
            (manifest_id,),
        )
        return int(cur.fetchone()[0])
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-057")
@pytest.mark.asyncio
async def test_post_manifest_reposted_body_no_orphan_manifest_id(
    v2m02_client: V2M02Client,
) -> None:
    """Re-POST the same body (no manifest_id) twice -> every returned
    manifest_id resolves to a durable manifest_versions row (no orphan)."""
    c, db_path, _app = v2m02_client
    body = {"name": "m-orphan", "commands": []}  # NO manifest_id -> auto-gen

    r1 = await c.post(
        "/v1/manifests", json=body, headers=scope_header("gates:configure")
    )
    assert r1.status_code == 201, r1.text
    mid1 = json.loads(r1.text)["manifest_id"]

    r2 = await c.post(
        "/v1/manifests", json=body, headers=scope_header("gates:configure")
    )
    assert r2.status_code == 201, r2.text
    mid2 = json.loads(r2.text)["manifest_id"]

    # Both returned ids MUST resolve to a persisted manifest_versions row.
    assert _manifest_versions_row_count(db_path, mid1) == 1, (
        f"first manifest_id {mid1!r} has no durable manifest_versions row"
    )
    assert _manifest_versions_row_count(db_path, mid2) == 1, (
        f"re-posted manifest_id {mid2!r} is an ORPHAN (no durable row)"
    )
    # On idempotent re-post the endpoint adopts the existing row's id, so the
    # two posts return the SAME manifest_id (one logical manifest per body).
    assert mid1 == mid2, (mid1, mid2)


# ---------------------------------------------------------------------------
# F5 follow-on 2 (busy 503 canonical envelope): the manifests busy path must
# return a CANONICAL ErrorEnvelope, not the non-canonical
# RelaySQLiteBusyExhausted.to_envelope() shape (which omits schema_version/
# blocked_surface/retry_advice/request_id/trace_id and includes the forbidden
# error_class field). RELAY-SQLITE-001 / HTTP 503.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-057")
@pytest.mark.asyncio
async def test_post_manifest_busy_exhausted_returns_canonical_503(
    v2m02_client: V2M02Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A busy-exhausted manifest_versions write -> 503 + canonical ErrorEnvelope."""
    c, _db_path, app = v2m02_client
    db = app.state.runtime.database
    assert db is not None
    orig = db.transactional_db_write_raw

    async def _busy(
        *,
        table: str,
        row: dict[str, Any],
        natural_key: str,
        natural_key_column: str,
    ) -> Any:
        if table == "manifest_versions":
            raise RelaySQLiteBusyExhausted(
                message="simulated SQLITE_BUSY budget exhausted",
                attempts=7,
                sql_statement_digest="sha256-" + "0" * 64,
            )
        return await orig(
            table=table,
            row=row,
            natural_key=natural_key,
            natural_key_column=natural_key_column,
        )

    monkeypatch.setattr(db, "transactional_db_write_raw", _busy)
    body = {"manifest_id": "mfst-busy", "name": "m-busy", "commands": []}
    r = await c.post(
        "/v1/manifests", json=body, headers=scope_header("gates:configure")
    )
    assert r.status_code == 503, r.text
    payload = json.loads(r.text)
    # Canonical ErrorEnvelope: no legacy error_class; validates against model.
    assert "error_class" not in payload, payload
    env = ErrorEnvelope.model_validate(payload)
    assert env.schema_version == "relay.error.v1"
    assert env.code == "RELAY-SQLITE-001"
    assert env.http_status == 503
    assert env.blocked_surface
    assert env.retry_advice
    assert env.request_id
    assert env.trace_id
    # retry_advice=after_retry_after MUST be backed by a real Retry-After header
    # (roborev e19ec7c): a client told to "retry after the Retry-After window"
    # needs the header to know the window.
    assert env.retry_advice == "after_retry_after"
    assert r.headers.get("Retry-After") == "1"


# ---------------------------------------------------------------------------
# F5 follow-on 3 (openapi contract): POST /v1/manifests now emits 500/503/507
# (the F5 persistence-failure paths). The OpenAPI contract MUST declare them so
# the generated TypeScript types and the codegen-drift gate stay in sync.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-057")
def test_openapi_declares_manifest_failure_statuses() -> None:
    """openapi.yaml POST /v1/manifests declares the 500/503/507 ErrorEnvelope
    responses introduced by the F5 fail-loud persistence path."""
    repo_root = Path(__file__).resolve().parents[3]
    openapi_path = repo_root / "packages" / "schemas" / "raw" / "openapi.yaml"
    doc = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))
    responses = doc["paths"]["/v1/manifests"]["post"]["responses"]
    for status in ("500", "503", "507"):
        assert status in responses, (
            f"openapi.yaml POST /v1/manifests missing the {status} response"
        )
        ref = responses[status]["content"]["application/json"]["schema"]["$ref"]
        assert ref.endswith("/ErrorEnvelope"), (status, ref)
