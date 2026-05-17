"""V2 M02 W2.5 sidecar gate-namespace HTTP endpoint tests.

Covers VAL-V2M02-037..048 (12 assertions):
  - 037/038 PUT /v1/gates/{gate_id} + gates:configure scope
  - 039/040 PUT /v1/gate-policies/{policy_id} + scope
  - 041     POST /v1/gates/{gate_id}/drafts returns 202
  - 042     POST drafts returns 409 RELAY-GATE-014 on conflict
  - 043     POST drafts returns 422 RELAY-GATE-021 on stale handoff
  - 044     POST drafts enforces gates:execute scope
  - 045/046 GET /v1/gate-decisions/{decision_id} + scope
  - 047/048 GET /v1/gates/{gate_id}/rounds + scope

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import httpx
import pytest
from _v2m02_w25_helpers import (
    no_scope_header,
    scope_header,
)

# ---- VAL-V2M02-037 / 038: PUT /v1/gates/{gate_id} ------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-037")
@pytest.mark.asyncio
async def test_put_gate_upserts(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    body = {
        "name": "gate-checkout",
        "scope_type": "run",
        "enabled": True,
        "draft_ttl_seconds": 900,
    }
    r1 = await c.put(
        "/v1/gates/gate-checkout",
        json=body,
        headers=scope_header("gates:configure"),
    )
    assert r1.status_code == 201, r1.text
    payload = json.loads(r1.text)
    assert payload["gate_id"] == "gate-checkout"
    assert payload["schema_version"].startswith("relay.gate.v")
    # Second PUT -> 200 (existing).
    r2 = await c.put(
        "/v1/gates/gate-checkout",
        json=body,
        headers=scope_header("gates:configure"),
    )
    assert r2.status_code == 200, r2.text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-038")
@pytest.mark.asyncio
async def test_put_gate_enforces_scope(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    r = await c.put(
        "/v1/gates/gate-x",
        json={"name": "g"},
        headers=no_scope_header(),
    )
    assert r.status_code == 403, r.text
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-039 / 040: PUT /v1/gate-policies/{policy_id} --------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-039")
@pytest.mark.asyncio
async def test_put_gate_policy_upserts(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    body = {
        "gate_id": "gate-x",
        "policy_version": "v1",
        "conditions": [],
        "blocking_severity": "p0_only",
    }
    r = await c.put(
        "/v1/gate-policies/policy-1",
        json=body,
        headers=scope_header("gates:configure"),
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    assert payload["policy_id"] == "policy-1"
    assert payload["schema_version"].startswith("relay.gate_policy.v")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-040")
@pytest.mark.asyncio
async def test_put_gate_policy_enforces_scope(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    r = await c.put(
        "/v1/gate-policies/p-x", json={}, headers=no_scope_header()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-041 / 042 / 043 / 044: POST /v1/gates/{id}/drafts ---------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-041")
@pytest.mark.asyncio
async def test_post_gate_draft_returns_202(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    body = {
        "manifest_commit_hash": "sha256-" + ("0" * 64),
        "actor_identity_hash": "sha256-" + ("1" * 64),
        "worker_id": "worker-A",
        "round": 1,
    }
    r = await c.post(
        "/v1/gates/gate-a/drafts",
        json=body,
        headers=scope_header("gates:execute"),
    )
    assert r.status_code == 202, r.text
    payload = json.loads(r.text)
    assert all(
        k in payload
        for k in ("draft_id", "gate_round_id", "await_url", "draft_ttl_seconds")
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-042")
@pytest.mark.asyncio
async def test_post_gate_draft_conflict_409(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    body_a = {
        "manifest_commit_hash": "sha256-" + ("0" * 64),
        "actor_identity_hash": "sha256-" + ("1" * 64),
        "worker_id": "worker-A",
        "round": 1,
    }
    body_b = dict(body_a)
    body_b["worker_id"] = "worker-B"
    r1 = await c.post(
        "/v1/gates/gate-conflict/drafts",
        json=body_a,
        headers=scope_header("gates:execute"),
    )
    assert r1.status_code == 202, r1.text
    r2 = await c.post(
        "/v1/gates/gate-conflict/drafts",
        json=body_b,
        headers=scope_header("gates:execute"),
    )
    assert r2.status_code == 409, r2.text
    assert json.loads(r2.text)["code"] == "RELAY-GATE-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-043")
@pytest.mark.asyncio
async def test_post_gate_draft_stale_handoff_422(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    body = {
        "manifest_commit_hash": "sha256-" + ("0" * 64),
        "actor_identity_hash": "sha256-" + ("1" * 64),
        "worker_id": "worker-S",
        "round": 7,
        "handoff_stale": True,
    }
    r = await c.post(
        "/v1/gates/gate-stale/drafts",
        json=body,
        headers=scope_header("gates:execute"),
    )
    assert r.status_code == 422, r.text
    assert json.loads(r.text)["code"] == "RELAY-GATE-021"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-044")
@pytest.mark.asyncio
async def test_post_gate_draft_enforces_scope(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    r = await c.post(
        "/v1/gates/g/drafts", json={}, headers=no_scope_header()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-045 / 046: GET /v1/gate-decisions/{id} --------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-045")
@pytest.mark.asyncio
async def test_get_gate_decision_returns_canonical_or_404(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, app = v2m02_client
    runtime = app.state.runtime
    # Seed a canonical gate_decisions record so the read path returns 200.
    runtime.gate_decisions["gd-123"] = {
        "schema_version": "relay.gate_decision.v1",
        "gate_decision_id": "gd-123",
        "decision": "pass",
        "written_by": "control_plane",
        "decided_by": "gate_engine",
        "evidence_bundle_id": "eb-abc",
    }
    r = await c.get(
        "/v1/gate-decisions/gd-123", headers=scope_header("runs:read")
    )
    assert r.status_code == 200, r.text
    payload = json.loads(r.text)
    assert payload["written_by"] == "control_plane"
    # Unknown id -> 404.
    r404 = await c.get(
        "/v1/gate-decisions/unknown", headers=scope_header("runs:read")
    )
    assert r404.status_code == 404


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-046")
@pytest.mark.asyncio
async def test_get_gate_decision_enforces_scope(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    r = await c.get(
        "/v1/gate-decisions/x", headers=no_scope_header()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


# ---- VAL-V2M02-047 / 048: GET /v1/gates/{id}/rounds ----------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-047")
@pytest.mark.asyncio
async def test_list_gate_rounds_paginated(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    # Create a few drafts to seed rounds.
    for i in range(3):
        await c.post(
            "/v1/gates/g-pager/drafts",
            json={
                "manifest_commit_hash": "sha256-" + ("0" * 64),
                "actor_identity_hash": "sha256-" + ("1" * 64),
                "worker_id": f"worker-{i}",
                "round": i + 1,
            },
            headers=scope_header("gates:execute"),
        )
    r = await c.get(
        "/v1/gates/g-pager/rounds", headers=scope_header("gates:configure")
    )
    assert r.status_code == 200, r.text
    payload = json.loads(r.text)
    assert isinstance(payload["items"], list)
    assert "next_cursor" in payload
    assert "has_more" in payload


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-048")
@pytest.mark.asyncio
async def test_list_gate_rounds_enforces_scope(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    c, _db, _app = v2m02_client
    r = await c.get("/v1/gates/g/rounds", headers=no_scope_header())
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"
