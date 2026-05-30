"""V2 M02 W2.8 sidecar redaction-policy endpoint tests.

Covers VAL-V2M02-061..064 (4 assertions):
  - 061 POST /v1/redaction-policies (201) + raw_capture=true denied without
        signed DPA + approver.
  - 062 POST enforces gates:configure scope.
  - 063 GET /v1/redaction-policies/{id} returns policy / 404 on unknown.
  - 064 GET enforces runs:read scope.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import pytest
from _v2m02_w25_helpers import (
    V2M02Client,
    no_scope_header,
    scope_header,
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-061")
@pytest.mark.asyncio
async def test_post_redaction_policy_create_and_raw_capture_denied(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    # Valid policy without raw_capture.
    r = await c.post(
        "/v1/redaction-policies",
        json={
            "policy_version": "v1",
            "patterns": [{"pattern": "email", "action": "mask"}],
        },
        headers=scope_header("gates:configure"),
    )
    assert r.status_code == 201, r.text
    payload = json.loads(r.text)
    assert payload["policy_id"]
    assert payload["version"] == "v1"

    # raw_capture=true without DPA + approver -> 422.
    r2 = await c.post(
        "/v1/redaction-policies",
        json={
            "policy_version": "v2",
            "patterns": [],
            "raw_capture": True,
        },
        headers=scope_header("gates:configure"),
    )
    assert r2.status_code == 422, r2.text
    assert json.loads(r2.text)["code"] == "RELAY-G-RAW-CAPTURE-DENIED"

    # raw_capture=true WITH DPA + approver -> 201 (audited path).
    r3 = await c.post(
        "/v1/redaction-policies",
        json={
            "policy_version": "v3",
            "patterns": [],
            "raw_capture": True,
            "dpa_reference": "dpa-2026-acme",
            "approved_by": "actor:org-admin:alice",
        },
        headers=scope_header("gates:configure"),
    )
    assert r3.status_code == 201, r3.text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-062")
@pytest.mark.asyncio
async def test_post_redaction_policy_enforces_scope(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.post(
        "/v1/redaction-policies", json={}, headers=no_scope_header()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-063")
@pytest.mark.asyncio
async def test_get_redaction_policy_returns_or_404(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    posted = await c.post(
        "/v1/redaction-policies",
        json={"policy_version": "v1", "patterns": []},
        headers=scope_header("gates:configure"),
    )
    pid = json.loads(posted.text)["policy_id"]
    r = await c.get(
        f"/v1/redaction-policies/{pid}", headers=scope_header("runs:read")
    )
    assert r.status_code == 200, r.text
    assert json.loads(r.text)["policy_id"] == pid
    r404 = await c.get(
        "/v1/redaction-policies/unknown", headers=scope_header("runs:read")
    )
    assert r404.status_code == 404


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M02-064")
@pytest.mark.asyncio
async def test_get_redaction_policy_enforces_scope(
    v2m02_client: V2M02Client,
) -> None:
    c, _db, _app = v2m02_client
    r = await c.get(
        "/v1/redaction-policies/x", headers=no_scope_header()
    )
    assert r.status_code == 403
    assert json.loads(r.text)["code"] == "RELAY-AUTH-014"
