"""VAL-ISO-025 regression: the ``handoff_stale`` request-body flag is a
client-triggerable control-flow backdoor and must NOT exist in the
production gate-draft handler.

Bug (base commit c911607): ``v1_post_gate_draft`` honours a body field
``handoff_stale`` that, when set to ``True`` by the client, forces a
RELAY-GATE-021 three-anchor-stale rejection regardless of the actual
anchor validity (runtime.py ~4367-4385). A client can therefore drive the
stale-handoff control path directly from the request body -- a backdoor
baked into the production route.

Fix: REMOVE the body-driven ``handoff_stale`` branch. The genuine stale
path is the three-anchor mismatch detected by
``validate_three_anchor_handoff`` (RELAY-GATE-021); it is exercised here
by seeding the actors/manifest_versions registries to a genuinely-stale
state (registered actor + a manifest whose commit_hash does NOT match the
submitted anchor -> MANIFEST_NOT_ACTIVE), NOT by a client-settable flag.

RED at base (body flag forces 422 RELAY-GATE-021 even with VALID anchors);
GREEN after (the flag is ignored; a request with otherwise-valid seeded
anchors and ``handoff_stale=True`` is ACCEPTED 202 because the flag no
longer short-circuits, while a genuine anchor mismatch still yields 422).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import httpx
import pytest
from _v2m02_w25_helpers import scope_header, seed_three_anchor_handoff

_ACTOR_HASH = "sha256-" + ("1" * 64)
_MANIFEST_HASH = "sha256-" + ("0" * 64)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-025")
@pytest.mark.asyncio
async def test_body_handoff_stale_flag_cannot_force_stale_path(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    """A client-supplied ``handoff_stale=True`` must NOT force the stale
    rejection when the real three-anchor handoff is valid.

    Seed a registered actor + a currently-active manifest matching the
    submitted anchors (a genuinely-VALID handoff). Submit the draft WITH
    ``handoff_stale=True`` in the body. Before the fix the backdoor
    short-circuits to 422 RELAY-GATE-021 despite the valid anchors; after
    the fix the flag is inert and the genuine validator accepts the draft
    (202).
    """
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_ACTOR_HASH,
        manifest_commit_hash=_MANIFEST_HASH,
    )
    body = {
        "manifest_commit_hash": _MANIFEST_HASH,
        "actor_identity_hash": _ACTOR_HASH,
        "worker_id": "worker-legit",
        "round": 1,
        # The backdoor: a client trying to force the stale path. With a
        # valid handoff seeded, this must be ignored after the fix.
        "handoff_stale": True,
    }
    r = await c.post(
        "/v1/gates/gate-iso025/drafts",
        json=body,
        headers=scope_header("gates:execute"),
    )
    assert r.status_code == 202, (
        f"body handoff_stale flag still forces the stale path (backdoor "
        f"present); got {r.status_code}: {r.text}"
    )
    assert "draft_id" in json.loads(r.text)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-025")
@pytest.mark.asyncio
async def test_genuine_stale_handoff_still_rejected(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    """The REAL stale-detection path (three-anchor mismatch) must still
    reject with 422 RELAY-GATE-021 -- removing the backdoor must not
    weaken genuine fail-closed handoff validation.

    Seed a registered actor but a manifest whose commit_hash does NOT
    match the submitted ``manifest_commit_hash`` -> MANIFEST_NOT_ACTIVE.
    """
    c, db_path, _app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_ACTOR_HASH,
        manifest_commit_hash="sha256-" + ("a" * 64),  # different manifest
    )
    body = {
        # Submit a manifest hash that is NOT active -> genuine stale.
        "manifest_commit_hash": "sha256-" + ("b" * 64),
        "actor_identity_hash": _ACTOR_HASH,
        "worker_id": "worker-stale",
        "round": 1,
    }
    r = await c.post(
        "/v1/gates/gate-iso025-stale/drafts",
        json=body,
        headers=scope_header("gates:execute"),
    )
    assert r.status_code == 422, r.text
    env = json.loads(r.text)
    assert env["code"] == "RELAY-GATE-021", env
    assert env["details"]["reason"] == "MANIFEST_NOT_ACTIVE", env
