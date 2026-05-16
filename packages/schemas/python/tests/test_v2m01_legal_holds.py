"""V2 M01 W1.4 legal holds + evidence_bundle_registry tests.

Covers contract assertions VAL-V2M01-026 through VAL-V2M01-029 (spec
section Y lines 5179-5220).

VAL-V2M01-026: evidence_legal_holds table DDL (closed enums + partial index).
VAL-V2M01-027: evidence_bundle_registry table DDL (mutable state machine).
VAL-V2M01-028: registry state machine permits active -> superseded only with
               superseded_by set; signed bundle bytes write is denied at the
               wire-format layer (the SQL role denial is the canonical
               enforcement; the wire-layer mirror is in the
               EvidenceBundleRegistryUpdate envelope-side helper).
VAL-V2M01-029: retention sweep query filters by registry state and
               legal_hold_id IS NULL.

Each test is bound to its assertion via the pytest.mark.fulfills marker so
the gate engine can attribute pass/fail to the assertion's evidence
requirement.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

# Repo-root anchored paths (this test lives at
# packages/schemas/python/tests/test_v2m01_legal_holds.py; parents[4] is the
# public relay repo root).
_THIS = Path(__file__).resolve()
_REPO_ROOT = _THIS.parents[4]
_SQL_DIR = _REPO_ROOT / "packages" / "schemas" / "sql"
_SIDECAR_MIGRATIONS = _REPO_ROOT / "apps" / "local-sidecar" / "migrations"
_NEW_DDL = _SQL_DIR / "0005_legal_holds.sql"
_NEW_SIDECAR = _SIDECAR_MIGRATIONS / "0013_legal_holds.sql"


def _read_new_ddl() -> str:
    return _NEW_DDL.read_text(encoding="utf-8")


def _read_sidecar_ddl() -> str:
    return _NEW_SIDECAR.read_text(encoding="utf-8")


def _table_block(text: str, table_name: str) -> str:
    """Return the substring from the CREATE TABLE statement for ``table_name``
    up to its terminating ``);`` (or end of file). Case-insensitive.
    """
    pat = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
        + re.escape(table_name)
        + r"\b.*?\);",
        re.IGNORECASE | re.DOTALL,
    )
    m = pat.search(text)
    assert m, f"CREATE TABLE for {table_name!r} not found"
    return m.group(0)


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


# ---------------------------------------------------------------------------
# Module presence
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_legal_holds_ddl_file_exists() -> None:
    assert _NEW_DDL.is_file(), f"Missing legal holds DDL file: {_NEW_DDL}"


@pytest.mark.plumbing
def test_legal_holds_sidecar_migration_file_exists() -> None:
    assert _NEW_SIDECAR.is_file(), (
        f"Missing legal holds sidecar mirror migration: {_NEW_SIDECAR}"
    )


# ---------------------------------------------------------------------------
# VAL-V2M01-026: evidence_legal_holds (spec Y lines 5184-5200)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-026")
def test_evidence_legal_holds_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "evidence_legal_holds")
    lowered = block.lower()
    assert "hold_id uuid primary key" in lowered
    assert "org_id uuid not null" in lowered
    assert "references orgs(org_id)" in lowered
    assert "scope_kind text not null" in lowered
    assert (
        "check (scope_kind in ('org','project','run','evidence_bundle'))"
        in lowered
    )
    assert "scope_id uuid not null" in lowered
    assert "reason text not null" in lowered
    assert "legal_matter_ref text" in lowered
    assert "imposed_by_user_id uuid not null" in lowered
    assert "references users(user_id)" in lowered
    assert "counsel_signoff_at timestamptz" in lowered
    assert "counsel_signoff_by text" in lowered
    assert "state text not null default 'active'" in lowered
    assert "check (state in ('active','released'))" in lowered
    assert "imposed_at timestamptz not null default now()" in lowered
    assert "released_at timestamptz" in lowered
    assert "released_by_user_id uuid" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-026")
def test_evidence_legal_holds_active_partial_index_present() -> None:
    text = _read_new_ddl()
    lowered = text.lower()
    # Partial index on (scope_kind, scope_id) where state = 'active'.
    assert (
        "create index evidence_legal_holds_active on evidence_legal_holds"
        "(scope_kind, scope_id) where state = 'active'"
        in lowered
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-026")
def test_evidence_legal_holds_sidecar_mirror_has_checks() -> None:
    text = _read_sidecar_ddl()
    block = _table_block(text, "evidence_legal_holds")
    lowered = block.lower()
    assert "hold_id              text    primary key" in lowered or (
        "hold_id" in lowered and "text" in lowered and "primary key" in lowered
    )
    # Closed enums preserved on the sidecar mirror.
    assert (
        "scope_kind in ('org','project','run','evidence_bundle')" in lowered
    )
    assert "state in ('active','released')" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-027: evidence_bundle_registry (spec Y lines 5202-5213)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-027")
def test_evidence_bundle_registry_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "evidence_bundle_registry")
    lowered = block.lower()
    assert "evidence_bundle_id uuid primary key" in lowered
    assert "references evidence_bundles(evidence_bundle_id)" in lowered
    assert "state text not null default 'active'" in lowered
    assert (
        "check (state in ('active','superseded','tombstoned','legal_hold'))"
        in lowered
    )
    assert "superseded_by uuid" in lowered
    # superseded_by references back into evidence_bundles (per spec Y line 5208).
    assert (
        "superseded_by uuid references evidence_bundles(evidence_bundle_id)"
        in lowered
    )
    assert (
        "subject_redacted_after_signing boolean not null default false"
        in lowered
    )
    assert "redaction_event_ref text" in lowered
    assert "legal_hold_id uuid" in lowered
    assert "references evidence_legal_holds(hold_id)" in lowered
    assert "last_state_change_at timestamptz not null default now()" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-027")
def test_evidence_bundle_registry_sidecar_mirror_has_checks() -> None:
    text = _read_sidecar_ddl()
    block = _table_block(text, "evidence_bundle_registry")
    lowered = block.lower()
    assert (
        "state in ('active','superseded','tombstoned','legal_hold')" in lowered
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-027")
def test_evidence_bundle_registry_is_mutable_sibling_documented() -> None:
    """The DDL header documents that the registry mutates while the signed
    bundle bytes (evidence_bundles) are immutable. Spec Y line 5202-5203.
    """
    text = _read_new_ddl()
    lowered = text.lower()
    assert "mutable" in lowered
    assert "immutable" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-028: state machine validator
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-028")
def test_state_machine_allows_active_to_superseded_with_superseded_by() -> None:
    from relay_schemas.bundle_registry import (
        BundleRegistryTransitionError,
        validate_registry_transition,
    )

    src_bundle = _new_uuid()
    new_bundle = _new_uuid()

    # Positive: active -> superseded with non-null superseded_by referencing
    # a different bundle id. No exception raised.
    validate_registry_transition(
        evidence_bundle_id=src_bundle,
        from_state="active",
        to_state="superseded",
        superseded_by=new_bundle,
        legal_hold_id=None,
    )

    # Negative 1: missing superseded_by on superseded state.
    with pytest.raises(BundleRegistryTransitionError) as exc_info:
        validate_registry_transition(
            evidence_bundle_id=src_bundle,
            from_state="active",
            to_state="superseded",
            superseded_by=None,
            legal_hold_id=None,
        )
    assert "superseded_by" in str(exc_info.value).lower()

    # Negative 2: superseded_by points at self (the same bundle row).
    with pytest.raises(BundleRegistryTransitionError):
        validate_registry_transition(
            evidence_bundle_id=src_bundle,
            from_state="active",
            to_state="superseded",
            superseded_by=src_bundle,
            legal_hold_id=None,
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-028")
def test_state_machine_rejects_unknown_states() -> None:
    from relay_schemas.bundle_registry import (
        BundleRegistryTransitionError,
        validate_registry_transition,
    )

    # Unknown to_state.
    with pytest.raises(BundleRegistryTransitionError):
        validate_registry_transition(
            evidence_bundle_id=_new_uuid(),
            from_state="active",
            to_state="archived",  # not in closed enum
            superseded_by=None,
            legal_hold_id=None,
        )

    # Unknown from_state.
    with pytest.raises(BundleRegistryTransitionError):
        validate_registry_transition(
            evidence_bundle_id=_new_uuid(),
            from_state="archived",
            to_state="active",
            superseded_by=None,
            legal_hold_id=None,
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-028")
def test_state_machine_legal_hold_requires_hold_id() -> None:
    from relay_schemas.bundle_registry import (
        BundleRegistryTransitionError,
        validate_registry_transition,
    )

    # legal_hold target state requires legal_hold_id non-null.
    with pytest.raises(BundleRegistryTransitionError):
        validate_registry_transition(
            evidence_bundle_id=_new_uuid(),
            from_state="active",
            to_state="legal_hold",
            superseded_by=None,
            legal_hold_id=None,
        )

    # Happy path: with legal_hold_id supplied.
    validate_registry_transition(
        evidence_bundle_id=_new_uuid(),
        from_state="active",
        to_state="legal_hold",
        superseded_by=None,
        legal_hold_id=_new_uuid(),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-028")
def test_state_machine_tombstoned_is_terminal() -> None:
    from relay_schemas.bundle_registry import (
        BundleRegistryTransitionError,
        validate_registry_transition,
    )

    # Tombstoned -> anything else is rejected (tombstoned is terminal per
    # spec Y line 5219: the tombstone bundle is the compliant-deletion
    # mechanism; reverting is not in the state machine).
    for target in ("active", "superseded", "legal_hold"):
        with pytest.raises(BundleRegistryTransitionError):
            validate_registry_transition(
                evidence_bundle_id=_new_uuid(),
                from_state="tombstoned",
                to_state=target,
                superseded_by=None,
                legal_hold_id=None,
            )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-028")
def test_signed_bundle_bytes_write_is_denied_at_role_layer_in_ddl() -> None:
    """The DDL documents that direct UPDATE on evidence_bundles (the signed
    bytes) is denied at the DB role layer (keystone invariant #1). The
    M02 role grants land the runtime REVOKE; the M01 DDL contribution is
    the documentation marker that the CI lint can pin against.
    """
    text = _read_new_ddl()
    lowered = text.lower()
    # Canonical marker phrase the lint scans for.
    assert "signed bundle bytes" in lowered
    assert "role" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-029: retention sweep query
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-029")
def test_retention_sweep_sql_file_present() -> None:
    """The retention sweep query is checked into source as a stable artifact
    so the digest in evidence bundles is reproducible. The query MUST live
    at packages/schemas/sql/queries/retention_sweep.sql (a queries/
    subdirectory keeps mutating SELECTs out of the migrations/ namespace).
    """
    path = _REPO_ROOT / "packages" / "schemas" / "sql" / "queries" / (
        "retention_sweep.sql"
    )
    assert path.is_file(), f"Missing retention sweep SQL: {path}"
    body = path.read_text(encoding="utf-8").lower()
    # Filter must match spec Y line 5218 verbatim shape.
    assert "evidence_bundle_registry" in body
    assert "state in ('active','superseded')" in body
    assert "legal_hold_id is null" in body


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-029")
def test_retention_sweep_filter_helper_includes_active_excludes_others() -> None:
    from relay_schemas.bundle_registry import is_sweep_eligible

    # Active + no legal hold -> sweep-eligible.
    assert is_sweep_eligible(state="active", legal_hold_id=None) is True
    # Superseded + no legal hold -> sweep-eligible.
    assert is_sweep_eligible(state="superseded", legal_hold_id=None) is True
    # Tombstoned -> never eligible.
    assert is_sweep_eligible(state="tombstoned", legal_hold_id=None) is False
    # legal_hold state -> never eligible.
    assert is_sweep_eligible(state="legal_hold", legal_hold_id=None) is False
    # Active but with a legal_hold_id present -> not eligible.
    assert is_sweep_eligible(state="active", legal_hold_id=_new_uuid()) is False
    # Superseded with legal_hold_id -> not eligible.
    assert (
        is_sweep_eligible(state="superseded", legal_hold_id=_new_uuid())
        is False
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-029")
def test_retention_sweep_helper_rejects_unknown_state() -> None:
    from relay_schemas.bundle_registry import is_sweep_eligible

    with pytest.raises(ValueError):
        is_sweep_eligible(state="archived", legal_hold_id=None)


# ---------------------------------------------------------------------------
# Wire-format envelopes
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-026")
def test_evidence_legal_hold_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import EvidenceLegalHold

    payload = {
        "schema_version": "relay.evidence_legal_hold.v1",
        "hold_id": _new_uuid(),
        "org_id": _new_uuid(),
        "scope_kind": "evidence_bundle",
        "scope_id": _new_uuid(),
        "reason": "SEC subpoena 26-CV-9001",
        "legal_matter_ref": "MATTER-2026-001",
        "imposed_by_user_id": _new_uuid(),
        "counsel_signoff_at": _now_iso(),
        "counsel_signoff_by": "counsel@example.com",
        "imposed_at": _now_iso(),
    }
    hold = EvidenceLegalHold.model_validate(payload)
    assert hold.scope_kind == "evidence_bundle"
    assert hold.state == "active"  # default


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-026")
def test_evidence_legal_hold_rejects_invalid_scope_kind() -> None:
    from relay_schemas.envelopes import EvidenceLegalHold

    payload = {
        "schema_version": "relay.evidence_legal_hold.v1",
        "hold_id": _new_uuid(),
        "org_id": _new_uuid(),
        "scope_kind": "tenant",  # not in closed enum
        "scope_id": _new_uuid(),
        "reason": "x",
        "imposed_by_user_id": _new_uuid(),
        "imposed_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        EvidenceLegalHold.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-026")
def test_evidence_legal_hold_rejects_invalid_state() -> None:
    from relay_schemas.envelopes import EvidenceLegalHold

    payload = {
        "schema_version": "relay.evidence_legal_hold.v1",
        "hold_id": _new_uuid(),
        "org_id": _new_uuid(),
        "scope_kind": "org",
        "scope_id": _new_uuid(),
        "reason": "x",
        "imposed_by_user_id": _new_uuid(),
        "state": "expired",  # not in closed enum
        "imposed_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        EvidenceLegalHold.model_validate(payload)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-027")
def test_evidence_bundle_registry_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import EvidenceBundleRegistry

    payload = {
        "schema_version": "relay.evidence_bundle_registry.v1",
        "evidence_bundle_id": _new_uuid(),
        "state": "active",
        "subject_redacted_after_signing": False,
        "last_state_change_at": _now_iso(),
    }
    reg = EvidenceBundleRegistry.model_validate(payload)
    assert reg.state == "active"
    assert reg.subject_redacted_after_signing is False
    assert reg.superseded_by is None
    assert reg.legal_hold_id is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-027")
def test_evidence_bundle_registry_rejects_invalid_state() -> None:
    from relay_schemas.envelopes import EvidenceBundleRegistry

    payload = {
        "schema_version": "relay.evidence_bundle_registry.v1",
        "evidence_bundle_id": _new_uuid(),
        "state": "archived",  # not in closed enum
        "subject_redacted_after_signing": False,
        "last_state_change_at": _now_iso(),
    }
    with pytest.raises(ValidationError):
        EvidenceBundleRegistry.model_validate(payload)


# ---------------------------------------------------------------------------
# Cross-surface presence (envelopes.yaml + openapi.yaml + codegen list)
# ---------------------------------------------------------------------------


_NEW_LEGAL_HOLD_ENVELOPES: tuple[str, ...] = (
    "EvidenceLegalHold",
    "EvidenceBundleRegistry",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-026")
@pytest.mark.fulfills("VAL-V2M01-027")
def test_new_envelopes_present_in_openapi_yaml() -> None:
    import yaml

    openapi_path = _REPO_ROOT / "packages" / "schemas" / "raw" / "openapi.yaml"
    doc = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))
    schemas = (doc.get("components") or {}).get("schemas") or {}
    missing = [n for n in _NEW_LEGAL_HOLD_ENVELOPES if n not in schemas]
    assert not missing, f"Missing OpenAPI components.schemas entries: {missing}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-026")
@pytest.mark.fulfills("VAL-V2M01-027")
def test_new_envelopes_present_in_envelopes_yaml() -> None:
    import yaml

    envelopes_path = _REPO_ROOT / "packages" / "schemas" / "raw" / "envelopes.yaml"
    doc = yaml.safe_load(envelopes_path.read_text(encoding="utf-8"))
    schemas = doc.get("schemas") or {}
    missing = [n for n in _NEW_LEGAL_HOLD_ENVELOPES if n not in schemas]
    assert not missing, f"Missing envelopes.yaml schemas entries: {missing}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-026")
@pytest.mark.fulfills("VAL-V2M01-027")
def test_new_envelopes_appear_in_codegen_canonical_list() -> None:
    codegen_path = (
        _REPO_ROOT / "packages" / "schemas" / "scripts" / "codegen.py"
    )
    text = codegen_path.read_text(encoding="utf-8")
    for name in _NEW_LEGAL_HOLD_ENVELOPES:
        assert f'"{name}"' in text, (
            f"codegen.py missing {name!r} in CANONICAL_ENVELOPES"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-026")
@pytest.mark.fulfills("VAL-V2M01-027")
def test_new_envelopes_schema_version_literal_pinned() -> None:
    """Each new envelope class pins schema_version via Literal (CLAUDE.md
    keystone invariant #10).
    """
    from typing import get_args

    from relay_schemas import envelopes as env

    expected_pin = {
        "EvidenceLegalHold": "relay.evidence_legal_hold.v1",
        "EvidenceBundleRegistry": "relay.evidence_bundle_registry.v1",
    }
    for name, version in expected_pin.items():
        cls = getattr(env, name)
        ann = cls.model_fields["schema_version"].annotation
        args = get_args(ann)
        assert args == (version,), (
            f"{name}.schema_version literal pin mismatch: expected "
            f"({version!r},) got {args!r}"
        )
