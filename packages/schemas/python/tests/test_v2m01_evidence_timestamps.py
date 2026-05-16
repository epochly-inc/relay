"""V2 M01 w1-6 evidence_timestamps + transparency_log_entries tests.

Covers contract assertions VAL-V2M01-033, VAL-V2M01-034, VAL-V2M01-035.

Spec anchor: section AB lines 5410-5446 (Trusted timestamping and transparency
log). Closes the §AB DDL gap surfaced by the 2026-05-16 spec audit.

Per CLAUDE.md keystone invariant #2 ("Pass without evidence is not a pass.")
and §AB line 5444, an evidence_bundle whose `evidence_timestamps` row is
missing cannot be marked `evidence_bundle_registry.state='active'`; the
signer halts with the canonical error code RELAY-EVID-031.

Per CLAUDE.md keystone invariant #11 (Trust anchor is the commercial moat)
and §AB line 5445, the transparency log is append-only. The application
role MUST be denied DELETE / UPDATE on transparency_log_entries. The OSS
sidecar profile emulates the GRANT model via BEFORE DELETE / BEFORE UPDATE
triggers that abort with RELAY-EVID-031.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

# Repo-root anchored paths. This file lives at
# packages/schemas/python/tests/test_v2m01_evidence_timestamps.py; parents[4]
# is the public relay repo root.
_THIS = Path(__file__).resolve()
_REPO_ROOT = _THIS.parents[4]
_SQL_DIR = _REPO_ROOT / "packages" / "schemas" / "sql"
_SIDECAR_MIGRATIONS = _REPO_ROOT / "apps" / "local-sidecar" / "migrations"
_NEW_DDL = _SQL_DIR / "0007_evidence_timestamps_log.sql"
_NEW_SIDECAR = _SIDECAR_MIGRATIONS / "0015_evidence_timestamps_log.sql"


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


def _sha256() -> str:
    return "sha256-" + ("0" * 64)


# ---------------------------------------------------------------------------
# Module presence
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_evidence_timestamps_ddl_file_exists() -> None:
    assert _NEW_DDL.is_file(), f"Missing canonical DDL file: {_NEW_DDL}"


@pytest.mark.plumbing
def test_evidence_timestamps_sidecar_migration_file_exists() -> None:
    assert _NEW_SIDECAR.is_file(), (
        f"Missing sidecar mirror migration: {_NEW_SIDECAR}"
    )


# ---------------------------------------------------------------------------
# VAL-V2M01-033: evidence_timestamps table DDL present with TSA fields
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-033")
def test_evidence_timestamps_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "evidence_timestamps")
    lowered = block.lower()
    assert "evidence_bundle_id uuid primary key" in lowered
    assert "references evidence_bundles(evidence_bundle_id)" in lowered
    assert "tsa_url text not null" in lowered
    assert "tsa_response_digest text not null" in lowered
    assert "tsa_response_ref text not null" in lowered
    assert "tsa_serial_number text" in lowered
    assert "tsa_gentime timestamptz not null" in lowered
    assert "tsa_witness_signature text" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-033")
def test_evidence_timestamps_sidecar_mirror_present() -> None:
    text = _read_sidecar_ddl().lower()
    assert "create table if not exists evidence_timestamps" in text
    assert "evidence_bundle_id" in text
    assert "tsa_url" in text
    assert "tsa_response_digest" in text
    assert "tsa_response_ref" in text
    assert "tsa_gentime" in text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-033")
def test_evidence_timestamps_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import EvidenceTimestamp

    payload = {
        "schema_version": "relay.evidence_timestamp.v1",
        "evidence_bundle_id": _new_uuid(),
        "tsa_url": "https://timestamp.digicert.com",
        "tsa_response_digest": _sha256(),
        "tsa_response_ref": "r2://relay-evidence/tsr/abc123.tsr",
        "tsa_genTime": _now_iso(),
    }
    et = EvidenceTimestamp.model_validate(payload)
    assert et.tsa_url == "https://timestamp.digicert.com"
    assert et.tsa_serial_number is None
    assert et.tsa_witness_signature is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-033")
def test_evidence_timestamps_rejects_missing_required_fields() -> None:
    from relay_schemas.envelopes import EvidenceTimestamp

    payload = {
        "schema_version": "relay.evidence_timestamp.v1",
        "evidence_bundle_id": _new_uuid(),
        # tsa_url missing
        "tsa_response_digest": _sha256(),
        "tsa_response_ref": "r2://x",
        "tsa_genTime": _now_iso(),
    }
    with pytest.raises(ValidationError):
        EvidenceTimestamp.model_validate(payload)


# ---------------------------------------------------------------------------
# VAL-V2M01-034: bundle without evidence_timestamps row cannot be active
# ---------------------------------------------------------------------------
#
# The integration test materializes the sidecar mirror migration against an
# in-memory SQLite database, creates a minimal stub of evidence_bundles and
# evidence_bundle_registry (these are owned by other features but are
# required for the trigger to fire), and verifies that:
#
#   1. UPDATE evidence_bundle_registry SET state='active' for a bundle
#      WITHOUT an evidence_timestamps row aborts with RELAY-EVID-031.
#   2. The same UPDATE succeeds once an evidence_timestamps row is
#      INSERTed for that bundle_id.


def _exec_script(conn: sqlite3.Connection, sql: str) -> None:
    conn.executescript(sql)


def _setup_bundle_registry_stub(conn: sqlite3.Connection) -> None:
    """Create minimal stubs of evidence_bundles + evidence_bundle_registry
    sufficient for VAL-V2M01-034 trigger testing. The full DDL for these
    tables is owned by other features (w1-1 evidence_bundles in 0003;
    w1-5 evidence_bundle_registry per spec section Y). The stubs here
    carry just the columns the trigger inspects.
    """
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS evidence_bundles (
            evidence_bundle_id TEXT PRIMARY KEY NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence_bundle_registry (
            evidence_bundle_id TEXT PRIMARY KEY NOT NULL,
            state TEXT NOT NULL DEFAULT 'building'
        );
        """
    )


def _apply_evidence_timestamps_migration(conn: sqlite3.Connection) -> None:
    conn.executescript(_read_sidecar_ddl())


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-034")
def test_update_to_active_blocked_without_evidence_timestamps_row() -> None:
    conn = sqlite3.connect(":memory:")
    try:
        _setup_bundle_registry_stub(conn)
        _apply_evidence_timestamps_migration(conn)

        bundle_id = _new_uuid()
        conn.execute(
            "INSERT INTO evidence_bundles (evidence_bundle_id) VALUES (?)",
            (bundle_id,),
        )
        conn.execute(
            "INSERT INTO evidence_bundle_registry "
            "(evidence_bundle_id, state) VALUES (?, 'building')",
            (bundle_id,),
        )
        # No evidence_timestamps row -> UPDATE to 'active' must abort.
        with pytest.raises(sqlite3.IntegrityError) as exc:
            conn.execute(
                "UPDATE evidence_bundle_registry SET state='active' "
                "WHERE evidence_bundle_id=?",
                (bundle_id,),
            )
        assert "RELAY-EVID-031" in str(exc.value), (
            f"abort message MUST cite RELAY-EVID-031; got {exc.value!r}"
        )
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-034")
def test_update_to_active_succeeds_with_evidence_timestamps_row() -> None:
    conn = sqlite3.connect(":memory:")
    try:
        _setup_bundle_registry_stub(conn)
        _apply_evidence_timestamps_migration(conn)

        bundle_id = _new_uuid()
        conn.execute(
            "INSERT INTO evidence_bundles (evidence_bundle_id) VALUES (?)",
            (bundle_id,),
        )
        conn.execute(
            "INSERT INTO evidence_bundle_registry "
            "(evidence_bundle_id, state) VALUES (?, 'building')",
            (bundle_id,),
        )
        conn.execute(
            "INSERT INTO evidence_timestamps ("
            "evidence_bundle_id, tsa_url, tsa_response_digest, "
            "tsa_response_ref, tsa_genTime"
            ") VALUES (?, ?, ?, ?, ?)",
            (
                bundle_id,
                "https://timestamp.digicert.com",
                _sha256(),
                "r2://relay-evidence/tsr/abc.tsr",
                _now_iso(),
            ),
        )
        # Now the UPDATE to 'active' must succeed.
        conn.execute(
            "UPDATE evidence_bundle_registry SET state='active' "
            "WHERE evidence_bundle_id=?",
            (bundle_id,),
        )
        row = conn.execute(
            "SELECT state FROM evidence_bundle_registry "
            "WHERE evidence_bundle_id=?",
            (bundle_id,),
        ).fetchone()
        assert row is not None
        assert row[0] == "active"
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-034")
def test_postgres_ddl_declares_active_guard_trigger_or_function() -> None:
    """Postgres path: the migration includes a guard function/trigger that
    references evidence_timestamps + cites RELAY-EVID-031. The actual
    Postgres trigger creation is gated on evidence_bundle_registry existing
    (DO $$ ... IF EXISTS ... END$$ pattern); the canonical body is
    inspected here via the SQL source.
    """
    text = _read_new_ddl()
    lowered = text.lower()
    assert "evidence_timestamps" in lowered
    assert "evidence_bundle_registry" in lowered
    assert "relay-evid-031" in lowered
    # The guard MUST reference an UPDATE on evidence_bundle_registry into
    # the 'active' state.
    assert "active" in lowered


# ---------------------------------------------------------------------------
# VAL-V2M01-035: transparency_log_entries table DDL present and append-only
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-035")
def test_transparency_log_entries_postgres_ddl() -> None:
    text = _read_new_ddl()
    block = _table_block(text, "transparency_log_entries")
    lowered = block.lower()
    assert "log_index bigserial primary key" in lowered
    assert "evidence_bundle_id uuid not null" in lowered
    assert "references evidence_bundles(evidence_bundle_id)" in lowered
    assert "bundle_digest text not null" in lowered
    assert "signer_key_id text not null" in lowered
    assert "appended_at timestamptz not null default now()" in lowered
    assert "tree_root_after text not null" in lowered
    assert "inclusion_proof_ref text" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-035")
def test_transparency_log_entries_postgres_grants_block_delete_update() -> None:
    """Spec section AB line 5445: the log is append-only. Application role
    grants explicit INSERT,SELECT only. The DDL MUST include a GRANT/REVOKE
    block (or REVOKE-all + GRANT INSERT,SELECT) so the role cannot DELETE
    or UPDATE.
    """
    text = _read_new_ddl().lower()
    # Either an explicit GRANT INSERT, SELECT or a REVOKE ALL + GRANT.
    assert "grant" in text and "insert" in text
    assert "transparency_log_entries" in text
    # No GRANT DELETE / UPDATE on transparency_log_entries in the source.
    assert "grant delete on transparency_log_entries" not in text
    assert "grant update on transparency_log_entries" not in text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-035")
def test_transparency_log_entries_sidecar_mirror_present() -> None:
    text = _read_sidecar_ddl().lower()
    assert "create table if not exists transparency_log_entries" in text
    assert "log_index" in text
    assert "tree_root_after" in text
    assert "inclusion_proof_ref" in text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-035")
def test_transparency_log_entries_append_only_delete_blocked() -> None:
    """The SQLite sidecar emulates the role-grant model via BEFORE DELETE
    triggers. A DELETE against transparency_log_entries MUST abort with
    RELAY-EVID-031.
    """
    conn = sqlite3.connect(":memory:")
    try:
        _setup_bundle_registry_stub(conn)
        _apply_evidence_timestamps_migration(conn)
        bundle_id = _new_uuid()
        conn.execute(
            "INSERT INTO evidence_bundles (evidence_bundle_id) VALUES (?)",
            (bundle_id,),
        )
        conn.execute(
            "INSERT INTO transparency_log_entries ("
            "evidence_bundle_id, bundle_digest, signer_key_id, "
            "appended_at, tree_root_after"
            ") VALUES (?, ?, ?, ?, ?)",
            (
                bundle_id,
                _sha256(),
                "key-1",
                _now_iso(),
                "merkle-root-0",
            ),
        )
        with pytest.raises(sqlite3.IntegrityError) as exc:
            conn.execute("DELETE FROM transparency_log_entries")
        assert "RELAY-EVID-031" in str(exc.value), (
            f"DELETE abort message MUST cite RELAY-EVID-031; got {exc.value!r}"
        )
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-035")
def test_transparency_log_entries_append_only_update_blocked() -> None:
    """The UPDATE path is also blocked (the log is strictly append-only)."""
    conn = sqlite3.connect(":memory:")
    try:
        _setup_bundle_registry_stub(conn)
        _apply_evidence_timestamps_migration(conn)
        bundle_id = _new_uuid()
        conn.execute(
            "INSERT INTO evidence_bundles (evidence_bundle_id) VALUES (?)",
            (bundle_id,),
        )
        conn.execute(
            "INSERT INTO transparency_log_entries ("
            "evidence_bundle_id, bundle_digest, signer_key_id, "
            "appended_at, tree_root_after"
            ") VALUES (?, ?, ?, ?, ?)",
            (
                bundle_id,
                _sha256(),
                "key-1",
                _now_iso(),
                "merkle-root-0",
            ),
        )
        with pytest.raises(sqlite3.IntegrityError) as exc:
            conn.execute(
                "UPDATE transparency_log_entries SET tree_root_after='x'"
            )
        assert "RELAY-EVID-031" in str(exc.value)
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-035")
def test_transparency_log_entries_envelope_roundtrip() -> None:
    from relay_schemas.envelopes import TransparencyLogEntry

    payload = {
        "schema_version": "relay.transparency_log_entry.v1",
        "log_index": 1234,
        "evidence_bundle_id": _new_uuid(),
        "bundle_digest": _sha256(),
        "signer_key_id": "k-1",
        "appended_at": _now_iso(),
        "tree_root_after": "merkle-root-hex",
    }
    tle = TransparencyLogEntry.model_validate(payload)
    assert tle.log_index == 1234
    assert tle.inclusion_proof_ref is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-035")
def test_transparency_log_entries_rejects_negative_log_index() -> None:
    from relay_schemas.envelopes import TransparencyLogEntry

    payload = {
        "schema_version": "relay.transparency_log_entry.v1",
        "log_index": -1,  # bigserial >= 1
        "evidence_bundle_id": _new_uuid(),
        "bundle_digest": _sha256(),
        "signer_key_id": "k-1",
        "appended_at": _now_iso(),
        "tree_root_after": "merkle-root-hex",
    }
    with pytest.raises(ValidationError):
        TransparencyLogEntry.model_validate(payload)


# ---------------------------------------------------------------------------
# Wire-format codegen + YAML alignment
# ---------------------------------------------------------------------------

_W1_6_NEW_ENVELOPES: tuple[str, ...] = (
    "EvidenceTimestamp",
    "TransparencyLogEntry",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-033")
def test_w1_6_new_envelopes_present_in_openapi_yaml() -> None:
    import yaml

    openapi_path = _REPO_ROOT / "packages" / "schemas" / "raw" / "openapi.yaml"
    doc = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))
    schemas = (doc.get("components") or {}).get("schemas") or {}
    missing = [n for n in _W1_6_NEW_ENVELOPES if n not in schemas]
    assert not missing, f"openapi.yaml missing components.schemas: {missing}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-033")
def test_w1_6_new_envelopes_present_in_envelopes_yaml() -> None:
    import yaml

    envelopes_path = (
        _REPO_ROOT / "packages" / "schemas" / "raw" / "envelopes.yaml"
    )
    doc = yaml.safe_load(envelopes_path.read_text(encoding="utf-8"))
    schemas = doc.get("schemas") or {}
    missing = [n for n in _W1_6_NEW_ENVELOPES if n not in schemas]
    assert not missing, f"envelopes.yaml missing schemas: {missing}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-033")
def test_w1_6_new_envelopes_pydantic_models_importable() -> None:
    from relay_schemas import envelopes as env

    for name in _W1_6_NEW_ENVELOPES:
        assert hasattr(env, name), f"relay_schemas.envelopes missing {name}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-033")
def test_w1_6_new_envelopes_schema_version_literal_pinned() -> None:
    from typing import get_args

    from relay_schemas import envelopes as env

    expected_pin = {
        "EvidenceTimestamp": "relay.evidence_timestamp.v1",
        "TransparencyLogEntry": "relay.transparency_log_entry.v1",
    }
    for name, version in expected_pin.items():
        cls = getattr(env, name)
        ann = cls.model_fields["schema_version"].annotation
        args = get_args(ann)
        assert args == (version,), (
            f"{name}.schema_version literal pin mismatch: expected "
            f"({version!r},) got {args!r}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-033")
def test_w1_6_new_envelopes_in_codegen_canonical_list() -> None:
    codegen_path = (
        _REPO_ROOT / "packages" / "schemas" / "scripts" / "codegen.py"
    )
    text = codegen_path.read_text(encoding="utf-8")
    for name in _W1_6_NEW_ENVELOPES:
        assert f'"{name}"' in text, (
            f"codegen.py missing {name!r} in CANONICAL_ENVELOPES"
        )
