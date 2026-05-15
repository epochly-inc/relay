"""W8.4 plumbing tests: remediation_round_cap defaults + range (VAL-W8-030/031).

Drives the real migration 0011 schema (the ``gates`` table) plus the
``load_gate_config`` helper to verify:

  - VAL-W8-030: a fresh ``gates`` row without explicit
    ``remediation_round_cap`` defaults to 5.
  - VAL-W8-031: caps in [1, 50] are accepted; caps of 0 or 51 are
    rejected by the SQL CHECK constraint.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path

import aiosqlite
import pytest
from _w8_2_helpers import setup_writer_fixture
from _w8_4_helpers import (
    fetch_one,
    seed_gate,
    try_seed_gate,
)
from relay_gate_engine import (
    DEFAULT_REMEDIATION_ROUND_CAP,
    REMEDIATION_ROUND_CAP_MAX,
    REMEDIATION_ROUND_CAP_MIN,
    load_gate_config,
    validate_remediation_round_cap,
)

# ---------------------------------------------------------------------------
# VAL-W8-030: default remediation_round_cap is 5.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-030")
@pytest.mark.asyncio
async def test_remediation_round_cap_default_is_5(tmp_path: Path) -> None:
    """A gates row inserted without explicit cap defaults to 5."""
    wf = await setup_writer_fixture(tmp_path)
    try:
        # Insert a gates row WITHOUT specifying remediation_round_cap so
        # the column DEFAULT applies. We bypass seed_gate (which sets the
        # cap explicitly) and use a minimal raw INSERT.
        import uuid as _uuid
        from datetime import UTC, datetime
        gate_id = str(_uuid.uuid4())
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        async with aiosqlite.connect(str(wf.database.db_path)) as conn:
            await conn.execute(
                "INSERT INTO gates ("
                "  gate_id, name, scope_type, created_at"
                ") VALUES (?, ?, ?, ?)",
                (gate_id, "default-cap-gate", "run", now),
            )
            await conn.commit()

        row = await fetch_one(
            wf.database,
            "SELECT remediation_round_cap, cascade_on_block FROM gates "
            "WHERE gate_id = ?",
            (gate_id,),
        )
        assert row is not None
        cap = int(row[0])
        cascade = int(row[1])
        assert cap == 5
        assert cap == DEFAULT_REMEDIATION_ROUND_CAP
        # cascade_on_block defaults to 1 (true) -- VAL-W8-038 dependency.
        assert cascade == 1
    finally:
        await wf.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-030")
@pytest.mark.asyncio
async def test_load_gate_config_returns_default_cap(tmp_path: Path) -> None:
    """``load_gate_config`` returns a GateConfig with cap=5 on a
    default-inserted gate row."""
    wf = await setup_writer_fixture(tmp_path)
    try:
        # Default-insert path (no explicit cap).
        import uuid as _uuid
        from datetime import UTC, datetime
        gate_id = str(_uuid.uuid4())
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        async with aiosqlite.connect(str(wf.database.db_path)) as conn:
            await conn.execute(
                "INSERT INTO gates ("
                "  gate_id, name, scope_type, created_at"
                ") VALUES (?, ?, ?, ?)",
                (gate_id, "default-cap-gate", "run", now),
            )
            await conn.commit()

        cfg = await load_gate_config(wf.database, gate_id=gate_id)
        assert cfg is not None
        assert cfg.gate_id == gate_id
        assert cfg.remediation_round_cap == 5
        assert cfg.cascade_on_block is True
        assert cfg.scope_type == "run"
    finally:
        await wf.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-031: cap is configurable per gate; range [1, 50].
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-031")
@pytest.mark.asyncio
@pytest.mark.parametrize("cap", [1, 3, 10, 50])
async def test_remediation_round_cap_accepts_valid_values(
    tmp_path: Path, cap: int
) -> None:
    """Caps 1, 3, 10, 50 are accepted and round-trip through the row."""
    wf = await setup_writer_fixture(tmp_path)
    try:
        import uuid as _uuid
        gate_id = str(_uuid.uuid4())
        await try_seed_gate(
            wf.database, gate_id=gate_id, remediation_round_cap=cap
        )
        cfg = await load_gate_config(wf.database, gate_id=gate_id)
        assert cfg is not None
        assert cfg.remediation_round_cap == cap
    finally:
        await wf.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-031")
@pytest.mark.asyncio
@pytest.mark.parametrize("bad_cap", [0, 51, -1, 100])
async def test_remediation_round_cap_rejects_out_of_range(
    tmp_path: Path, bad_cap: int
) -> None:
    """Caps of 0 or 51 (and other out-of-range values) are rejected by
    the SQL CHECK constraint."""
    wf = await setup_writer_fixture(tmp_path)
    try:
        import uuid as _uuid
        gate_id = str(_uuid.uuid4())
        with pytest.raises(aiosqlite.IntegrityError) as excinfo:
            await seed_gate(
                wf.database,
                gate_id=gate_id,
                remediation_round_cap=bad_cap,
            )
        # The CHECK name appears in SQLite's error text.
        assert (
            "gates_remediation_round_cap_range" in str(excinfo.value)
            or "CHECK constraint failed" in str(excinfo.value)
        )
    finally:
        await wf.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-031")
def test_validate_remediation_round_cap_python_validator() -> None:
    """``validate_remediation_round_cap`` mirrors the SQL CHECK at the
    application layer so callers can produce a structured error before
    a DB round-trip."""
    # Accepts MIN and MAX boundaries.
    assert validate_remediation_round_cap(REMEDIATION_ROUND_CAP_MIN) == 1
    assert validate_remediation_round_cap(REMEDIATION_ROUND_CAP_MAX) == 50
    assert validate_remediation_round_cap(5) == 5
    # Rejects out-of-range.
    with pytest.raises(ValueError):
        validate_remediation_round_cap(0)
    with pytest.raises(ValueError):
        validate_remediation_round_cap(51)
    with pytest.raises(ValueError):
        validate_remediation_round_cap(-1)
