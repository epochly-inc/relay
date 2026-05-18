-- V3M1-F01 (2026-05-18) sidecar migration 0025: SQLite mirror of the
-- two run_result join tables.
--
-- Mirrors packages/schemas/sql/0012_v3_join_tables.sql. Per spec §A.1
-- the RunResult envelope binds to its contract_results and
-- gate_decisions via dedicated join tables (replacing the historical
-- array-column form for FK integrity). This migration lands the SQLite
-- mirror so the OSS sidecar profile carries the same relational shape
-- the hosted Postgres profile carries.
--
-- SQLite-vs-Postgres deltas (consistent with the rest of the sidecar
-- mirror set):
--   1. uuid columns -> TEXT (SQLite has no native uuid type).
--   2. FOREIGN KEY clauses written explicitly via REFERENCES so the
--      relational intent is documented in the DDL even if SQLite
--      PRAGMA foreign_keys is off in some test fixtures. The sidecar
--      runtime enables PRAGMA foreign_keys = ON, so enforcement is
--      real on the production path.
--
-- Per CLAUDE.md keystone invariant #8 (four atomic primitives), the
-- _allowed_tables() whitelist in apps/local-sidecar/relay_sidecar/db.py
-- is extended in the same V3M1-F01 batch to include both join table
-- names. Writes to these tables MUST route through
-- transactional_db_write_raw (single-writer queue; same path as
-- side_effect_markers / side_effect_proofs / cli_invocations /
-- idempotency_records). Direct db._writer.execute(...) is a banned
-- bypass per the audit-r3 BUG-A1 precedent.
--
-- Idempotent (CREATE ... IF NOT EXISTS).
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- run_result_contract_results (spec A.1; VAL-V3M1-001)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS run_result_contract_results (
    run_result_id      TEXT NOT NULL,
    contract_result_id TEXT NOT NULL,
    PRIMARY KEY (run_result_id, contract_result_id),
    FOREIGN KEY (run_result_id)      REFERENCES run_results(run_result_id),
    FOREIGN KEY (contract_result_id) REFERENCES contract_results(contract_result_id)
);

-- Reverse-direction index for "which run_results bind this
-- contract_result?" queries.
CREATE INDEX IF NOT EXISTS ix_run_result_contract_results_by_contract
    ON run_result_contract_results(contract_result_id);

-- -----------------------------------------------------------------------------
-- run_result_gate_decisions (spec A.1; VAL-V3M1-002)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS run_result_gate_decisions (
    run_result_id    TEXT NOT NULL,
    gate_decision_id TEXT NOT NULL,
    PRIMARY KEY (run_result_id, gate_decision_id),
    FOREIGN KEY (run_result_id)    REFERENCES run_results(run_result_id),
    FOREIGN KEY (gate_decision_id) REFERENCES gate_decisions(gate_decision_id)
);

-- Reverse-direction index for "which run_results bind this gate
-- decision?" queries.
CREATE INDEX IF NOT EXISTS ix_run_result_gate_decisions_by_gate_decision
    ON run_result_gate_decisions(gate_decision_id);
