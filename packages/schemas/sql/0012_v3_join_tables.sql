-- 0012_v3_join_tables.sql
--
-- V3M1-F01 (2026-05-18): canonical Postgres DDL for the two join tables
-- that bind a run_result to (a) its set of contract_results and (b) its
-- set of gate_decisions. Spec authority: §A.1 (RunResult envelope
-- definition) -- the join-table form replaces the historical array-
-- column form for FK integrity. The Pydantic RunResult model already
-- omits the array fields (`contract_result_ids`, `gate_decision_ids`);
-- this migration provides the relational binding the spec requires.
--
-- Shape (per VAL-V3M1-001 + VAL-V3M1-002):
--   run_result_contract_results(run_result_id uuid, contract_result_id uuid,
--                                PRIMARY KEY(run_result_id, contract_result_id))
--   run_result_gate_decisions(run_result_id uuid, gate_decision_id uuid,
--                              PRIMARY KEY(run_result_id, gate_decision_id))
--
-- Both tables carry inline FOREIGN KEY constraints to their parents per
-- the canonical Postgres shape used by 0003a_canonical_run_results_and_
-- gates.sql. Parent tables exist by the time this migration runs:
--   * run_results          -> 0003a_canonical_run_results_and_gates.sql
--   * contract_results     -> 0004_v2_canonical_tables.sql
--   * gate_decisions       -> 0003a_canonical_run_results_and_gates.sql
--
-- Per CLAUDE.md keystone invariant #1 (control plane writes the result):
-- writes to these join tables are gated by the SAME role grants that
-- restrict run_results / gate_decisions INSERT to the control-plane /
-- gate-engine roles. Those grants land in private relay-platform
-- migrations alongside the run_results / gate_decisions grants.
--
-- Per CLAUDE.md keystone invariant #8 (four atomic primitives): on the
-- sidecar SQLite mirror, writes to these tables MUST route through
-- ``transactional_db_write_raw``. The allowlist is updated in
-- apps/local-sidecar/relay_sidecar/db.py::_allowed_tables() in the
-- same V3M1-F01 batch (VAL-V3M1-003).
--
-- Indexes: the composite PRIMARY KEY provides a btree index on
-- (run_result_id, contract_result_id) / (run_result_id, gate_decision_id)
-- which serves the common forward direction (look up join rows for a
-- given run_result). A reverse index on the child side
-- (contract_result_id -> run_results, gate_decision_id -> run_results)
-- is added so the reverse lookup ("which run_results reference this
-- gate decision?") is also btree-served without a table scan.
--
-- ASCII-only per CLAUDE.md "ASCII-Safe Source".

-- -----------------------------------------------------------------------------
-- run_result_contract_results (spec A.1; VAL-V3M1-001)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS run_result_contract_results (
    run_result_id      uuid NOT NULL REFERENCES run_results(run_result_id),
    contract_result_id uuid NOT NULL REFERENCES contract_results(contract_result_id),
    PRIMARY KEY (run_result_id, contract_result_id)
);

-- Reverse-direction index for "which run_results bind this
-- contract_result?" queries (audit + replay-reproduce paths).
CREATE INDEX IF NOT EXISTS run_result_contract_results_by_contract
    ON run_result_contract_results(contract_result_id);

-- -----------------------------------------------------------------------------
-- run_result_gate_decisions (spec A.1; VAL-V3M1-002)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS run_result_gate_decisions (
    run_result_id    uuid NOT NULL REFERENCES run_results(run_result_id),
    gate_decision_id uuid NOT NULL REFERENCES gate_decisions(gate_decision_id),
    PRIMARY KEY (run_result_id, gate_decision_id)
);

-- Reverse-direction index for "which run_results bind this gate
-- decision?" queries (incident-root-cause + remediation-history paths).
CREATE INDEX IF NOT EXISTS run_result_gate_decisions_by_gate_decision
    ON run_result_gate_decisions(gate_decision_id);
