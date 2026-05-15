# epochly-relay-gate-engine

W8 gate evaluation pipeline (Python). Implements the deterministic
three-gate evaluator (scrutiny -> structural-review -> testing), the
gate_decision_drafts intake path, draft TTL enforcement, concurrent-draft
conflict (`RELAY-GATE-014`), the anti-bypass guard mirror
(`RELAY-GATE-061`), and the assertion-priority short-circuit
(`P0 > P1 > P2 > P3`).

This package is the W8.1 surface only. The control-plane write of
`gate_decisions` (with role grants, `compare_and_set_state`, signature
binding) lands in W8.2 (`packages/gate/decision_writer.py` + the
`relay_gate_engine` Postgres role). W8.3 ships the gate-restart-on-
failure trigger and W8.4 the remediation circuit breaker.

Contract assertions: VAL-W8-001 .. VAL-W8-007 and VAL-W8-041 (w8.1).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
