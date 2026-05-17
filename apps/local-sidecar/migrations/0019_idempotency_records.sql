-- 0019 idempotency_records (V2 M02 W2.9, VAL-V2M02-065..068).
--
-- Per spec B.2 lines 3374-3380: the control plane MUST persist
-- (Idempotency-Key, request_digest, response_status, response_ref)
-- tuples with a 24-hour TTL so a re-submission with the same key + same
-- digest returns the original response identically and a re-submission
-- with the same key + different digest is rejected as a logical
-- conflict (RELAY-IDEMPOTENCY-001).
--
-- The composite primary key (key, surface) keys per-endpoint so the
-- same Idempotency-Key on POST /v1/manifests does not collide with the
-- same key on POST /v1/redaction-policies. `surface` carries the
-- canonical route string (e.g., "POST /v1/manifests").
--
-- ASCII-only; idempotent CREATE.

CREATE TABLE IF NOT EXISTS idempotency_records (
    key                TEXT    NOT NULL,
    surface            TEXT    NOT NULL,
    request_digest     TEXT    NOT NULL,
    response_status    INTEGER NOT NULL,
    response_body      TEXT    NOT NULL,
    response_headers   TEXT    NOT NULL DEFAULT '{}',
    inserted_at        TEXT    NOT NULL,
    expires_at         TEXT    NOT NULL,
    PRIMARY KEY (key, surface)
);

CREATE INDEX IF NOT EXISTS ix_idempotency_records_expires_at
    ON idempotency_records (expires_at);
