# Relay local-sidecar

Local-only FastAPI + aiosqlite process that the Relay SDK and CLI attach
to. Single instance per host, serialized via the four-state lockfile
classifier (spec H.5).

This is the W2 milestone package. W2.1 (this commit) lands the lockfile +
spawn semantics, the `local_atomic_file_write` atomic-persistence
primitive, and the `/health` nonce challenge. Later sub-features
(W2.2-W2.7) layer on the asyncio runtime, aiosqlite WAL, state engine,
event log, quiesce protocol, and crash recovery.

## Status

W2.1 scaffold. Not yet runnable as a daemon - the CLI entrypoint lands in
W5 (`rly sidecar start`). The library surface (`relay_sidecar.spawn`,
`relay_sidecar.primitives.local_atomic_file_write`) is exercised by tests
under `tests/`.

## Anchors

- Spec: `planning/epochly-replay-spec.md` section H.5 (lockfile four-state
  classifier), section H (four atomic-persistence primitives).
- CLAUDE.md keystone invariant #3 (manifest source of truth) + #8 (atomic
  persistence via four primitives).
- Contract: `relay-v0.1-oss-wedge/contract.md` VAL-W2-001 .. VAL-W2-011.

## ASCII-only

Per CLAUDE.md `ASCII-Safe Source`, all files under `apps/` are ASCII-only.
