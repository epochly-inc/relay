"""verify_self package.

Holds the closed enum of finding codes referenced by VAL-W5-036.
The runner and per-invariant checkers live under
``packages/cli/src/relay_cli/invariants/``; this package is intentionally
small and import-cheap so the closed enum can be loaded without pulling
in any CLI runtime modules.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""
