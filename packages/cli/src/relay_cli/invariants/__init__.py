"""``rly verify-self`` invariant checkers (W5.5 VAL-W5-031..040).

Each invariant has its own module exposing a ``run(repo_root) -> Check``
function. The :mod:`relay_cli.invariants.runner` aggregator dispatches to
each checker, sorts the results deterministically, and returns the
canonical JSON shape.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""
