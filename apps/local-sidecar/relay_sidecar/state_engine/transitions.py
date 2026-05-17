"""TRANSITION_TABLE: machine-readable form of spec C.3.

Loaded from ``packages/schemas/raw/state-transition-table.yaml`` so the
canonical-spec YAML and the production lookup table can never silently
drift. VAL-W2-059 enforces this: a parameterized pytest test loads the
YAML AND introspects this module's TRANSITION_TABLE and asserts byte-
identical (scope_kind, from, event, to) tuple coverage.

Per CLAUDE.md keystone invariant #10 (schema versioning): the YAML's
top-level ``schema`` field MUST equal ``relay.state_transition_table.v1``.
Loader refuses unknown versions.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

import yaml

# Path to the canonical YAML. Resolved at import time so test-time mutation
# of the file is picked up only on re-import; for production this is fine.
_HERE = Path(__file__).resolve()
# state_engine -> relay_sidecar -> local-sidecar -> apps -> relay (root)
_REPO_ROOT = _HERE.parent.parent.parent.parent.parent
_YAML_PATH = (
    _REPO_ROOT / "packages" / "schemas" / "raw" / "state-transition-table.yaml"
)

_REQUIRED_SCHEMA: Final[str] = "relay.state_transition_table.v1"


@dataclass(frozen=True)
class Transition:
    """One row of the state-transition table.

    Fields mirror spec C.3 columns: from, event, to, actor, guard,
    event_log_type. ``allowed_actor_kinds`` is a tuple to keep the
    dataclass hashable and allow set membership checks
    (``actor.kind in t.allowed_actor_kinds``).

    Per VAL-V2M03-024 (sub-feature w3-state-guards): every transition
    declares one or more named guards drawn from the registry in
    ``state_engine/guards.py``. ``compare_and_set_state`` evaluates every
    guard (left-to-right) before applying the CAS UPDATE; one False short-
    circuits with ``reason="GUARD_FAILED"`` (or ``"HANDOFF_INVALID"`` when
    the failing guard is the three-anchor handoff guard).
    """

    scope_kind: str
    from_state: str
    event: str
    to_state: str
    allowed_actor_kinds: tuple[str, ...]
    event_log_type: str
    guard_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScopeKindSpec:
    """Metadata for one scope kind: initial state, terminal states, transitions."""

    scope_kind: str
    initial_state: str
    terminal_states: frozenset[str]
    transitions: tuple[Transition, ...]


class TransitionTable:
    """Indexed lookup over the canonical transitions.

    Two indexes:
      - ``by_scope_state_event``: O(1) (scope_kind, from_state, event) -> Transition
      - ``by_scope_kind``: O(1) scope_kind -> ScopeKindSpec (for initial_state / terminal_states)

    The table is immutable post-construction; pass a different YAML at
    construction time for tests.
    """

    def __init__(self, by_scope_kind: dict[str, ScopeKindSpec]) -> None:
        self._by_scope_kind: dict[str, ScopeKindSpec] = dict(by_scope_kind)
        self._by_scope_state_event: dict[tuple[str, str, str], Transition] = {}
        for spec in by_scope_kind.values():
            for t in spec.transitions:
                key = (t.scope_kind, t.from_state, t.event)
                if key in self._by_scope_state_event:
                    raise ValueError(
                        f"state-transition-table.yaml has duplicate "
                        f"(scope_kind, from, event) tuple: {key}"
                    )
                self._by_scope_state_event[key] = t

    def lookup(
        self, scope_kind: str, from_state: str, event: str
    ) -> Transition | None:
        return self._by_scope_state_event.get((scope_kind, from_state, event))

    def scope_spec(self, scope_kind: str) -> ScopeKindSpec | None:
        return self._by_scope_kind.get(scope_kind)

    def initial_state(self, scope_kind: str) -> str | None:
        spec = self._by_scope_kind.get(scope_kind)
        return spec.initial_state if spec is not None else None

    def is_terminal(self, scope_kind: str, state: str) -> bool:
        spec = self._by_scope_kind.get(scope_kind)
        if spec is None:
            return False
        return state in spec.terminal_states

    def all_transitions(self) -> tuple[Transition, ...]:
        rows: list[Transition] = []
        for spec in self._by_scope_kind.values():
            rows.extend(spec.transitions)
        return tuple(rows)

    @property
    def transition_count(self) -> int:
        return len(self._by_scope_state_event)

    @property
    def scope_kinds(self) -> tuple[str, ...]:
        return tuple(self._by_scope_kind.keys())


def load_transition_table(yaml_path: Path | None = None) -> TransitionTable:
    """Load the canonical transition table from YAML.

    Raises:
        ValueError: schema mismatch, missing required keys, or duplicate
            (scope_kind, from, event) tuples.
        FileNotFoundError: yaml_path absent.
    """
    path = yaml_path if yaml_path is not None else _YAML_PATH
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(
            f"state-transition-table.yaml at {path}: top-level must be a mapping"
        )
    schema = data.get("schema")
    if schema != _REQUIRED_SCHEMA:
        raise ValueError(
            f"state-transition-table.yaml schema mismatch at {path}: "
            f"expected {_REQUIRED_SCHEMA!r}, got {schema!r}"
        )
    scope_kinds_yaml = data.get("scope_kinds")
    if not isinstance(scope_kinds_yaml, dict):
        raise ValueError(
            f"state-transition-table.yaml at {path}: missing 'scope_kinds' mapping"
        )

    by_scope_kind: dict[str, ScopeKindSpec] = {}
    for scope_kind, body in scope_kinds_yaml.items():
        if not isinstance(scope_kind, str):
            raise ValueError(f"scope_kind key must be a string: {scope_kind!r}")
        if not isinstance(body, dict):
            raise ValueError(f"scope_kind {scope_kind!r} body must be a mapping")
        initial_state = body.get("initial_state")
        if not isinstance(initial_state, str):
            raise ValueError(
                f"scope_kind {scope_kind!r}: 'initial_state' must be a string"
            )
        terminals_raw = body.get("terminal_states", [])
        if not isinstance(terminals_raw, list) or not all(
            isinstance(t, str) for t in terminals_raw
        ):
            raise ValueError(
                f"scope_kind {scope_kind!r}: 'terminal_states' must be a list of strings"
            )
        transitions_raw = body.get("transitions", [])
        if not isinstance(transitions_raw, list):
            raise ValueError(
                f"scope_kind {scope_kind!r}: 'transitions' must be a list"
            )
        transitions_built: list[Transition] = []
        for row in transitions_raw:
            if not isinstance(row, dict):
                raise ValueError(
                    f"scope_kind {scope_kind!r}: transition row must be a mapping; got {row!r}"
                )
            for required in ("from", "event", "to", "actor", "event_log_type"):
                if required not in row:
                    raise ValueError(
                        f"scope_kind {scope_kind!r}: transition missing required "
                        f"field {required!r}: {row!r}"
                    )
            actor_value = row["actor"]
            allowed_actor_kinds: tuple[str, ...]
            if isinstance(actor_value, list):
                allowed_actor_kinds = tuple(str(x) for x in actor_value)
            else:
                allowed_actor_kinds = (str(actor_value),)
            guards_value = row.get("guards", [])
            if not isinstance(guards_value, list):
                raise ValueError(
                    f"scope_kind {scope_kind!r}: 'guards' must be a list of "
                    f"strings; got {guards_value!r}"
                )
            guard_names_tuple: tuple[str, ...] = tuple(
                str(g) for g in guards_value
            )
            transitions_built.append(
                Transition(
                    scope_kind=scope_kind,
                    from_state=str(row["from"]),
                    event=str(row["event"]),
                    to_state=str(row["to"]),
                    allowed_actor_kinds=allowed_actor_kinds,
                    event_log_type=str(row["event_log_type"]),
                    guard_names=guard_names_tuple,
                )
            )
        by_scope_kind[scope_kind] = ScopeKindSpec(
            scope_kind=scope_kind,
            initial_state=initial_state,
            terminal_states=frozenset(terminals_raw),
            transitions=tuple(transitions_built),
        )

    return TransitionTable(by_scope_kind)


# Module-level singleton: loaded once on first import. Tests that need a
# different table construct their own via load_transition_table(path).
TRANSITION_TABLE: Final[TransitionTable] = load_transition_table()


__all__ = [
    "ScopeKindSpec",
    "TRANSITION_TABLE",
    "Transition",
    "TransitionTable",
    "load_transition_table",
]
