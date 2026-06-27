"""Direct-unit mutation-hardening suite for the guard REGISTRY machinery.

The 23 guard predicates were only exercised indirectly through
``compare_and_set_state`` transitions, so the registry-level invariants
(``Guard`` frozen-ness, ``register_guard`` duplicate protection) were not
pinned by any assertion. Mutation testing (cosmic-ray) surfaced survivors at:

  * ``guards.py`` L78  -- ``@dataclass(frozen=True)`` (ReplaceTrueWithFalse).
  * ``guards.py`` L91  -- ``override: bool = False`` default (ReplaceFalseWithTrue).
  * ``guards.py`` L106 -- ``if name in _REGISTRY and not override`` (Delete_Not).

This module calls the registry surface DIRECTLY and asserts those invariants
so any mutant that flips them is killed. ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
import relay_sidecar.state_engine.guards as guards_mod
from relay_sidecar.state_engine.guards import (
    Guard,
    get_guard,
    is_handoff_guard,
    register_guard,
    registered_guard_names,
)


async def _noop_guard(conn, scope_kind, scope_id, payload, manifest_commit_hash):
    return True, {}


@pytest.mark.plumbing
def test_guard_dataclass_is_frozen() -> None:
    """``Guard`` is ``frozen=True``: mutating an attribute raises.

    Kills the L78 ``frozen=True`` -> ``frozen=False`` mutant -- under the
    mutant the assignment would silently succeed.
    """
    g = Guard(name="probe", check=_noop_guard)
    with pytest.raises(FrozenInstanceError):
        g.name = "tampered"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        g.check = _noop_guard  # type: ignore[misc]


@pytest.mark.plumbing
def test_register_guard_duplicate_without_override_raises() -> None:
    """Re-registering an existing name WITHOUT ``override`` raises ValueError.

    Kills BOTH the L91 default-flip mutant (``override=False`` -> ``True``,
    which would silently accept the duplicate) and the L106 ``not override``
    deletion mutant (``and not override`` -> ``and override``, which would
    evaluate the guard to False and skip the raise).
    """
    name = "z_mutation_probe_guard_dup"
    try:
        register_guard(name, _noop_guard)
        assert get_guard(name) is not None
        with pytest.raises(ValueError, match="already registered"):
            register_guard(name, _noop_guard)
    finally:
        guards_mod._REGISTRY.pop(name, None)


@pytest.mark.plumbing
def test_register_guard_override_true_replaces() -> None:
    """``override=True`` replaces an existing registration without raising.

    Pins the live arm of the L106 condition: with ``override=True`` the
    ``and not override`` clause is False, so no ValueError is raised and the
    new function takes the slot.
    """
    name = "z_mutation_probe_guard_override"

    async def _other_guard(conn, scope_kind, scope_id, payload, mch):
        return False, {"reason": "other"}

    try:
        first = register_guard(name, _noop_guard)
        assert first.check is _noop_guard
        second = register_guard(name, _other_guard, override=True)
        assert second.check is _other_guard
        assert get_guard(name).check is _other_guard
    finally:
        guards_mod._REGISTRY.pop(name, None)


@pytest.mark.plumbing
def test_register_guard_returns_guard_and_names_sorted() -> None:
    """``register_guard`` returns the new ``Guard``; names are sorted+present."""
    name = "z_mutation_probe_guard_names"
    try:
        g = register_guard(name, _noop_guard)
        assert isinstance(g, Guard)
        assert g.name == name
        names = registered_guard_names()
        assert name in names
        assert list(names) == sorted(names)
    finally:
        guards_mod._REGISTRY.pop(name, None)


@pytest.mark.plumbing
def test_is_handoff_guard_only_for_three_anchor() -> None:
    """``is_handoff_guard`` is True ONLY for the three-anchor guard name.

    Pins the L132 equality so a comparison-operator mutant that broadens or
    narrows the match is killed.
    """
    assert is_handoff_guard("three_anchor_handoff_valid") is True
    assert is_handoff_guard("valid_manifest_commit_hash") is False
    assert is_handoff_guard("") is False


@pytest.mark.plumbing
def test_get_guard_unknown_returns_none() -> None:
    assert get_guard("z_definitely_not_a_registered_guard") is None
