"""Evidence-bundle registry state-machine and sweep-eligibility helpers.

Companion module to the evidence_bundle_registry SQL table introduced in
packages/schemas/sql/0005_legal_holds.sql (spec section Y lines 5202-5213).

Two responsibilities:

  1. ``validate_registry_transition`` enforces the state-transition rules
     that the SQL CHECK alone cannot express:
       - The closed enum {active, superseded, tombstoned, legal_hold}.
       - ``active`` -> ``superseded`` requires ``superseded_by`` to be set
         to a *different* evidence_bundle_id.
       - ``* -> legal_hold`` requires ``legal_hold_id`` to be non-null.
       - ``tombstoned`` is a terminal state (no outgoing transitions).
       - Unknown ``from_state`` or ``to_state`` raises.

  2. ``is_sweep_eligible`` mirrors the retention-sweep predicate from
     spec section Y line 5218:

         state IN ('active','superseded') AND legal_hold_id IS NULL

     The helper exists so unit tests (and the Python-side worker) can
     exercise the filter without a live database; the canonical SQL form
     lives at packages/schemas/sql/queries/retention_sweep.sql and the
     two MUST stay aligned (the wire-format test
     test_retention_sweep_filter_helper_includes_active_excludes_others
     pins the helper to the SQL).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

# The four closed-enum members of evidence_bundle_registry.state, per the
# SQL CHECK in packages/schemas/sql/0005_legal_holds.sql.
REGISTRY_STATES: frozenset[str] = frozenset(
    {"active", "superseded", "tombstoned", "legal_hold"}
)

# The two members the retention sweep predicate is allowed to select.
# Spec section Y line 5218.
SWEEP_ELIGIBLE_STATES: frozenset[str] = frozenset({"active", "superseded"})

# Terminal states - once a bundle reaches one of these, no further
# state transitions are permitted on its registry row.
TERMINAL_STATES: frozenset[str] = frozenset({"tombstoned"})


class BundleRegistryTransitionError(ValueError):
    """Raised when an evidence_bundle_registry state transition violates the
    state-machine rules. Subclasses ValueError so existing call sites that
    catch ValueError continue to work; the specific subclass enables
    targeted handling in writer-service paths.
    """


def validate_registry_transition(
    *,
    evidence_bundle_id: str,
    from_state: str,
    to_state: str,
    superseded_by: str | None,
    legal_hold_id: str | None,
) -> None:
    """Validate a proposed state transition on an evidence_bundle_registry row.

    Raises ``BundleRegistryTransitionError`` (a ValueError subclass) on any
    violation. Returns ``None`` on success.

    Args:
        evidence_bundle_id: PK of the registry row being mutated.
        from_state: current state value on the row (pre-update).
        to_state: proposed new state value (post-update).
        superseded_by: proposed ``superseded_by`` value (post-update); MUST
            be a different ``evidence_bundle_id`` when ``to_state ==
            'superseded'``; MAY be set on any state but only validated
            against ``superseded``.
        legal_hold_id: proposed ``legal_hold_id`` value (post-update); MUST
            be non-null when ``to_state == 'legal_hold'``.

    Rules enforced:
        1. ``from_state`` and ``to_state`` MUST be members of REGISTRY_STATES.
        2. ``from_state`` MUST NOT be in TERMINAL_STATES (tombstoned is a
           one-way door, spec Y line 5219).
        3. If ``to_state == 'superseded'``, ``superseded_by`` MUST be set
           AND MUST differ from ``evidence_bundle_id`` (a bundle cannot
           supersede itself).
        4. If ``to_state == 'legal_hold'``, ``legal_hold_id`` MUST be set.
    """
    # Rule 1: closed-enum membership for both ends of the transition.
    if from_state not in REGISTRY_STATES:
        raise BundleRegistryTransitionError(
            f"unknown from_state {from_state!r}; expected one of "
            f"{sorted(REGISTRY_STATES)}"
        )
    if to_state not in REGISTRY_STATES:
        raise BundleRegistryTransitionError(
            f"unknown to_state {to_state!r}; expected one of "
            f"{sorted(REGISTRY_STATES)}"
        )

    # Rule 2: terminal states have no outgoing transitions.
    if from_state in TERMINAL_STATES and from_state != to_state:
        raise BundleRegistryTransitionError(
            f"state {from_state!r} is terminal; cannot transition to "
            f"{to_state!r} (spec Y line 5219: tombstone is the compliant-"
            f"deletion record and is not revertible)"
        )

    # Rule 3: 'superseded' requires superseded_by != self.
    if to_state == "superseded":
        if superseded_by is None:
            raise BundleRegistryTransitionError(
                "to_state='superseded' requires superseded_by to be set "
                "(spec Y line 5208: the supersession arc must point at "
                "the new bundle)"
            )
        if superseded_by == evidence_bundle_id:
            raise BundleRegistryTransitionError(
                "superseded_by must differ from evidence_bundle_id "
                "(a bundle cannot supersede itself)"
            )

    # Rule 4: 'legal_hold' requires legal_hold_id set.
    if to_state == "legal_hold" and legal_hold_id is None:
        raise BundleRegistryTransitionError(
            "to_state='legal_hold' requires legal_hold_id to be set "
            "(spec Y line 5211)"
        )


def is_sweep_eligible(*, state: str, legal_hold_id: str | None) -> bool:
    """Return True iff a registry row is eligible for the retention sweep.

    Mirrors the canonical SELECT predicate at
    packages/schemas/sql/queries/retention_sweep.sql (spec section Y line
    5218):

        state IN ('active','superseded') AND legal_hold_id IS NULL

    Raises:
        ValueError: if ``state`` is not a member of REGISTRY_STATES. The
            caller MUST normalize the state value before calling; an
            unknown state indicates a schema drift bug, not a sweep miss.
    """
    if state not in REGISTRY_STATES:
        raise ValueError(
            f"unknown evidence_bundle_registry.state {state!r}; expected "
            f"one of {sorted(REGISTRY_STATES)}"
        )
    return state in SWEEP_ELIGIBLE_STATES and legal_hold_id is None


__all__ = [
    "BundleRegistryTransitionError",
    "REGISTRY_STATES",
    "SWEEP_ELIGIBLE_STATES",
    "TERMINAL_STATES",
    "is_sweep_eligible",
    "validate_registry_transition",
]
