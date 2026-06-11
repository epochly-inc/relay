"""Deterministic single-gate evaluator for w8.1.

Surface:

  - :class:`GateEvaluator` -- evaluate a :class:`GatePolicy` against a
    submitted :class:`GateDecisionDraft`. Loads evidence_bundle ids
    through a :class:`EvidenceBundleProvider` (VAL-W8-003), sorts
    assertions by ``priority`` (VAL-W8-004), evaluates conditions via
    the W6 contract engine -- the wasm-backed evaluator constructed by
    :func:`relay_contracts.make_cel_evaluator` (VAL-W8-002) -- and
    enforces draft TTL (VAL-W8-006), the anti-bypass guard
    (VAL-W8-041), and the deterministic input contract (VAL-W8-005).

The evaluator is intentionally pure: no wall clock, no random, no
network, no env reads. The "now" timestamp used for TTL comparison is
either supplied by the caller (typical) or read from a callback the
caller supplies; the W6 banned-pattern grep enforces this here too.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, Protocol

from relay_contracts import (
    RELAY_UDFS,
    CelEvaluatorProtocol,
    RelayCelError,
    make_cel_evaluator,
)

from .errors import (
    AntiBypassRejectedError,
    DraftTtlExpiredError,
    GateEngineError,
    StaleHandoffError,
)

if TYPE_CHECKING:
    # GateDecisionDraft is defined in pipeline.py to keep the envelope
    # close to the orchestrator that consumes it. The evaluator uses it
    # only as a type hint (the runtime accepts any duck-typed object
    # carrying the documented attributes), so we import under
    # TYPE_CHECKING to avoid the circular import.
    from .pipeline import GateDecisionDraft

# ----------------------------------------------------------------------------
# Anti-bypass: declared-command flag screen (VAL-W8-041; W2.5 mirror).
# ----------------------------------------------------------------------------
#
# Banned tokens. Spec / CLAUDE.md banned pattern 8 names ``--no-verify``,
# ``--no-gpg-sign``, and ``--skip-hooks``. Contract assertion VAL-W8-041
# additionally pins the git short-form ``-n`` for ``--no-verify``. We DO
# NOT pin the in-source comment-marker tokens (the three uppercase
# T-O-D-O / F-I-X-M-E / H-A-C-K markers) here: those belong to the
# SIDECAR-side mirror at apps/local-sidecar/ relay_sidecar/anti_bypass.py
# BYPASS_MARKERS (which screens event_log_entries payloads, not gate-
# engine command lines). The gate engine screens shell-command flag
# invocations only.

BANNED_BYPASS_TOKENS: Final[tuple[str, ...]] = (
    "--no-verify",
    "--no-gpg-sign",
    "--skip-hooks",
    # git short-form for --no-verify (VAL-W8-041 explicitly names it).
    # Matched as a standalone arg to avoid collisions with longer flags
    # that happen to start with -n (e.g. -name, -nice).
    "-n",
)


# Boundary regex per banned token. ``--no-verify``-style flags need
# whitespace / end-of-string boundaries to avoid matching ``--no-verifyx``;
# the short-form ``-n`` needs the same plus a left boundary that is NOT
# another letter (so ``--name`` does not match). Compiled at import time;
# the gate engine evaluates many drafts, so the pattern reuse matters.
def _compile_token_pattern(token: str) -> re.Pattern[str]:
    boundary_l = r"(?:^|\s)"
    boundary_r = r"(?=$|\s)"
    return re.compile(boundary_l + re.escape(token) + boundary_r)


_BANNED_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = tuple(
    (t, _compile_token_pattern(t)) for t in BANNED_BYPASS_TOKENS
)


def _detect_banned_tokens(command_line: str) -> tuple[str, ...]:
    """Return banned tokens present in ``command_line`` (deterministic order).

    Tokens are matched as whole shell args; substring near-misses do
    NOT match (``--no-verifyx`` does not flag).

    Round-3 P1 fix #6: parse ``command_line`` with :func:`shlex.split`
    so banned tokens hidden in shell quotes or parentheses are
    surfaced. Pre-fix the regex required whitespace boundaries; tokens
    adjacent to quote / paren characters slipped through. Examples
    that were missed pre-fix:

      ``sh -c 'git commit --no-verify'``         (trailing ``'`` adjacent)
      ``(git commit --no-verify)``               (trailing ``)`` adjacent)
      ``bash -c "(--no-verify)"``                (both adjacencies)

    Falls back to the regex-based scan when ``shlex.split`` raises
    (malformed quote balance, etc.) so a deliberately-adversarial
    malformed input cannot DoS the gate engine by triggering an
    uncaught ValueError; the regex scan is then the conservative
    backstop.
    """
    if not command_line:
        return ()
    found: list[str] = []
    found_set: set[str] = set()
    try:
        # POSIX shlex splits on whitespace AND strips quote characters,
        # exposing tokens that were previously hidden by adjacency to a
        # quote. Parentheses do not have lexical meaning to shlex (it
        # does not enforce shell grammar), but they ARE included in the
        # adjacent token, which our exact-match check then detects via
        # token-equality OR strip. We additionally strip leading /
        # trailing ASCII punctuation characters that shells use as
        # grouping or pipeline metacharacters so an unquoted
        # ``(--no-verify)`` token is matched as ``--no-verify``.
        tokens = shlex.split(command_line, posix=True)
    except ValueError:
        tokens = ()
    # Strip surrounding shell-grouping punctuation. We do NOT strip
    # arbitrary characters -- only the punctuation set that real
    # shells use for grouping / sequencing.
    _GROUPING = "()[]{};|&"
    # Recursively re-shlex tokens that contain whitespace -- this
    # handles ``sh -c 'git commit --no-verify'`` where shlex strips
    # the outer single-quotes but leaves the inner shell command as
    # a single multi-word token. Without the inner re-split, the
    # embedded ``--no-verify`` is never seen as a standalone token.
    expanded: list[str] = []
    for t in tokens:
        if any(ws in t for ws in (" ", "\t", "\n")):
            try:
                expanded.extend(shlex.split(t, posix=True))
            except ValueError:
                # Inner token is malformed -- contribute it raw; the
                # regex fallback at the bottom of this function will
                # still scan the original command_line.
                expanded.append(t)
        else:
            expanded.append(t)
    stripped_tokens = [t.strip(_GROUPING) for t in expanded]
    banned_set = set(BANNED_BYPASS_TOKENS)
    for tok in stripped_tokens:
        if tok in banned_set and tok not in found_set:
            found_set.add(tok)
            found.append(tok)
    # Regex fallback / belt-and-suspenders: even when shlex.split
    # succeeds, the regex catches the (pre-fix) cases that already
    # worked. This preserves the existing behavior for whitespace-
    # bounded tokens and also handles any token shape that shlex
    # surfaces in an unexpected form. Order of BANNED_BYPASS_TOKENS
    # preserved.
    for token, pattern in _BANNED_PATTERNS:
        if token not in found_set and pattern.search(command_line):
            found_set.add(token)
            found.append(token)
    # Stable order: BANNED_BYPASS_TOKENS canonical order.
    canonical: list[str] = []
    for token in BANNED_BYPASS_TOKENS:
        if token in found_set:
            canonical.append(token)
    return tuple(canonical)


# ----------------------------------------------------------------------------
# Provider protocols. Concrete storage backends land in W8.2.
# ----------------------------------------------------------------------------


class EvidenceBundleProvider(Protocol):
    """Resolve ``evidence_bundle_id`` references to bundle records.

    The W8.1 evaluator consumes bundles BY ID ONLY (VAL-W8-003); inline
    artifact bodies are not accepted. A missing id MUST raise
    ``KeyError`` so the evaluator can record an ``invalid`` outcome
    binding the missing id in ``unmet_conditions``.
    """

    def get(self, bundle_id: str) -> Mapping[str, Any]:
        """Return the bundle dict for ``bundle_id`` or raise ``KeyError``."""
        ...


class ManifestCommandResolver(Protocol):
    """Resolve a ``command_hash`` to its manifest-declared ``command_line``.

    Per CLAUDE.md keystone invariant 3, the gate engine only acknowledges
    commands that the manifest declares. A ``command_hash`` not present
    in the active manifest MUST raise ``KeyError`` -- the engine treats
    that as a stale-handoff signal (the worker ran an undeclared command
    or the manifest commit hash is mismatched).
    """

    def resolve(self, command_hash: str) -> str:
        """Return the command line string for ``command_hash`` or raise."""
        ...


class AssertionLoader(Protocol):
    """Load :class:`GateAssertion` records by id.

    The evaluator consumes assertions by their stable ``VAL-W{N}-NNN``
    ids; the loader pulls the parsed CEL expression + priority + owner
    from contract storage (the contract publish path lands in W6.6).
    """

    def load(self, assertion_id: str) -> GateAssertion:
        """Return the assertion or raise ``KeyError``."""
        ...


# ----------------------------------------------------------------------------
# Domain dataclasses.
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class GateAssertion:
    """A single contract assertion as the gate engine sees it.

    ``priority`` is one of ``p0``, ``p1``, ``p2``, ``p3`` (per spec D.1
    line 3769 / contract preamble VAL-W6-043). ``expression`` is a CEL
    string compiled via the W6 evaluator. ``cascade_on_block`` mirrors
    the gate-level field but allows per-assertion override; in v0.1 the
    field is read from the gate, not the assertion -- it is held here
    only for forward-compat with spec A.5 line 3068.
    """

    assertion_id: str
    priority: str  # one of p0|p1|p2|p3
    expression: str

    def __post_init__(self) -> None:
        if self.priority not in {"p0", "p1", "p2", "p3"}:
            raise ValueError(
                f"GateAssertion.priority MUST be one of p0|p1|p2|p3; "
                f"got {self.priority!r} for {self.assertion_id!r}"
            )
        if not isinstance(self.expression, str) or not self.expression:
            raise ValueError(
                f"GateAssertion.expression MUST be a non-empty CEL string; "
                f"got {self.expression!r} for {self.assertion_id!r}"
            )


@dataclass(frozen=True)
class GatePolicy:
    """A gate's policy: ordered assertions + cascade behavior + TTL.

    ``conditions`` is the GatePolicy.conditions field per spec D.3 line
    3870; entries are CEL expression strings evaluated via the W6
    evaluator. ``draft_ttl_seconds`` defaults to 900 per spec A.5 line
    3056. ``cascade_on_block`` defaults to True per VAL-W8-004.
    """

    gate_id: str
    gate_name: str  # one of "scrutiny" | "structural-review" | "testing"
    assertions: tuple[GateAssertion, ...]
    conditions: tuple[str, ...] = ()
    cascade_on_block: bool = True
    draft_ttl_seconds: int = 900
    remediation_round_cap: int = 5

    def __post_init__(self) -> None:
        if self.gate_name not in {"scrutiny", "structural-review", "testing"}:
            raise ValueError(
                f"GatePolicy.gate_name MUST be one of "
                f"scrutiny|structural-review|testing; got {self.gate_name!r}"
            )
        if not isinstance(self.draft_ttl_seconds, int) or self.draft_ttl_seconds <= 0:
            raise ValueError(
                f"GatePolicy.draft_ttl_seconds MUST be positive int; "
                f"got {self.draft_ttl_seconds!r}"
            )


# Priority sort order: P0 first, then P1, P2, P3. VAL-W8-004.
_PRIORITY_RANK: Final[Mapping[str, int]] = {"p0": 0, "p1": 1, "p2": 2, "p3": 3}


def _sort_assertions(
    assertions: Iterable[GateAssertion],
) -> list[GateAssertion]:
    """Return a list sorted by priority then assertion_id (stable, deterministic).

    Ties on priority break by assertion_id (lexicographic). This makes
    the iteration order byte-identical across runs (VAL-W8-005) given
    identical inputs, even when the input order varies.
    """
    return sorted(
        assertions,
        key=lambda a: (_PRIORITY_RANK[a.priority], a.assertion_id),
    )


# ----------------------------------------------------------------------------
# Outcome envelope.
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class DraftOutcome:
    """The result of evaluating a draft against a gate policy.

    Mirrors the ``gate_decisions`` row shape (envelopes.yaml:82-120) for
    the fields w8.1 owns; the canonical row is written by w8.2 using
    these values plus ``decided_by``, ``decided_at``, ``signature``,
    ``signature_key_id``. The signed/timestamped fields are deliberately
    NOT computed here -- they belong to the writer service.
    """

    gate_id: str
    gate_name: str
    scope_type: str
    scope_id: str
    round: int
    action: str  # accept | remediate | block | invalid
    failed_assertion_ids: tuple[str, ...] = ()
    unmet_conditions: tuple[Mapping[str, Any], ...] = ()
    skipped_assertion_ids: tuple[str, ...] = ()
    evaluated_assertion_ids: tuple[str, ...] = ()
    sequence_log: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)


# ----------------------------------------------------------------------------
# TTL helper (VAL-W8-006).
# ----------------------------------------------------------------------------


def is_draft_expired(
    *,
    submitted_at: datetime,
    now: datetime,
    draft_ttl_seconds: int,
) -> bool:
    """Return True iff ``now - submitted_at >= draft_ttl_seconds``.

    Both timestamps MUST be timezone-aware (UTC); naive datetimes are
    rejected to avoid silent wall-clock-zone bugs. Equality at the TTL
    boundary counts as expired (closed-on-the-right interval), matching
    the contract preamble exit-code 7 mapping.
    """
    if submitted_at.tzinfo is None or submitted_at.tzinfo.utcoffset(submitted_at) is None:
        raise ValueError("submitted_at MUST be timezone-aware (UTC).")
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise ValueError("now MUST be timezone-aware (UTC).")
    if not isinstance(draft_ttl_seconds, int) or draft_ttl_seconds <= 0:
        raise ValueError(
            f"draft_ttl_seconds MUST be a positive int; got {draft_ttl_seconds!r}"
        )
    elapsed = (now - submitted_at).total_seconds()
    return elapsed >= draft_ttl_seconds


# ----------------------------------------------------------------------------
# Anti-bypass guard.
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class AntiBypassOverrideClaim:
    """Operator-override claim recorded in event_log_entries (VAL-W8-041).

    A draft whose declared command contains a banned bypass flag is
    rejected UNLESS an event_log_entries row with
    ``event_kind = 'operator_override'`` exists for the (scope, command)
    pair AND the actor referenced is human + (org_admin or org_owner).
    The W8.1 engine receives the override claim through the
    :class:`AntiBypassGuard` callback so we do not couple the gate
    engine to a particular event log storage backend.
    """

    actor_identity_hash: str
    actor_kind: str  # "human"
    actor_role: str  # "org_admin" | "org_owner"
    scope_type: str
    scope_id: str
    command_hash: str
    revoked: bool = False


class AntiBypassGuard:
    """Refuse drafts whose declared command carries a bypass flag.

    The guard is constructed with an optional override resolver that
    answers "is this command_hash explicitly approved on this scope by a
    registered org-admin?". Without the resolver, override is
    impossible and any banned flag rejects.
    """

    def __init__(
        self,
        *,
        override_resolver: (
            Callable[[str, str, str], AntiBypassOverrideClaim | None] | None
        ) = None,
    ) -> None:
        self._override_resolver = override_resolver

    def screen(
        self,
        *,
        command_hash: str,
        command_line: str,
        scope_type: str,
        scope_id: str,
    ) -> tuple[str, ...]:
        """Return the banned tokens detected, or ``()`` if the draft passes.

        Raises :class:`AntiBypassRejectedError` when banned tokens are
        present AND no valid override resolves. Returns the tuple of
        detected tokens when the draft is accepted (so callers can audit
        even on the override-permitted path).
        """
        detected = _detect_banned_tokens(command_line)
        if not detected:
            return ()

        if self._override_resolver is None:
            raise AntiBypassRejectedError(
                f"declared command {command_hash!r} contains bypass "
                f"flag(s) {list(detected)!r}; no operator override "
                f"resolver configured",
                payload={
                    "command_hash": command_hash,
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "detected_tokens": list(detected),
                },
            )

        claim = self._override_resolver(scope_type, scope_id, command_hash)
        if claim is None:
            raise AntiBypassRejectedError(
                f"declared command {command_hash!r} contains bypass "
                f"flag(s) {list(detected)!r}; no operator override claim "
                f"recorded for this (scope, command_hash)",
                payload={
                    "command_hash": command_hash,
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "detected_tokens": list(detected),
                },
            )
        if claim.revoked:
            raise AntiBypassRejectedError(
                "operator override claim is revoked",
                payload={
                    "command_hash": command_hash,
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "detected_tokens": list(detected),
                    "actor_identity_hash": claim.actor_identity_hash,
                },
            )
        if claim.actor_kind != "human":
            raise StaleHandoffError(
                "operator override claim actor is not human",
                payload={
                    "command_hash": command_hash,
                    "actor_identity_hash": claim.actor_identity_hash,
                    "actor_kind": claim.actor_kind,
                },
            )
        if claim.actor_role not in {"org_admin", "org_owner"}:
            raise AntiBypassRejectedError(
                "operator override claim actor lacks org_admin / org_owner role",
                payload={
                    "command_hash": command_hash,
                    "actor_identity_hash": claim.actor_identity_hash,
                    "actor_role": claim.actor_role,
                },
            )
        if claim.scope_type != scope_type or claim.scope_id != scope_id:
            raise AntiBypassRejectedError(
                "operator override claim binds a different scope",
                payload={
                    "command_hash": command_hash,
                    "expected_scope_type": scope_type,
                    "expected_scope_id": scope_id,
                    "claim_scope_type": claim.scope_type,
                    "claim_scope_id": claim.scope_id,
                },
            )
        if claim.command_hash != command_hash:
            raise AntiBypassRejectedError(
                "operator override claim binds a different command_hash",
                payload={
                    "expected_command_hash": command_hash,
                    "claim_command_hash": claim.command_hash,
                },
            )
        # Override accepted; return detected tokens for audit binding.
        return detected


# ----------------------------------------------------------------------------
# The evaluator.
# ----------------------------------------------------------------------------


class GateEvaluator:
    """Evaluate a single gate against a submitted draft (VAL-W8-001..007, 041).

    Construction is cheap: a W6 CEL evaluator is created once via the
    contracts factory (:func:`relay_contracts.make_cel_evaluator`, typed as
    :class:`relay_contracts.CelEvaluatorProtocol`) with the canonical Relay
    UDF set, and reused across calls so expression compilation caches persist.
    """

    def __init__(
        self,
        *,
        evidence_provider: EvidenceBundleProvider,
        manifest_resolver: ManifestCommandResolver,
        assertion_loader: AssertionLoader | None = None,
        anti_bypass: AntiBypassGuard | None = None,
        cel_evaluator: CelEvaluatorProtocol | None = None,
    ) -> None:
        self._evidence = evidence_provider
        self._manifest = manifest_resolver
        self._loader = assertion_loader
        self._anti_bypass = anti_bypass or AntiBypassGuard()
        # Single shared CEL evaluator with the canonical Relay UDF set.
        # VAL-W8-002: gate policy conditions MUST be evaluated by the W6
        # contract engine, never inlined. The evaluator is constructed by
        # the contracts factory -- the single engine-construction site,
        # which returns the wasm-backed engine (the only CEL backend since
        # the M6 single-engine cutover) -- so gate src stays env-free and
        # deterministic (VAL-W8-005 / VAL-CWC-P2TSGATE-010). The hint is
        # the CelEvaluatorProtocol facade so the gate stays decoupled from
        # engine internals.
        self._cel: CelEvaluatorProtocol = cel_evaluator or make_cel_evaluator(
            udfs=RELAY_UDFS
        )

    # --- Public API ---------------------------------------------------

    def evaluate(
        self,
        *,
        gate: GatePolicy,
        draft: GateDecisionDraft,
        now: datetime,
        evaluator_bindings: Mapping[str, Any] | None = None,
    ) -> DraftOutcome:
        """Evaluate ``draft`` against ``gate`` at logical time ``now``.

        Side-effect-free. The draft must already have passed the
        :class:`DraftLock` acquisition (VAL-W8-007) and any caller-side
        three-anchor handoff validation; this method enforces TTL,
        anti-bypass, evidence id resolution, condition evaluation,
        priority-ordered assertion evaluation, and outcome computation.
        """
        sequence: list[Mapping[str, Any]] = []
        sequence.append(_log_event(gate.gate_name + ".start", {
            "scope_type": draft.scope_type,
            "scope_id": str(draft.scope_id),
            "round": draft.round,
            "draft_id": str(draft.draft_id),
        }))

        # 1) TTL check (VAL-W8-006). Reject before any work.
        if is_draft_expired(
            submitted_at=draft.submitted_at,
            now=now,
            draft_ttl_seconds=gate.draft_ttl_seconds,
        ):
            raise DraftTtlExpiredError(
                f"draft {draft.draft_id!r} expired: "
                f"submitted_at + {gate.draft_ttl_seconds}s < now",
                payload={
                    "draft_id": str(draft.draft_id),
                    "scope_type": draft.scope_type,
                    "scope_id": str(draft.scope_id),
                    "round": draft.round,
                    "draft_ttl_seconds": gate.draft_ttl_seconds,
                    "submitted_at": draft.submitted_at.isoformat(),
                    "now": now.isoformat(),
                },
            )

        # 2) Anti-bypass (VAL-W8-041). Reject before any condition runs.
        try:
            command_line = self._manifest.resolve(draft.command_hash)
        except KeyError as exc:
            raise StaleHandoffError(
                f"command_hash {draft.command_hash!r} is not declared in "
                f"the active manifest -- worker ran an undeclared command",
                payload={
                    "draft_id": str(draft.draft_id),
                    "command_hash": draft.command_hash,
                },
            ) from exc
        self._anti_bypass.screen(
            command_hash=draft.command_hash,
            command_line=command_line,
            scope_type=draft.scope_type,
            scope_id=str(draft.scope_id),
        )

        # 3) Evidence bundle resolution by id (VAL-W8-003). Inline
        # artifact bodies are NOT accepted; missing ids yield invalid.
        unmet: list[Mapping[str, Any]] = []
        bundles: dict[str, Mapping[str, Any]] = {}
        for ref in draft.evidence_refs:
            bundle_id = _extract_bundle_id(ref)
            try:
                bundles[bundle_id] = self._evidence.get(bundle_id)
            except KeyError:
                unmet.append({
                    "kind": "missing_evidence_bundle",
                    "evidence_bundle_id": bundle_id,
                })
        if unmet:
            sequence.append(_log_event(gate.gate_name + ".missing_evidence", {
                "missing_ids": [u["evidence_bundle_id"] for u in unmet],
            }))
            return DraftOutcome(
                gate_id=gate.gate_id,
                gate_name=gate.gate_name,
                scope_type=draft.scope_type,
                scope_id=str(draft.scope_id),
                round=draft.round,
                action="invalid",
                failed_assertion_ids=(),
                unmet_conditions=tuple(unmet),
                evaluated_assertion_ids=(),
                skipped_assertion_ids=tuple(a.assertion_id for a in gate.assertions),
                sequence_log=tuple(sequence),
            )

        # 4) Gate policy conditions (VAL-W8-002). Evaluate via W6.
        bindings = dict(evaluator_bindings or {})
        bindings.setdefault("evidence_bundles", bundles)
        bindings.setdefault("draft", _draft_bindings(draft))

        condition_unmet: list[Mapping[str, Any]] = []
        for cond_idx, expression in enumerate(gate.conditions):
            cond_log: dict[str, Any] = {
                "expression": expression,
                "index": cond_idx,
            }
            try:
                value = self._cel.evaluate(expression, bindings=bindings)
            except RelayCelError as exc:
                cond_log["outcome"] = "error"
                cond_log["error_code"] = exc.code
                sequence.append(_log_event(
                    gate.gate_name + ".condition.error", cond_log,
                ))
                condition_unmet.append({
                    "kind": "condition_evaluation_error",
                    "expression": expression,
                    "error_code": exc.code,
                    "error_message": exc.message,
                })
                continue
            ok = _coerce_bool(value)
            cond_log["outcome"] = "pass" if ok else "fail"
            sequence.append(_log_event(
                gate.gate_name + ".condition", cond_log,
            ))
            if not ok:
                condition_unmet.append({
                    "kind": "unmet_condition",
                    "expression": expression,
                })

        # 5) Priority-ordered assertion execution (VAL-W8-004).
        sorted_assertions = _sort_assertions(gate.assertions)
        evaluated: list[str] = []
        skipped: list[str] = []
        failed: list[str] = []
        cascading = False

        for assertion in sorted_assertions:
            if cascading:
                skipped.append(assertion.assertion_id)
                sequence.append(_log_event(
                    gate.gate_name + ".assertion.skipped",
                    {
                        "assertion_id": assertion.assertion_id,
                        "priority": assertion.priority,
                        "reason": "cascade_on_block",
                    },
                ))
                continue
            evaluated.append(assertion.assertion_id)
            try:
                raw = self._cel.evaluate(assertion.expression, bindings=bindings)
                outcome_ok = _coerce_bool(raw)
            except RelayCelError as exc:
                failed.append(assertion.assertion_id)
                sequence.append(_log_event(
                    gate.gate_name + ".assertion.error",
                    {
                        "assertion_id": assertion.assertion_id,
                        "priority": assertion.priority,
                        "error_code": exc.code,
                    },
                ))
                if assertion.priority == "p0" and gate.cascade_on_block:
                    cascading = True
                continue
            if outcome_ok:
                sequence.append(_log_event(
                    gate.gate_name + ".assertion.pass",
                    {
                        "assertion_id": assertion.assertion_id,
                        "priority": assertion.priority,
                    },
                ))
                continue
            failed.append(assertion.assertion_id)
            sequence.append(_log_event(
                gate.gate_name + ".assertion.fail",
                {
                    "assertion_id": assertion.assertion_id,
                    "priority": assertion.priority,
                },
            ))
            if assertion.priority == "p0" and gate.cascade_on_block:
                cascading = True

        # 6) Compute action.
        action = _compute_action(
            failed_assertion_ids=failed,
            unmet_conditions=condition_unmet,
            assertions=sorted_assertions,
        )

        sequence.append(_log_event(gate.gate_name + ".end", {
            "action": action,
            "evaluated": evaluated,
            "failed": failed,
            "skipped": skipped,
        }))

        return DraftOutcome(
            gate_id=gate.gate_id,
            gate_name=gate.gate_name,
            scope_type=draft.scope_type,
            scope_id=str(draft.scope_id),
            round=draft.round,
            action=action,
            failed_assertion_ids=tuple(failed),
            unmet_conditions=tuple(condition_unmet),
            skipped_assertion_ids=tuple(skipped),
            evaluated_assertion_ids=tuple(evaluated),
            sequence_log=tuple(sequence),
        )


# ----------------------------------------------------------------------------
# Helpers.
# ----------------------------------------------------------------------------


def _log_event(name: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return a deterministic sequence-log entry.

    No wall-clock timestamp; the sequence is its own ordering. Tests
    assert on this log to verify VAL-W8-001 (gate ordering),
    VAL-W8-004 (priority short-circuit skip), and VAL-W8-005
    (determinism).
    """
    # Defensive copy: mappings can be mutated by callers after return.
    return {"event": name, "body": dict(body)}


def _extract_bundle_id(ref: Any) -> str:
    """Normalize an evidence_refs[] entry to a bundle id string.

    Per VAL-W8-003 the evaluator consumes BUNDLES BY ID ONLY -- inline
    artifact bodies are not accepted. ``evidence_refs[]`` entries are
    either a bare string id or an object with an ``evidence_bundle_id``
    field. Anything else (a dict carrying inline bytes, a list, a
    number) raises -- we surface the rejection as a stale-handoff error
    so the caller cannot accidentally smuggle inline data.
    """
    if isinstance(ref, str):
        return ref
    if isinstance(ref, Mapping):
        bid = ref.get("evidence_bundle_id")
        if isinstance(bid, str):
            return bid
        raise StaleHandoffError(
            "evidence_refs[] entry MUST be a string id or an object with "
            "evidence_bundle_id field; inline artifact bodies are not accepted",
            payload={"received": type(ref).__name__},
        )
    raise StaleHandoffError(
        "evidence_refs[] entry MUST be a string id or an object with "
        "evidence_bundle_id field; inline artifact bodies are not accepted",
        payload={"received": type(ref).__name__},
    )


def _coerce_bool(value: Any) -> bool:
    """Map a CEL evaluation result to a Python bool.

    The wasm-backed evaluator returns plain Python ``bool``. The
    ``BoolType`` class-name branch is a defensive tolerance for an
    engine-internal bool wrapper (an ``int`` subclass that is NOT
    ``bool``) handed back through a caller-supplied ``cel_evaluator``.
    Detection is by class name so the gate engine stays decoupled from
    CEL implementation internals (mirrors
    :func:`relay_contracts.pipeline._classify_outcome`). Non-bool
    returns surface as a runtime error -- contract policies MUST
    evaluate to bool; a non-bool result is a contract authoring bug.
    """
    if isinstance(value, bool):
        return value
    if type(value).__name__ == "BoolType":
        return int(value) == 1
    raise GateEngineError(
        f"gate condition / assertion expression returned non-bool: "
        f"{type(value).__name__}",
        payload={"value_type": type(value).__name__},
    )


def _draft_bindings(draft: GateDecisionDraft) -> Mapping[str, Any]:
    """Render a draft to a CEL-binding-friendly mapping.

    The CEL profile bans ``dyn(...)`` so we hand back primitives only.
    ``submitted_at`` is rendered as the ISO 8601 UTC string per
    timestamp-canonicalization.md.
    """
    return {
        "draft_id": str(draft.draft_id),
        "gate_id": str(draft.gate_id),
        "scope_type": draft.scope_type,
        "scope_id": str(draft.scope_id),
        "round": draft.round,
        "worker_id": str(draft.worker_id),
        "actor_identity_hash": draft.actor_identity_hash,
        "manifest_commit_hash": draft.manifest_commit_hash,
        "command_hash": draft.command_hash,
        "submitted_at": draft.submitted_at.astimezone(UTC).isoformat(),
    }


def _compute_action(
    *,
    failed_assertion_ids: Sequence[str],
    unmet_conditions: Sequence[Mapping[str, Any]],
    assertions: Sequence[GateAssertion],
) -> str:
    """Map (failed, unmet) -> ``accept|remediate|block|invalid``.

    Rules:

      - any ``unmet_conditions`` of kind ``missing_evidence_bundle`` ->
        ``invalid`` (handled by the evaluator early-return path; this
        function still treats them as ``invalid`` if surfaced).
      - any failed P0 assertion -> ``block``.
      - any failed P1/P2/P3 assertion OR any unmet_condition (other than
        missing evidence) -> ``remediate``.
      - otherwise -> ``accept``.

    Note: Cascade-on-block leaves higher-priority assertions unevaluated;
    those are reported in the outcome's ``skipped_assertion_ids`` and
    do NOT contribute to ``failed_assertion_ids``. This matches
    VAL-W8-004's "P1 must NOT appear in failed_assertion_ids when
    short-circuited by P0".
    """
    if any(u.get("kind") == "missing_evidence_bundle" for u in unmet_conditions):
        return "invalid"

    by_id = {a.assertion_id: a for a in assertions}
    failed_p0 = any(by_id.get(aid) and by_id[aid].priority == "p0"
                    for aid in failed_assertion_ids)
    if failed_p0:
        return "block"
    if failed_assertion_ids or unmet_conditions:
        return "remediate"
    return "accept"


__all__ = [
    "AntiBypassGuard",
    "AntiBypassOverrideClaim",
    "AssertionLoader",
    "BANNED_BYPASS_TOKENS",
    "DraftOutcome",
    "EvidenceBundleProvider",
    "GateAssertion",
    "GateEvaluator",
    "GatePolicy",
    "ManifestCommandResolver",
    "is_draft_expired",
]
