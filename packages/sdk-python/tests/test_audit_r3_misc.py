"""Audit R3 P1 misc fixes -- Python-side parity + safety tests.

Covers four P1 fixes in this package:
  * BUG-E2  _to_string float parity with TS String() / ECMA-262 ToString
  * BUG-E3  redaction_budget non-daemon thread leak + admission gate
  * BUG-E4  salt_registry.rotate() atomic single-_commit semantics

The matching TS-side fix (BUG-E1: gate-draft optional-field validation
in TypeScript) lives in packages/sdk-typescript/test/audit_r3_misc.test.ts.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import builtins
import contextlib
import math
import threading
from pathlib import Path

import pytest
from relay.redaction import _to_string
from relay.salt_registry import SaltRegistry
from relay_schemas.redaction_budget import (
    RelayBudgetExceededError,
    evaluate_matcher_budget,
)

# ---------------------------------------------------------------------------
# BUG-E2  _to_string float parity (Python <-> ECMA-262)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_to_string_whole_float_emits_integer_form() -> None:
    """``1.0`` MUST serialize to ``"1"`` (matches TS ``String(1.0)``)."""
    assert _to_string(1.0) == "1"
    assert _to_string(42.0) == "42"
    assert _to_string(-7.0) == "-7"


@pytest.mark.plumbing
def test_to_string_negative_zero_collapses() -> None:
    """``-0.0`` MUST serialize to ``"0"`` (matches TS ``String(-0)``)."""
    assert _to_string(-0.0) == "0"


@pytest.mark.plumbing
def test_to_string_non_finite_floats_match_ecma262() -> None:
    """NaN / +Inf / -Inf MUST serialize to the ECMA-262 names."""
    assert _to_string(float("nan")) == "NaN"
    assert _to_string(float("inf")) == "Infinity"
    assert _to_string(float("-inf")) == "-Infinity"


@pytest.mark.plumbing
def test_to_string_int_unchanged() -> None:
    """Integers pass through the final ``str()`` path; no regression."""
    assert _to_string(1) == "1"
    assert _to_string(0) == "0"
    assert _to_string(-2147483648) == "-2147483648"


@pytest.mark.plumbing
def test_to_string_bool_routed_to_literal_form() -> None:
    """``bool`` MUST keep the JSON-literal form, not the int form."""
    assert _to_string(True) == "true"
    assert _to_string(False) == "false"


@contextlib.contextmanager
def _relay_contracts_absent():
    """Force ``import relay_contracts`` to raise ImportError, simulating a
    real ``pip install epochly-relay`` end-user install whose dependency
    closure does NOT include ``epochly-relay-contracts`` (only the gate /
    evals / contracts packages depend on it). The workspace dev venv HAS
    ``relay_contracts`` importable, which is exactly why the parity corpus
    test never exercised this fallback path."""
    real_import = builtins.__import__

    def _blocked(name, *args, **kwargs):
        if name == "relay_contracts" or name.startswith("relay_contracts."):
            raise ImportError("relay_contracts not in install closure (simulated)")
        return real_import(name, *args, **kwargs)

    builtins.__import__ = _blocked
    try:
        yield
    finally:
        builtins.__import__ = real_import


# JS ``String(value)`` reference (verified against node `String()`): the float
# leaf fed to HMAC-SHA-256 for an ``action: "hash"`` redaction matcher MUST be
# byte-identical across the Python and TS SDKs. Values requiring exponential
# notation (>= 1e21) or a leading-zero fraction (<= 1e-5) are where Python's
# ``str()``/``repr()`` fallback DIVERGED from ECMA-262 ToString.
_ECMA262_FLOAT_TABLE = [
    (1e21, "1e+21"),
    (1.1e21, "1.1e+21"),
    (1e-6, "0.000001"),
    (1.23e-7, "1.23e-7"),
    (1e-7, "1e-7"),
    (1234567890123456800.0, "1234567890123456800"),
    (5e-324, "5e-324"),
    (1.7976931348623157e308, "1.7976931348623157e+308"),
]


@pytest.mark.plumbing
@pytest.mark.parametrize("value,expected", _ECMA262_FLOAT_TABLE)
def test_to_string_float_parity_holds_without_relay_contracts(
    value: float, expected: str
) -> None:
    """Round-4 re-hunt HIGH: ``_to_string`` MUST yield ECMA-262 ToString
    (byte-equal to JS ``String(value)``) for the HMAC-hash redaction path
    EVEN when ``relay_contracts`` is absent (the real end-user install).

    Before the fix the ImportError fallback returned Python ``repr``:
    ``1e21`` -> ``"1000000000000000000000"`` (vs JS ``"1e+21"``), ``1e-6`` ->
    ``"1e-06"`` (vs ``"0.000001"``), yielding a DIFFERENT HMAC-SHA-256 digest
    on Python vs TypeScript for the same float leaf (Py<->TS byte-parity
    break, keystone invariant #11). The module's self-contained
    ``_encode_jcs_number`` removes the optional dependency entirely.
    """
    with _relay_contracts_absent():
        assert _to_string(value) == expected


@pytest.mark.plumbing
def test_to_string_non_finite_floats_match_ecma262_without_relay_contracts() -> None:
    """The NaN/Inf names hold on the relay_contracts-absent path too."""
    with _relay_contracts_absent():
        assert _to_string(float("nan")) == "NaN"
        assert _to_string(float("inf")) == "Infinity"
        assert _to_string(float("-inf")) == "-Infinity"


# ---------------------------------------------------------------------------
# BUG-E3  redaction_budget thread discipline
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_evaluate_matcher_budget_threads_are_daemon() -> None:
    """Probe threads MUST be marked daemon=True so a runaway regex
    cannot block interpreter shutdown.
    """
    seen: list[threading.Thread] = []
    original_init = threading.Thread.__init__

    def _capturing_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        original_init(self, *args, **kwargs)
        if kwargs.get("name", "").startswith("relay-redos"):
            seen.append(self)

    threading.Thread.__init__ = _capturing_init  # type: ignore[assignment]
    try:
        result = evaluate_matcher_budget(
            matcher_id="m1",
            pattern=r"^[a-z]+$",
            stress_inputs=["abc"],
        )
    finally:
        threading.Thread.__init__ = original_init  # type: ignore[assignment]

    assert result is None
    assert seen, "expected at least one relay-redos probe thread"
    for t in seen:
        assert t.daemon is True, (
            f"probe thread {t.name!r} must be daemon=True; "
            "non-daemon threads block interpreter shutdown"
        )


@pytest.mark.plumbing
def test_evaluate_matcher_budget_admission_gate_refuses_when_saturated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the stuck-thread counter exceeds the cap, the gate MUST
    raise RelayBudgetExceededError instead of spawning another probe.
    """
    import relay_schemas.redaction_budget as rb

    monkeypatch.setattr(rb, "_STUCK_REGEX_THREADS", rb._STUCK_REGEX_THREAD_CAP)
    with pytest.raises(RelayBudgetExceededError) as excinfo:
        evaluate_matcher_budget(
            matcher_id="m-saturated",
            pattern=r"^a$",
            stress_inputs=["a"],
        )
    assert "matcher_id" in excinfo.value.details
    assert excinfo.value.details["matcher_id"] == "m-saturated"
    assert excinfo.value.details["stuck_threads"] >= rb._STUCK_REGEX_THREAD_CAP


@pytest.mark.plumbing
def test_evaluate_matcher_budget_happy_path_does_not_leak_counter() -> None:
    """A regex that completes in budget MUST leave the stuck counter
    unchanged.
    """
    import relay_schemas.redaction_budget as rb

    before = rb._STUCK_REGEX_THREADS
    result = evaluate_matcher_budget(
        matcher_id="m-fast",
        pattern=r"^[a-z]{1,4}$",
        stress_inputs=["abc", "xy"],
    )
    after = rb._STUCK_REGEX_THREADS
    assert result is None
    assert before == after, (
        f"stuck counter mutated on happy path: before={before} after={after}"
    )


# ---------------------------------------------------------------------------
# BUG-E4  salt_registry.rotate() atomicity
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_rotate_calls_commit_exactly_once(tmp_path: Path, monkeypatch) -> None:
    """rotate() MUST persist with a single _commit invocation so a
    crash between salt + policy_version writes cannot leave a
    half-applied state.
    """
    registry_path = tmp_path / "salts.json"
    reg = SaltRegistry(path=registry_path)
    # Bootstrap a predecessor via rotate (first-version path; the
    # registry has no public "bind only" helper).
    reg.rotate(
        policy_id="policy-A",
        new_salt_ref="salt-v1",
        new_policy_version="1",
        new_salt_bytes=b"\x00" * 32,
    )

    commit_calls: list[int] = []
    original_commit = reg._commit

    def _counting_commit() -> None:
        commit_calls.append(1)
        original_commit()

    monkeypatch.setattr(reg, "_commit", _counting_commit)
    reg.rotate(
        policy_id="policy-A",
        new_salt_ref="salt-v2",
        new_policy_version="2",
        new_salt_bytes=b"\x11" * 32,
    )
    assert len(commit_calls) == 1, (
        f"rotate() must call _commit exactly once; got {len(commit_calls)}"
    )


@pytest.mark.plumbing
def test_rotate_rolls_back_in_memory_on_commit_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If _commit raises, in-memory salt + policy_version mutations
    MUST be rolled back so the predecessor remains the active head.
    """
    registry_path = tmp_path / "salts.json"
    reg = SaltRegistry(path=registry_path)
    reg.rotate(
        policy_id="policy-A",
        new_salt_ref="salt-v1",
        new_policy_version="1",
        new_salt_bytes=b"\x00" * 32,
    )

    pre_salts = dict(reg._salts)
    pre_versions = list(reg._policy_versions)

    def _exploding_commit() -> None:
        raise OSError("simulated disk failure")

    monkeypatch.setattr(reg, "_commit", _exploding_commit)
    with pytest.raises(OSError, match="simulated disk failure"):
        reg.rotate(
            policy_id="policy-A",
            new_salt_ref="salt-v2",
            new_policy_version="2",
            new_salt_bytes=b"\x22" * 32,
        )
    assert reg._salts == pre_salts, "in-memory salts not rolled back"
    assert reg._policy_versions == pre_versions, (
        "in-memory policy_versions not rolled back"
    )


# ---------------------------------------------------------------------------
# Sanity guard: math import is intentional (silences potential pyflakes drift).
# ---------------------------------------------------------------------------


def test_module_imports_clean() -> None:
    assert math.isfinite(1.0)
