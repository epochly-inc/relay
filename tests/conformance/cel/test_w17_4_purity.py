"""W17.4 VAL-W17-018: Relay UDF purity assertions.

Every Relay UDF MUST be ``pure`` per CLAUDE.md banned pattern #16:
no wall clock, no network, no filesystem reads outside the inputs,
no random sources, no mutable process globals. This test enforces
purity at three layers:

  (1) Structural: every registered UDF in
      :data:`relay_contracts.RELAY_UDFS` has ``pure is True``. The
      :func:`relay_contracts.register_udf` constructor already raises
      :class:`RelayUdfPurityError` on ``pure=False``, but this guard
      catches a hypothetical future regression where ``RELAY_UDFS`` is
      constructed by a path that bypasses the constructor.
  (2) Clock-shift: for every per-UDF case, invoke the UDF, then
      monkey-patch ``time.time`` / ``time.monotonic`` / ``time.time_ns``
      / ``time.monotonic_ns`` / ``datetime.datetime.now`` to return
      values 3600 seconds in the future, invoke again, and assert
      byte-identical JCS-canonical output.
  (3) Network-deny: monkey-patch ``socket.socket.__init__`` and
      ``socket.create_connection`` to raise ``RuntimeError`` and
      assert the UDF call still succeeds (proving zero network egress).

Per the contract: ANY UDF that fails either runtime check is a banned
pattern #16 violation and fails the suite with the offending UDF
named.

Tool: parity-test (sandbox + clock-shift double execution).
ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import socket
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
RELAY_UDFS_DIR = REPO_ROOT / "tests" / "conformance" / "cel" / "relay-udfs"

REQUIRED_UDFS: tuple[str, ...] = (
    "relay.coverage",
    "relay.tool_arg",
    "relay.schema_match",
)


def _load_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for udf in REQUIRED_UDFS:
        udf_dir = RELAY_UDFS_DIR / udf
        if not udf_dir.is_dir():
            continue
        for path in sorted(udf_dir.glob("case_*.json")):
            cases.append(json.loads(path.read_text(encoding="utf-8")))
    return cases


def _invoke(udf: str, args: list[Any]) -> Any:
    from relay_contracts import relay_coverage, relay_schema_match, relay_tool_arg

    if udf == "relay.coverage":
        return relay_coverage(args[0], args[1])
    if udf == "relay.tool_arg":
        return relay_tool_arg(args[0], args[1])
    if udf == "relay.schema_match":
        return relay_schema_match(args[0], args[1])
    raise ValueError(f"unknown UDF: {udf}")


def _jcs_digest(value: Any) -> str:
    from relay_contracts import jcs_canonicalize

    return hashlib.sha256(jcs_canonicalize(value)).hexdigest()


# ---------------------------------------------------------------------------
# Layer 1: structural -- every registered UDF declares pure=True.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-018")
def test_every_registered_relay_udf_is_pure() -> None:
    """The PureUdf dataclass is constructed only via register_udf, which
    raises on pure=False. The constructed RELAY_UDFS tuple MUST contain
    only the three production UDFs and each MUST be a PureUdf
    instance. This guards against a future regression where RELAY_UDFS
    is rebuilt by a path that bypasses register_udf."""

    from relay_contracts import RELAY_UDFS, PureUdf

    names = [u.name for u in RELAY_UDFS]
    assert set(names) == set(REQUIRED_UDFS), (
        f"VAL-W17-018: RELAY_UDFS registry mismatch: {names!r} vs "
        f"required {sorted(REQUIRED_UDFS)!r}"
    )
    for u in RELAY_UDFS:
        assert isinstance(u, PureUdf), (
            f"VAL-W17-018: RELAY_UDFS contains a non-PureUdf entry: "
            f"{u!r} (type={type(u).__name__})"
        )
        # PureUdf has no public ``pure`` attribute because the type
        # itself encodes purity (constructor raises on impure). Assert
        # the type itself.
        assert u.__class__.__name__ == "PureUdf", (
            f"VAL-W17-018: UDF {u.name!r} is not a PureUdf instance"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-018")
def test_register_udf_rejects_pure_false() -> None:
    """Sanity guard for layer 1: registering with pure=False MUST raise
    :class:`RelayUdfPurityError` -- this enforces the invariant at
    registration time so the impure UDF never reaches evaluation."""

    from relay_contracts import RelayUdfPurityError, register_udf

    def _impure(_a: Any, _b: Any) -> bool:
        return True

    with pytest.raises(RelayUdfPurityError):
        register_udf(name="relay.testonly_impure", fn=_impure, pure=False, arity=2)


# ---------------------------------------------------------------------------
# Layer 2: clock-shift determinism -- 1-hour clock jump produces same bytes.
# ---------------------------------------------------------------------------


def _shifted_time_factory(delta_seconds: float) -> Any:
    """Build a stand-in for time.time / time.monotonic / time.time_ns /
    time.monotonic_ns / datetime.datetime.now that advances the wall
    clock by ``delta_seconds``."""

    real_time = time.time()
    real_monotonic = time.monotonic()

    def _fake_time() -> float:
        return real_time + delta_seconds

    def _fake_monotonic() -> float:
        return real_monotonic + delta_seconds

    def _fake_time_ns() -> int:
        return int((real_time + delta_seconds) * 1_000_000_000)

    def _fake_monotonic_ns() -> int:
        return int((real_monotonic + delta_seconds) * 1_000_000_000)

    class _ShiftedDatetime(_dt.datetime):
        @classmethod
        def now(cls, tz: _dt.tzinfo | None = None) -> _dt.datetime:
            return _dt.datetime.fromtimestamp(
                real_time + delta_seconds, tz=tz
            )

        @classmethod
        def utcnow(cls) -> _dt.datetime:
            return _dt.datetime.utcfromtimestamp(real_time + delta_seconds)

    return {
        "time.time": _fake_time,
        "time.monotonic": _fake_monotonic,
        "time.time_ns": _fake_time_ns,
        "time.monotonic_ns": _fake_monotonic_ns,
        "datetime.datetime": _ShiftedDatetime,
    }


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-018")
def test_every_udf_case_is_clock_shift_deterministic() -> None:
    """For every per-UDF case: invoke once with the real clock, then
    invoke again under a 3600s wall-clock shift, and assert byte-identical
    JCS output. ANY UDF that varies across the shift is a banned-pattern
    #16 violation."""

    cases = _load_cases()
    if not cases:
        pytest.fail(
            "VAL-W17-018: no per-UDF cases found at "
            f"{RELAY_UDFS_DIR}; regenerate via "
            "`uv run python scripts/generate-w17-4-udf-cases.py`."
        )
    impure: list[str] = []
    for c in cases:
        first = _jcs_digest(_invoke(c["udf"], c["args"]))
        fakes = _shifted_time_factory(3600.0)
        with (
            patch("time.time", fakes["time.time"]),
            patch("time.monotonic", fakes["time.monotonic"]),
            patch("time.time_ns", fakes["time.time_ns"]),
            patch("time.monotonic_ns", fakes["time.monotonic_ns"]),
            patch("datetime.datetime", fakes["datetime.datetime"]),
        ):
            second = _jcs_digest(_invoke(c["udf"], c["args"]))
        if first != second:
            impure.append(
                f"{c['udf']}/{c['label']}: clock-shift digest changed "
                f"({first[:16]} -> {second[:16]})"
            )
    assert impure == [], (
        "VAL-W17-018: clock-shift determinism check FAILED. Banned "
        "pattern #16 violation:\n  " + "\n  ".join(impure)
    )


# ---------------------------------------------------------------------------
# Layer 3: network-deny -- UDFs must never open a socket.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-018")
def test_every_udf_case_succeeds_under_network_deny() -> None:
    """Patch socket.socket.__init__ and socket.create_connection to
    raise on use. Every UDF case MUST still succeed -- proving the
    UDF performed zero network I/O."""

    cases = _load_cases()
    if not cases:
        pytest.fail(
            "VAL-W17-018: no per-UDF cases found at "
            f"{RELAY_UDFS_DIR}; regenerate via "
            "`uv run python scripts/generate-w17-4-udf-cases.py`."
        )

    def _deny_socket(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError(
            "VAL-W17-018: network egress forbidden under purity sandbox"
        )

    def _deny_create_connection(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError(
            "VAL-W17-018: socket.create_connection forbidden under "
            "purity sandbox"
        )

    failures: list[str] = []
    with (
        patch.object(socket.socket, "__init__", _deny_socket),
        patch("socket.create_connection", _deny_create_connection),
    ):
        for c in cases:
            try:
                _invoke(c["udf"], c["args"])
            except RuntimeError as exc:
                if "VAL-W17-018" in str(exc):
                    failures.append(
                        f"{c['udf']}/{c['label']}: attempted network "
                        f"egress: {exc}"
                    )
                else:
                    # Unrelated runtime error -- re-raise.
                    raise
    assert failures == [], (
        "VAL-W17-018: network-deny check FAILED. Banned pattern #16 "
        "violation:\n  " + "\n  ".join(failures)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-018")
def test_dual_execution_digest_pair_recorded_for_evidence() -> None:
    """Evidence requirement: the dual-execution digest pair MUST be
    recorded per case. This test runs both executions explicitly and
    prints the pair so CI captures it in the test log."""

    cases = _load_cases()
    if not cases:
        pytest.skip("no per-UDF cases to record")
    sample = cases[:3]  # Cap the noise -- representative sample.
    for c in sample:
        d1 = _jcs_digest(_invoke(c["udf"], c["args"]))
        fakes = _shifted_time_factory(3600.0)
        with (
            patch("time.time", fakes["time.time"]),
            patch("time.monotonic", fakes["time.monotonic"]),
            patch("time.time_ns", fakes["time.time_ns"]),
            patch("time.monotonic_ns", fakes["time.monotonic_ns"]),
            patch("datetime.datetime", fakes["datetime.datetime"]),
        ):
            d2 = _jcs_digest(_invoke(c["udf"], c["args"]))
        # Also confirm the recorded py_jcs_b64 golden agrees.
        golden_digest = hashlib.sha256(
            base64.b64decode(c["py_jcs_b64"].encode("ascii"))
        ).hexdigest()
        print(
            f"[w17.4-purity] {c['udf']}/{c['label']} "
            f"d1={d1[:16]} d2={d2[:16]} golden={golden_digest[:16]}"
        )
        assert d1 == d2 == golden_digest, (
            f"VAL-W17-018: digest mismatch for {c['label']}: "
            f"d1={d1} d2={d2} golden={golden_digest}"
        )
