"""VAL-CANON-001: ``pid_start_time_epoch_s`` ps-fallback must be locale-independent.

Bug (base commit c911607): the POSIX ``ps`` fallback in
``relay_sidecar.process.pid_start_time_epoch_s`` parses
``ps -p <pid> -o lstart=`` with ``time.strptime(out, "%a %b %d %H:%M:%S %Y")``.
The ``%a`` (abbreviated weekday) and ``%b`` (abbreviated month) directives are
LC_TIME-dependent: ``time.strptime`` matches against the *current* locale's
names, and ``ps`` itself emits ``lstart`` localized to LC_TIME. On a host with a
non-English LC_TIME (e.g. ``de_DE.UTF-8`` -> "Sa Mai 17 ...") the English
struct produced under the C locale fails to parse, ``strptime`` raises
``ValueError``, and the fallback returns ``None``. ``None`` makes the four-state
lockfile classifier (CLAUDE.md keystone / H.5 ZOMBIE_PORT branch) unable to
distinguish a stale PID from a live one (it conservatively refuses to terminate,
so a real port-holding zombie is never cleared).

The fix:
  1. forces ``LC_ALL=C``/``LANG=C`` on the ``ps`` subprocess env so ``lstart``
     is always emitted in English / C-locale form, AND
  2. parses that English struct under the C locale (via
     ``calendar.different_locale``) so the parse is correct regardless of the
     interpreter process's ambient LC_TIME.

These tests are RED at base commit c911607 and GREEN after the fix.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import locale
import os
import sys
import time

import pytest
from relay_sidecar import process as process_mod
from relay_sidecar.process import pid_start_time_epoch_s


def _locale_available(loc: str) -> bool:
    """Return True iff ``loc`` can be set for LC_TIME on this host."""
    saved = locale.setlocale(locale.LC_TIME)
    try:
        locale.setlocale(locale.LC_TIME, loc)
        return True
    except locale.Error:
        return False
    finally:
        locale.setlocale(locale.LC_TIME, saved)


# A C-locale (English) lstart string as ``ps`` emits it when LC_ALL=C is forced.
# Sat May 17 2025 12:34:56 local time.
_C_LOCALE_LSTART = "Sat May 17 12:34:56 2025"


@pytest.mark.plumbing
@pytest.mark.skipif(
    sys.platform == "win32", reason="ps fallback is POSIX-only; Windows uses psutil"
)
@pytest.mark.skipif(
    not _locale_available("de_DE.UTF-8"),
    reason="de_DE.UTF-8 LC_TIME locale not installed on this host",
)
def test_canon_001_lstart_parsed_under_non_english_lc_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """VAL-CANON-001: with the interpreter's LC_TIME set to a non-English
    locale, the ps-fallback must STILL parse the C-locale ``lstart`` ``ps``
    emits (under LC_ALL=C) and return the correct epoch.

    At base commit c911607 the parse runs ``time.strptime`` in the ambient
    (German) locale, which cannot match the English "Sat May ..." struct, so
    the helper returns None. The fix parses under the C locale -> correct epoch.
    """
    # Force the process LC_TIME to German for the duration of this test.
    saved = locale.setlocale(locale.LC_TIME)
    locale.setlocale(locale.LC_TIME, "de_DE.UTF-8")
    try:
        # Make psutil unavailable so the ps fallback is exercised, and stub the
        # ps subprocess to return the C-locale (English) lstart that a fixed
        # implementation forces via LC_ALL=C.
        monkeypatch.setitem(sys.modules, "psutil", None)

        def _fake_check_output(argv: list[str], **kwargs: object) -> str:
            # A correct implementation MUST force the C locale on the ps env so
            # lstart is English regardless of the host LC_TIME.
            env = kwargs.get("env")
            assert isinstance(env, dict), (
                "ps subprocess must be invoked with an explicit env forcing the "
                "C locale (env={'LC_ALL':'C','LANG':'C', ...})"
            )
            assert env.get("LC_ALL") == "C"
            assert env.get("LANG") == "C"
            return _C_LOCALE_LSTART + "\n"

        monkeypatch.setattr(
            process_mod.subprocess, "check_output", _fake_check_output
        )

        result = pid_start_time_epoch_s(os.getpid())
    finally:
        locale.setlocale(locale.LC_TIME, saved)

    assert result is not None, (
        "ps-fallback returned None under non-English LC_TIME: locale-dependent "
        "strptime failed to parse the C-locale lstart string (VAL-CANON-001)"
    )
    # Expected epoch: Sat May 17 12:34:56 2025 interpreted as LOCAL time
    # (matching the helper's documented time.mktime semantics).
    expected = time.mktime(time.strptime(_C_LOCALE_LSTART, "%a %b %d %H:%M:%S %Y"))
    assert result == pytest.approx(expected, abs=1.0)


@pytest.mark.plumbing
@pytest.mark.skipif(
    sys.platform == "win32", reason="ps fallback is POSIX-only; Windows uses psutil"
)
def test_canon_001_ps_subprocess_forces_c_locale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """VAL-CANON-001: the ps subprocess MUST be invoked with an env that forces
    the C locale (LC_ALL=C / LANG=C), so ``ps`` never emits a localized
    ``lstart`` that the parser cannot handle.

    At base commit c911607 ``subprocess.check_output`` is called with no ``env``
    argument, so the captured env is None -> this assertion fails (RED). After
    the fix the env carries LC_ALL=C / LANG=C (GREEN).
    """
    monkeypatch.setitem(sys.modules, "psutil", None)

    captured: dict[str, object] = {}

    def _fake_check_output(argv: list[str], **kwargs: object) -> str:
        captured["argv"] = argv
        captured["env"] = kwargs.get("env")
        return _C_LOCALE_LSTART + "\n"

    monkeypatch.setattr(process_mod.subprocess, "check_output", _fake_check_output)

    result = pid_start_time_epoch_s(os.getpid())

    assert captured.get("argv") == ["ps", "-p", str(os.getpid()), "-o", "lstart="]
    env = captured.get("env")
    assert isinstance(env, dict), (
        "ps subprocess invoked without an env forcing the C locale "
        "(VAL-CANON-001): localized LC_TIME hosts will emit unparseable lstart"
    )
    assert env.get("LC_ALL") == "C"
    assert env.get("LANG") == "C"
    assert result is not None


@pytest.mark.plumbing
@pytest.mark.skipif(
    sys.platform == "win32", reason="ps fallback is POSIX-only; Windows uses psutil"
)
@pytest.mark.skipif(
    not _locale_available("de_DE.UTF-8"),
    reason="de_DE.UTF-8 LC_TIME locale not installed on this host",
)
def test_canon_001_real_ps_subprocess_under_non_english_lc_time() -> None:
    """VAL-CANON-001 (end-to-end): with LC_TIME=de_DE in the interpreter
    AND no psutil, the REAL ps subprocess plus parse must still resolve the
    current process start time.

    This drives the actual subprocess (no stubbing) under a non-English
    ambient locale. At base, ps inherits the German LC_TIME and emits a
    localized lstart that the English strptime cannot parse -> None (RED).
    After the fix, ps is run with LC_ALL=C and parsed under the C locale
    -> a real epoch (GREEN).
    """
    if "psutil" in sys.modules:
        pytest.skip("psutil importable in this interpreter; cannot force ps path")
    try:
        import psutil  # type: ignore[import-not-found]  # noqa: F401

        pytest.skip("psutil installed; ps fallback not exercised")
    except ImportError:
        pass

    saved = locale.setlocale(locale.LC_TIME)
    saved_env = {k: os.environ.get(k) for k in ("LC_ALL", "LC_TIME", "LANG")}
    locale.setlocale(locale.LC_TIME, "de_DE.UTF-8")
    os.environ["LC_TIME"] = "de_DE.UTF-8"
    os.environ.pop("LC_ALL", None)
    try:
        result = pid_start_time_epoch_s(os.getpid())
    finally:
        locale.setlocale(locale.LC_TIME, saved)
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    assert result is not None, (
        "real ps fallback returned None under LC_TIME=de_DE.UTF-8 "
        "(VAL-CANON-001 locale dependence)"
    )
    assert result > 1_577_836_800.0  # after 2020-01-01
    assert result < time.time() + 3600.0


@pytest.mark.plumbing
def test_canon_001_existing_smoke_still_passes() -> None:
    """Regression guard: the helper still returns a real epoch for the current
    process under the default chain (psutil/ps/proc), proving the fix did not
    break the common path.
    """
    start = pid_start_time_epoch_s(os.getpid())
    assert start is not None
    assert start > 1_577_836_800.0
    assert start < time.time() + 3600.0
