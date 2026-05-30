"""VAL-ISO-033: gate evaluate SIGINT/SIGTERM handler must be async-signal-safe.

The previous ``_install_cancel_handler._handler`` performed a full httpx
cancel POST (TCP connect + TLS + request), built+emitted an envelope, and
called ``sys.exit`` -- all INSIDE the signal context. None of that is
async-signal-safe: httpx can deadlock if the signal arrives mid-allocation
or while a lock is held, and re-entrant ``sys.exit`` in a handler can corrupt
interpreter state.

Per the handler's own docstring (and the contract PASS criteria) the handler
must set ONLY ``_CANCELLED['flag'] = True``; the cancel POST + envelope emit
+ ``sys.exit`` belong in the polling loop's FOREGROUND flag check, outside the
signal context.

This module pins:
  * ``_handler`` sets only the flag and performs NO network I/O and does NOT
    call ``sys.exit``.
  * The foreground ``_perform_cancel_and_exit`` performs the cancel POST,
    emits the RELAY-CLI-130 envelope, and exits 130.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import signal
from typing import Any

import httpx
import pytest
from relay_cli.commands import gate as gate_mod
from relay_cli.exit_codes import EXIT_SIGINT_INTERRUPTED


@pytest.fixture(autouse=True)
def _reset_cancel_state() -> Any:
    saved = dict(gate_mod._CANCELLED)
    gate_mod._CANCELLED.clear()
    gate_mod._CANCELLED["flag"] = False
    yield
    gate_mod._CANCELLED.clear()
    gate_mod._CANCELLED.update(saved)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-033")
def test_handler_only_sets_flag_no_network_no_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Arm a known draft so the OLD handler would have issued a cancel POST.
    gate_mod._CANCELLED["draft_id"] = "draft-xyz"

    posts: list[str] = []

    def _no_post(*args: Any, **kwargs: Any) -> Any:
        posts.append(args[0] if args else kwargs.get("url", ""))
        raise AssertionError("handler must not perform network I/O")

    monkeypatch.setattr(httpx, "post", _no_post)

    # Install + invoke the registered SIGINT handler directly (no real signal).
    gate_mod._install_cancel_handler()
    handler = signal.getsignal(signal.SIGINT)
    assert callable(handler)

    # The handler MUST NOT raise SystemExit and MUST NOT touch the network.
    handler(signal.SIGINT, None)

    assert gate_mod._CANCELLED["flag"] is True
    assert posts == [], "handler issued a network POST in signal context"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-033")
def test_foreground_performs_cancel_post_and_exits_130(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate_mod._CANCELLED["flag"] = True
    gate_mod._CANCELLED["draft_id"] = "draft-xyz"

    posted: list[str] = []

    def _capture_post(url: str, *args: Any, **kwargs: Any) -> Any:
        posted.append(url)

        class _Resp:
            status_code = 200

        return _Resp()

    monkeypatch.setattr(httpx, "post", _capture_post)

    with pytest.raises(SystemExit) as exc:
        gate_mod._perform_cancel_and_exit(signal.SIGINT)

    assert exc.value.code == EXIT_SIGINT_INTERRUPTED
    assert len(posted) == 1
    assert posted[0].endswith("/v1/gate-decisions/draft-xyz/cancel")
