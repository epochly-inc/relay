"""WS-A engine factory tier-1 plumbing tests (M1 P1HOST, M5-flip transitioned).

``make_cel_evaluator()`` (``relay_contracts.engine``) is the SINGLE place the
``RELAY_CEL_ENGINE`` environment variable is read in the whole codebase. As of
M6 (WS-I) the wasm-backed ``WasmCelEvaluator`` is the ONLY engine: it is the
default (unset / blank env) and the only accepted explicit token (``wasm``);
ANY other value -- including the removed legacy engine token -- fails closed
with a clear ``ValueError`` naming the allowed set. The factory forwards the
``udfs`` / ``timeout_ms`` keyword arguments with identical semantics.

Covers:
  - VAL-CWC-P1HOST-009: ``make_cel_evaluator`` reads ``RELAY_CEL_ENGINE`` and
    returns the right class (factory-only env read); unknown value -> ValueError.
    The udf / timeout forwarding, the case-sensitivity / whitespace-trim /
    unknown-value handling, and the single-read-site determinism guard are
    engine-default-agnostic.
  - VAL-CWC-P1HOST-010: the engine-DEFAULT assertion. M5 (WS-H) flipped the
    factory default to wasm; M6 (WS-I) removed the legacy engine entirely, so
    the explicit legacy selection now FAILS CLOSED (the rollback hatch is
    closed) -- pinned by test_explicit_legacy_engine_fails_closed and the
    p6remove guard suite.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_SRC = REPO_ROOT / "packages" / "contracts" / "src" / "relay_contracts"
ENGINE_FILE = PKG_SRC / "engine.py"


@pytest.fixture(autouse=True)
def _clear_engine_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test controls ``RELAY_CEL_ENGINE`` explicitly; start from unset."""
    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-010: default engine (env unset) -- TRANSITIONED M1 celpy -> M5
# wasm. M1-M4 the unset default was celpy; M5 (WS-H) flips it to wasm, so these
# assertions now pin the NEW wasm default (the old celpy-default would be a false
# assertion post-flip). The flip itself is locked by the P5FLIP tests
# (test_p5flip_default_engine_wasm.py); these keep the P1HOST default-engine
# coverage truthful after the cutover.
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-010")
def test_default_engine_is_wasm_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """With ``RELAY_CEL_ENGINE`` absent, the factory returns the wasm evaluator.

    The default FLIPPED to wasm at M5 (WS-H). Through M1-M4 this returned celpy;
    post-flip an unset env constructs the ``WasmCelEvaluator``.
    """
    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)
    from relay_contracts.engine import make_cel_evaluator

    ev = make_cel_evaluator(udfs=())
    assert type(ev).__name__ == "WasmCelEvaluator"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-010")
def test_default_engine_is_wasm_returns_wasm_cel_evaluator_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The unset-env default is an actual ``WasmCelEvaluator`` instance (the
    wasm-backed evaluator, M5 flip), not merely a class whose name happens to
    match."""
    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)
    from relay_contracts.engine import make_cel_evaluator
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    ev = make_cel_evaluator()
    assert isinstance(ev, WasmCelEvaluator)


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-009: explicit engine selection (celpy / wasm) + unknown reject
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_explicit_legacy_engine_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M6 WS-I: the legacy engine token is no longer an allowed selection --
    it routes through the unknown-engine fail-closed ValueError (never a
    silent fallback to wasm, never the deleted legacy class)."""
    monkeypatch.setenv("RELAY_CEL_ENGINE", "celpy")
    from relay_contracts.engine import make_cel_evaluator

    with pytest.raises(ValueError) as ctx:
        make_cel_evaluator(udfs=())
    assert "wasm" in str(ctx.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_wasm_returns_wasm_cel_evaluator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RELAY_CEL_ENGINE", "wasm")
    from relay_contracts.engine import make_cel_evaluator

    ev = make_cel_evaluator(udfs=())
    assert type(ev).__name__ == "WasmCelEvaluator"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_unknown_engine_raises_clear_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bogus engine name is rejected with a clear ``ValueError`` naming the
    bad value AND the allowed set -- never a silent fallback to a default."""
    monkeypatch.setenv("RELAY_CEL_ENGINE", "bogus")
    from relay_contracts.engine import make_cel_evaluator

    with pytest.raises(ValueError) as ctx:
        make_cel_evaluator(udfs=())
    msg = str(ctx.value)
    assert "bogus" in msg, f"error must name the bad value; got {msg!r}"
    # The allowed engine names appear in the message so the caller can fix it
    # (wasm-only as of M6 WS-I).
    assert "wasm" in msg, (
        f"error must name the allowed engines; got {msg!r}"
    )


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-009: udfs / timeout_ms kwargs forwarded with identical semantics
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_custom_udf_forwarded_to_default_engine_rejected_structured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M6 WS-I port of the legacy custom-UDF forwarding case (ADR Revisions
    section 4: the custom-UDF capability was a legacy-engine feature and is
    DROPPED under the single wasm engine). The ``udfs`` keyword is still
    forwarded verbatim -- proven by the structured fail-closed rejection the
    wasm evaluator raises for a non-allowlist UDF at construction
    (RELAY-CEL-004 / RELAY-CEL-UDF-UNREGISTERED), never a silent drop."""
    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)
    from relay_contracts.engine import make_cel_evaluator
    from relay_contracts.errors import RelayCelUnsupportedUdfError
    from relay_contracts.udf import register_udf

    udf = register_udf("doubler", lambda x: x * 2, pure=True, arity=1)
    with pytest.raises(RelayCelUnsupportedUdfError) as ctx:
        make_cel_evaluator(udfs=(udf,))
    assert ctx.value.code == "RELAY-CEL-004"
    assert ctx.value.subtype == "RELAY-CEL-UDF-UNREGISTERED"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_allowlist_udfs_forwarded_to_wasm_evaluator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 3 native relay.* UDFs are forwarded to the wasm engine without
    rejection (they are baked into the wasm)."""
    monkeypatch.setenv("RELAY_CEL_ENGINE", "wasm")
    from relay_contracts import RELAY_UDFS
    from relay_contracts.engine import make_cel_evaluator
    from relay_contracts.evaluator import MAX_TIMEOUT_MS

    # Value assertion decoupled from the 50 ms wall-clock to avoid host-thread
    # jitter under concurrent load; the factory forwards timeout_ms to the wasm
    # evaluator. Production 50 ms default (CQ1) unchanged; root cause resolved by
    # M7 P7EDGE fuel metering.
    ev = make_cel_evaluator(udfs=RELAY_UDFS, timeout_ms=MAX_TIMEOUT_MS)
    assert type(ev).__name__ == "WasmCelEvaluator"
    assert ev.evaluate("1 + 2") == 3


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_extra_udf_rejected_on_wasm_via_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wasm engine's fail-closed extra-UDF rejection is preserved through
    the factory: a non-allowlist UDF forwarded to the wasm path raises."""
    monkeypatch.setenv("RELAY_CEL_ENGINE", "wasm")
    from relay_contracts.engine import make_cel_evaluator
    from relay_contracts.errors import RelayCelUnsupportedUdfError
    from relay_contracts.udf import register_udf

    extra = register_udf("my_check", lambda *a: True, pure=True, arity=1)
    with pytest.raises(RelayCelUnsupportedUdfError) as ctx:
        make_cel_evaluator(udfs=(extra,))
    assert ctx.value.code == "RELAY-CEL-004"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_timeout_ms_forwarded_and_bounds_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``timeout_ms`` is forwarded with identical bound semantics: a valid
    value is set on the evaluator; an out-of-bound value is rejected with
    ``ValueError`` exactly as the underlying evaluator would."""
    from relay_contracts.engine import make_cel_evaluator

    for engine in ("wasm",):
        monkeypatch.setenv("RELAY_CEL_ENGINE", engine)
        ev = make_cel_evaluator(timeout_ms=42, udfs=())
        assert ev.timeout_ms == 42
        with pytest.raises(ValueError):
            make_cel_evaluator(timeout_ms=0, udfs=())
        with pytest.raises(ValueError):
            make_cel_evaluator(timeout_ms=10_000, udfs=())


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_default_udfs_is_empty_tuple(monkeypatch: pytest.MonkeyPatch) -> None:
    """``make_cel_evaluator()`` with no ``udfs`` argument defaults to an empty
    UDF set (constructs cleanly with the empty default UDF set)."""
    from relay_contracts.engine import make_cel_evaluator

    monkeypatch.delenv("RELAY_CEL_ENGINE", raising=False)
    assert type(make_cel_evaluator()).__name__ == "WasmCelEvaluator"


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-009: edge cases for the env value parse
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_empty_string_env_treated_as_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An EMPTY ``RELAY_CEL_ENGINE`` (set but blank, e.g. ``RELAY_CEL_ENGINE=``)
    is treated as 'unset' -> the default. A blank env var is the standard 'no
    selection' signal; it resolves to the default (wasm, the only engine as of
    M6)."""
    monkeypatch.setenv("RELAY_CEL_ENGINE", "")
    from relay_contracts.engine import make_cel_evaluator

    assert type(make_cel_evaluator(udfs=())).__name__ == "WasmCelEvaluator"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_engine_value_is_case_sensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    """The engine value is matched against the exact lowercase tokens; an
    upper/mixed-case value is NOT silently coerced to a known engine -- it is
    rejected with the clear ValueError. (Determinism: no locale-dependent
    case-folding in selection; the env contract is the exact token.)"""
    from relay_contracts.engine import make_cel_evaluator

    monkeypatch.setenv("RELAY_CEL_ENGINE", "WASM")
    with pytest.raises(ValueError):
        make_cel_evaluator(udfs=())
    monkeypatch.setenv("RELAY_CEL_ENGINE", "Wasm")
    with pytest.raises(ValueError):
        make_cel_evaluator(udfs=())


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_surrounding_whitespace_in_env_value_is_trimmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A value with surrounding whitespace (a common shell-export accident,
    ``RELAY_CEL_ENGINE=' wasm '``) is trimmed before matching so the operator
    intent is honored rather than silently rejected."""
    from relay_contracts.engine import make_cel_evaluator

    monkeypatch.setenv("RELAY_CEL_ENGINE", "  wasm  ")
    assert type(make_cel_evaluator(udfs=())).__name__ == "WasmCelEvaluator"


# ---------------------------------------------------------------------------
# VAL-CWC-P1HOST-009: RELAY_CEL_ENGINE is READ ONLY in engine.py (determinism)
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_relay_cel_engine_read_only_in_engine_module() -> None:
    """The ``RELAY_CEL_ENGINE`` env var is READ (via ``os.environ`` / getenv) in
    exactly ONE source file under ``packages/contracts/src`` -- ``engine.py`` --
    so engine selection cannot leak into ``evaluator.py`` /
    ``wasm_backed_evaluator.py`` / ``pipeline.py`` / ``errors.py`` (and,
    downstream, into ``packages/gate`` src, which would trip the VAL-W8-005
    gate-determinism grep).

    The invariant is about the env READ, not the mere appearance of the token.
    ``wasm_backed_evaluator.py`` NAMES ``RELAY_CEL_ENGINE`` in a docstring that
    explicitly states the var is NOT read there ("This module never touches
    ``os.environ``") -- a deliberate negative reference, not a violation. A
    substring grep is fooled by that prose, so this guard parses the source
    AST and looks for a REAL environment access node -- ``os.environ`` /
    ``os.getenv`` / ``getenv`` as an attribute, subscript, or call -- which
    never matches a string literal or comment. ``engine.py`` is the sanctioned
    read site (it performs exactly such an access); every OTHER source file
    under ``packages/contracts/src`` must contain NO environment-access node at
    all. The guard also asserts ``engine.py`` itself still performs the read,
    so a refactor that drops the read without relocating it is caught.
    """

    def _reads_environment(tree: ast.AST) -> bool:
        """True if the AST contains a genuine os.environ / os.getenv access."""
        for node in ast.walk(tree):
            # os.environ  /  os.environ[...]  /  os.environ.get(...)
            if (
                isinstance(node, ast.Attribute)
                and node.attr in {"environ", "getenv"}
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
            ):
                return True
            # a bare ``getenv(...)`` call (from-import form)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getenv"
            ):
                return True
        return False

    engine_rel = str(ENGINE_FILE.relative_to(REPO_ROOT))
    offenders: list[str] = []
    engine_is_read_site = False
    for py in PKG_SRC.rglob("*.py"):
        rel = str(py.relative_to(REPO_ROOT))
        # The ``_wasm/`` directory holds BUILD-TIME VENDORED package data (the
        # reproducible ``.wasm`` binary and a byte-identical copy of the
        # canonical OSS wasm loader ``packages/cel-wasm/python/relay_cel_wasm.py``
        # shipped so a wheel-only install can LOAD the wasm). It is NOT
        # first-party ``relay_contracts`` source: it is a verbatim, drift-guarded
        # copy of code that lives outside ``src/``. The loader reads ``CEL_WASM``
        # (its OWN dev-default wasm-path resolution), NEVER ``RELAY_CEL_ENGINE``,
        # so it is not an engine-selection site; the engine-selection determinism
        # invariant this guard protects (RELAY_CEL_ENGINE leaking out of
        # engine.py) is unaffected. Excluding the vendored copy keeps the guard
        # scoped to first-party host source, the same way the ascii-source lint
        # excludes vendored / generated trees.
        if "/_wasm/" in rel.replace("\\", "/") + "/":
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        reads_env = _reads_environment(tree)
        if rel == engine_rel:
            engine_is_read_site = reads_env
            continue
        if reads_env:
            offenders.append(rel)

    assert offenders == [], (
        "engine selection (os.environ/os.getenv) must be performed ONLY in "
        f"engine.py (packages/contracts src); env access found in: {offenders}"
    )
    assert engine_is_read_site, (
        "engine.py must remain the RELAY_CEL_ENGINE read site (it must read "
        "the env via os.environ/os.getenv)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P1HOST-009")
def test_engine_module_exposes_make_cel_evaluator() -> None:
    """The module exists and exports ``make_cel_evaluator``."""
    assert ENGINE_FILE.is_file(), f"engine.py missing at {ENGINE_FILE}"
    import relay_contracts.engine as engine_mod

    assert hasattr(engine_mod, "make_cel_evaluator")
    assert "make_cel_evaluator" in engine_mod.__all__
