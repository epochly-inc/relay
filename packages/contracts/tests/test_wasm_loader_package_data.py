"""WS-G packaging (loader): the wasm LOADER module shipped as relay_contracts package data.


Completes the fresh-wheel-install story for VAL-CWC-P3CORPUS-008 ("a fresh
installed wheel can locate AND load the wasm"). The prior WS-G feature vendored
``relay_cel_wasm.wasm`` as ``relay_contracts`` package data (resolvable via
``importlib.resources``) -- but NOT the wasm LOADER python module
(``packages/cel-wasm/python/relay_cel_wasm.py``, a loose module with no
pyproject, not a published package). So in a wheel-only install
``WasmCelEvaluator._load_relay_cel_class()`` -- which tries ``import
relay_cel_wasm`` then falls back to the in-repo
``packages/cel-wasm/python/relay_cel_wasm.py`` source path -- FAILS: the loose
module is not on ``sys.path`` and the in-repo path is absent. Result: a fresh
``pip install relay-contracts`` resolves the ``.wasm`` but cannot CONSTRUCT the
wasm engine.

This module vendors the canonical loader source as a git-tracked package-data
copy at ``packages/contracts/src/relay_contracts/_wasm/relay_cel_wasm.py`` and
force-includes it into the wheel (hatch
``[tool.hatch.build.targets.wheel.force-include]``, the SAME mechanism + the
SAME vendored-copy pattern the ``.wasm`` uses -- the ``.wasm`` is a git-tracked
copy in ``src/_wasm/`` with a sha-pin drift guard, so the loader matches that
pattern for consistency). Because the loader copy is a git-tracked DUPLICATE of
the canonical ``packages/cel-wasm/python/relay_cel_wasm.py``, a BYTE-IDENTITY
drift guard (``test_wasm_loader_vendored_copy_is_byte_identical_to_canonical``)
fails CI if the two diverge -- no silent drift.
``WasmCelEvaluator._load_relay_cel_class()`` gains a package-data FALLBACK
(after the in-repo dev path) that loads the loader via
``importlib.resources.files('relay_contracts').joinpath('_wasm/relay_cel_wasm.py')``
with ``spec_from_file_location``.

Assertions (all tier-1 plumbing, offline, deterministic, no build, no network):

  - the loader source is resolvable via ``importlib.resources`` on
    ``relay_contracts`` (the wheel-only resolution path);
  - the package-data resolver returns a concrete on-disk path whose bytes parse
    as the loader (``RelayCel`` class present);
  - a wheel-only-simulated ``WasmCelEvaluator`` (in-repo loader path forced
    absent + top-level ``relay_cel_wasm`` not importable) STILL constructs and
    evaluates through the wasm engine using ONLY package data (loader + .wasm);
  - a wheel-only env with the LOADER package data absent raises a structured
    ``RelayCel*Error`` (engine family RELAY-CEL-009), NOT a bare ImportError /
    ModuleNotFoundError;
  - the celpy default path is UNAFFECTED by a missing loader package data.

The ``-k`` selectors the contract evidence commands use:
    wasm_loader_package_data | importlib_resource   -> 008 (loader half)
    wasm_loader_missing_structured_error            -> 010 (loader half)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""
from __future__ import annotations

import builtins
import hashlib
import importlib
import importlib.resources
import importlib.util
from typing import Any

import pytest

pytestmark = pytest.mark.plumbing

# The loader's package-data path relative to the imported ``relay_contracts``
# package root, mirroring ``WASM_PACKAGE_DATA_RELPATH`` for the .wasm.
_LOADER_RELPATH = "_wasm/relay_cel_wasm.py"


# --- VAL-CWC-P3CORPUS-008 (loader half): importlib.resources resolution ------


def test_wasm_loader_package_data_resolvable_via_importlib_resource() -> None:
    """The vendored loader module is locatable via importlib.resources.

    Mirrors a fresh-installed-wheel resolution: the loader source is resolved
    from the IMPORTED package root (``importlib.resources.files('relay_contracts')``),
    NOT from an in-repo ``packages/cel-wasm/python`` relative path. The resource
    must exist as a file in the wheel-only world.
    """
    from relay_contracts.wasm_artifact import WASM_LOADER_PACKAGE_DATA_RELPATH

    assert WASM_LOADER_PACKAGE_DATA_RELPATH == _LOADER_RELPATH
    resource = importlib.resources.files("relay_contracts").joinpath(
        WASM_LOADER_PACKAGE_DATA_RELPATH
    )
    assert resource.is_file(), (
        f"packaged wasm LOADER not resolvable via importlib.resources at "
        f"{WASM_LOADER_PACKAGE_DATA_RELPATH!r}"
    )


def test_wasm_loader_package_data_resolver_returns_loader_with_relaycel() -> None:
    """The resolver returns a concrete path whose bytes parse as the loader.

    Loading the package-data path via ``spec_from_file_location`` yields a module
    exposing the ``RelayCel`` class -- the same class the in-repo path exposes.
    """
    from relay_contracts.wasm_artifact import resolve_packaged_wasm_loader_path

    path = resolve_packaged_wasm_loader_path()
    assert path is not None
    spec = importlib.util.spec_from_file_location(
        "relay_cel_wasm__pkgdata_test", str(path)
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert hasattr(module, "RelayCel")


def test_wasm_loader_package_data_constructs_engine_wheel_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wheel-only-simulated WasmCelEvaluator constructs + evaluates.

    Simulate a wheel-only install: (1) the in-repo loader path is forced ABSENT
    (so ``_load_relay_cel_from_repo`` cannot resolve it), and (2) the loose
    top-level ``relay_cel_wasm`` module is NOT importable. The evaluator must
    STILL construct and evaluate through the wasm engine -- resolving BOTH the
    loader AND the .wasm from ``relay_contracts`` package data, with NO
    ``packages/cel-wasm/python`` path on disk and NO crate/target dependency.
    """
    import relay_contracts.wasm_backed_evaluator as wbe

    _force_wheel_only(monkeypatch, wbe)

    ev = wbe.WasmCelEvaluator(timeout_ms=250)
    result = ev.evaluate("1 + 2")
    # Native decode target (M6 type layer): an exact Python int.
    assert type(result) is int
    assert result == 3


def test_wasm_loader_package_data_used_when_repo_path_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_load_relay_cel_class`` returns the package-data loader's RelayCel.

    With the in-repo loader path forced absent and the top-level module not
    importable, ``_load_relay_cel_class()`` must NOT raise -- it falls back to
    the package-data loader and returns a usable ``RelayCel`` class.
    """
    import relay_contracts.wasm_backed_evaluator as wbe

    _force_wheel_only(monkeypatch, wbe)

    cls = wbe._load_relay_cel_class()
    assert cls.__name__ == "RelayCel"


def test_wasm_loader_falls_through_when_in_repo_source_genuinely_absent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: object,
) -> None:
    """The REAL in-repo loader path being absent falls through to package data.

    Regression guard for the wheel-only behavior. In a wheel-only install the
    in-repo ``packages/cel-wasm/python/relay_cel_wasm.py`` does NOT exist, so
    ``_load_relay_cel_from_repo`` must surface a STRUCTURED engine error (not a
    bare ``FileNotFoundError`` from ``spec.loader.exec_module`` on a nonexistent
    file) so ``_load_relay_cel_class`` falls through to the package-data loader.

    Unlike ``_force_wheel_only`` (which monkeypatches ``_load_relay_cel_from_repo``
    to raise directly), this drives the GENUINE ``_load_relay_cel_from_repo``
    code path: it repoints the module's ``__file__``-derived ``repo_root`` at an
    EMPTY temp tree containing NO ``packages/cel-wasm/python/relay_cel_wasm.py``.
    The computed in-repo ``loader_path`` is then a real-but-nonexistent file --
    so WITHOUT the existence guard, ``exec_module`` raises a bare
    ``FileNotFoundError`` (the test BITES), and WITH the guard the structured
    ``RelayCelError`` lets ``_load_relay_cel_class`` fall through to the
    package-data loader (the test PASSES).
    """
    import os
    import sys

    import relay_contracts.wasm_backed_evaluator as wbe

    # Block the loose top-level module import (not on sys.path in wheel-only).
    real_import = builtins.__import__

    def _blocked_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "relay_cel_wasm":
            raise ModuleNotFoundError("No module named 'relay_cel_wasm'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    monkeypatch.delitem(sys.modules, "relay_cel_wasm", raising=False)

    # Repoint the __file__-derived repo_root at an EMPTY tree. _load_relay_cel_
    # from_repo computes repo_root via os.path.abspath(__file__) then four
    # os.path.normpath(join(..)) parents up; patch os.path.abspath so the module
    # __file__ resolves into <tmp>/a/b/c/d (four levels deep) whose grandparent
    # tree has no packages/cel-wasm/python/relay_cel_wasm.py. Every OTHER
    # abspath call is delegated unchanged.
    real_abspath = os.path.abspath
    fake_file = os.path.join(str(tmp_path), "a", "b", "c", "d", "wbe.py")
    os.makedirs(os.path.dirname(fake_file), exist_ok=True)
    module_file = wbe.__file__

    def _abspath(path: Any) -> str:
        if path == module_file:
            return fake_file
        return real_abspath(path)

    monkeypatch.setattr(wbe.os.path, "abspath", _abspath)

    cls = wbe._load_relay_cel_class()
    assert cls.__name__ == "RelayCel"


# --- drift guard: vendored loader copy is byte-identical to the canonical source -


def test_wasm_loader_vendored_copy_is_byte_identical_to_canonical() -> None:
    """The vendored package-data loader byte-equals the canonical loader source.

    Approach B (vendor a git-tracked copy) ships
    ``src/relay_contracts/_wasm/relay_cel_wasm.py`` as a DUPLICATE of the
    canonical ``packages/cel-wasm/python/relay_cel_wasm.py``. This guard fails
    CI the moment the two diverge, so there is NO silent drift between the
    shipped loader and its single canonical source.
    """
    import os

    from relay_contracts.wasm_artifact import resolve_packaged_wasm_loader_path

    vendored = resolve_packaged_wasm_loader_path()
    assert vendored is not None

    # tests/ -> packages/contracts/tests; repo root is three parents up.
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, "..", "..", ".."))
    canonical = os.path.join(
        repo_root, "packages", "cel-wasm", "python", "relay_cel_wasm.py"
    )
    assert os.path.isfile(canonical), (
        f"canonical loader source not found at {canonical!r}"
    )

    vendored_bytes = vendored.read_bytes()
    with open(canonical, "rb") as handle:
        canonical_bytes = handle.read()
    assert hashlib.sha256(vendored_bytes).hexdigest() == hashlib.sha256(
        canonical_bytes
    ).hexdigest(), (
        "vendored relay_contracts/_wasm/relay_cel_wasm.py has drifted from the "
        "canonical packages/cel-wasm/python/relay_cel_wasm.py -- re-vendor the "
        "copy (cp the canonical source) so they are byte-identical"
    )


# --- VAL-CWC-P3CORPUS-010 (loader half): missing loader -> structured error ---


def test_wasm_loader_missing_structured_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An absent LOADER package data raises a structured RelayCel*Error.

    When BOTH the top-level ``relay_cel_wasm`` import AND the in-repo loader path
    AND the package-data loader are unresolvable, ``_load_relay_cel_class`` must
    surface a ``RelayCelError``-family error carrying a stable RELAY-CEL- code
    (the WS-A engine-error code), NOT a bare ImportError / ModuleNotFoundError /
    generic exception.
    """
    import relay_contracts.wasm_backed_evaluator as wbe
    from relay_contracts.errors import RelayCelError

    _force_wheel_only(monkeypatch, wbe)
    # Now also make the package-data loader unresolvable.
    monkeypatch.setattr(
        wbe, "resolve_packaged_wasm_loader_path", lambda: None, raising=True
    )

    with pytest.raises(RelayCelError) as excinfo:
        wbe._load_relay_cel_class()
    err = excinfo.value
    assert not isinstance(err, ImportError | ModuleNotFoundError | FileNotFoundError)
    assert isinstance(err.code, str) and err.code.startswith("RELAY-CEL-"), (
        f"missing-loader error must carry a RELAY-CEL- code; got {err.code!r}"
    )


def test_wasm_loader_missing_no_legacy_fallback_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M6 WS-I port of the legacy-engine-unaffected case: there is NO legacy
    engine to fall back to when the loader package data is absent. An explicit
    legacy-engine selection fails closed at the factory with the structured
    unknown-engine ValueError, so a missing loader can never be papered over
    by silently routing to a removed engine -- the structured RELAY-CEL-009
    load error (asserted above) IS the contract.
    """
    import relay_contracts.wasm_backed_evaluator as wbe
    from relay_contracts.engine import make_cel_evaluator

    _force_wheel_only(monkeypatch, wbe)
    monkeypatch.setattr(
        wbe, "resolve_packaged_wasm_loader_path", lambda: None, raising=True
    )

    monkeypatch.setenv("RELAY_CEL_ENGINE", "celpy")
    with pytest.raises(ValueError) as excinfo:
        make_cel_evaluator(udfs=())
    msg = str(excinfo.value)
    assert "wasm" in msg and "RELAY_CEL_ENGINE" in msg


# --- helpers -----------------------------------------------------------------


def _force_wheel_only(
    monkeypatch: pytest.MonkeyPatch, wbe: object
) -> None:
    """Simulate a wheel-only install: no in-repo loader path, no loose module.

    (1) ``_load_relay_cel_from_repo`` is patched to raise a structured engine
        error (the in-repo ``packages/cel-wasm/python/relay_cel_wasm.py`` is
        absent in a wheel-only tree).
    (2) ``import relay_cel_wasm`` raises ModuleNotFoundError (the loose loader
        module is not a published package and is not on sys.path).

    Both the .wasm AND (after the implementation lands) the loader still resolve
    from ``relay_contracts`` package data, so the evaluator must still work.

    Implementation note: this helper patches importlib.import_module (via the
    wbe module's importlib reference) in addition to builtins.__import__.
    On Python 3.4+ importlib.import_module is implemented in C (_bootstrap) and
    does NOT route through builtins.__import__ when the module is absent from
    sys.modules -- it drives sys.meta_path finders directly.  If another test
    has added packages/cel-wasm/python to sys.path (e.g. by exec-loading the
    corpus generator), builtins.__import__ patching is ineffective because the
    module is still findable via sys.path.  Patching importlib.import_module
    closes the gap; monkeypatch restores the real function after the test.
    """
    import sys

    from relay_contracts.errors import RelayCelEngineError

    def _no_repo_loader() -> object:
        raise RelayCelEngineError(
            "wasm CEL loader not resolvable in repo (wheel-only simulation)",
            subtype="RELAY-CEL-ENGINE-REQUEST",
        )

    monkeypatch.setattr(
        wbe, "_load_relay_cel_from_repo", _no_repo_loader, raising=True
    )

    real_import = builtins.__import__

    def _blocked_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "relay_cel_wasm":
            raise ModuleNotFoundError("No module named 'relay_cel_wasm'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    # On Python 3.4+ importlib.import_module routes through _bootstrap._gcd_import,
    # NOT builtins.__import__, so the patch above is insufficient when
    # relay_cel_wasm is findable on sys.path (e.g. packages/cel-wasm/python was
    # inserted by the corpus-generator loader in an earlier test).  Patch
    # importlib.import_module on the wbe module's importlib reference directly
    # so this function is blocked regardless of sys.path state.
    real_import_module = importlib.import_module

    def _blocked_import_module(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "relay_cel_wasm":
            raise ModuleNotFoundError("No module named 'relay_cel_wasm'")
        return real_import_module(name, *args, **kwargs)

    import types

    monkeypatch.setattr(
        wbe,  # type: ignore[arg-type]
        "importlib",
        types.SimpleNamespace(
            import_module=_blocked_import_module,
            util=importlib.util,
        ),
    )

    # importlib.import_module consults sys.modules first; drop any cached entry.
    monkeypatch.delitem(sys.modules, "relay_cel_wasm", raising=False)
