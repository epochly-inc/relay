"""M4 P4DUALRUN guard tests: default-stays-celpy + RELAY_CEL_ENGINE read site.

These are TEST-ONLY guards. They change no production source: they LOCK two
load-bearing invariants so a future edit cannot silently backslide them.

Covers:
  - VAL-CWC-P4DUALRUN-007: the default CEL engine STAYS celpy through M4. With
    ``RELAY_CEL_ENGINE`` unset (and with it set-but-blank) the
    ``packages/contracts`` factory (``make_cel_evaluator`` / the engine-name
    resolver in ``engine.py``) selects the celpy-backed ``RelayCelEvaluator``,
    NOT the ``WasmCelEvaluator``. The flip to wasm is explicitly deferred to M5
    (WS-H); a wasm default here would fail the assertion.
  - VAL-CWC-P4DUALRUN-008: engine selection (the ``RELAY_CEL_ENGINE`` READ)
    appears ONLY in the contracts factory (``engine.py``) and is ABSENT from
    ``packages/gate`` src. A gate-src read would trip the VAL-W8-005 /
    VAL-CWC-P4DUALRUN-008 gate-determinism grep (a gate decision must not
    depend on ambient process environment).

The default-engine assertions (VAL-007) read the default through the factory
with the env explicitly cleared, exactly as the contract Evidence requires
(``the test MUST clear RELAY_CEL_ENGINE from the environment``).

The determinism guard (VAL-008) encodes the contract's grep semantics:
  - ``grep -rn 'RELAY_CEL_ENGINE' packages/gate/src`` returns NO matches
    (exit 1) -- gate src never names the engine var at all.
  - the only file under ``packages/contracts/src`` that actually READS the env
    var (``os.environ`` / ``os.getenv`` / ``getenv``) is ``engine.py``. Other
    contracts-src files (``pipeline.py``, ``wasm_backed_evaluator.py``) name the
    token ONLY in docstring / comment prose that explicitly states the var is
    NOT read there -- a deliberate negative reference, not a read. A bare
    substring grep is fooled by that prose, so the read-site half of the guard
    asserts on the env-READ pattern, which never matches a string literal or
    comment, and confirms ``engine.py`` is the sole read site.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
GATE_SRC = REPO_ROOT / "packages" / "gate" / "src"
CONTRACTS_SRC = REPO_ROOT / "packages" / "contracts" / "src"
ENGINE_FILE = (
    CONTRACTS_SRC / "relay_contracts" / "engine.py"
)

_ENGINE_VAR = "RELAY_CEL_ENGINE"

# An env-READ of the engine var: ``os.environ``/``os.getenv``/``getenv`` on a
# line (or contiguous statement) that names the var. This pattern never matches
# a docstring/comment that merely mentions the token, so it isolates the REAL
# selection read from deliberate negative-reference prose.
_ENV_READ_TOKENS = ("os.environ", "os.getenv", "getenv(")


def _ast_reads_environment(tree: ast.AST) -> bool:
    """True if the AST contains a GENUINE ``os.environ`` / ``os.getenv`` /
    bare ``getenv(...)`` access node.

    Walks the parsed AST for a real environment-access node (an
    ``ast.Attribute`` ``os.environ`` / ``os.getenv``, or a bare ``getenv(...)``
    call). It never matches a string literal or comment, so prose like
    ``"This module never touches os.environ"`` in a docstring is correctly NOT
    treated as a read. Mirrors the proven detector in
    ``test_engine_factory.test_relay_cel_engine_read_only_in_engine_module``.
    """
    for node in ast.walk(tree):
        # os.environ  /  os.environ[...]  /  os.environ.get(...)  /  os.getenv(...)
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


# ---------------------------------------------------------------------------
# VAL-CWC-P4DUALRUN-007: default engine stays celpy through M4 (env unset/blank)
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-007")
def test_default_engine_is_celpy_when_env_unset_through_m4(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Contract Evidence: with ``RELAY_CEL_ENGINE`` CLEARED from the env, the
    contracts factory resolves to the celpy-backed evaluator (NOT wasm).

    Asserts BOTH the engine-name resolution (``_select_engine_name`` -> celpy)
    AND the concrete returned type (``RelayCelEvaluator``), so the default is
    pinned at the resolver level and at the constructed-instance level. The
    flip to wasm is M5 (WS-H); a wasm default would fail here.
    """
    # The contract explicitly requires the test clear RELAY_CEL_ENGINE.
    monkeypatch.delenv(_ENGINE_VAR, raising=False)

    from relay_contracts.engine import _select_engine_name, make_cel_evaluator
    from relay_contracts.evaluator import RelayCelEvaluator
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    # Engine-name resolution: unset -> "celpy", never "wasm".
    assert _select_engine_name() == "celpy", (
        "default-stays-celpy invariant broken: with RELAY_CEL_ENGINE unset the "
        "factory resolver must return 'celpy' through M4 (the flip to wasm is "
        f"M5/WS-H); got {_select_engine_name()!r}"
    )

    # Concrete type: the celpy evaluator, NOT the wasm evaluator.
    ev = make_cel_evaluator(udfs=())
    assert isinstance(ev, RelayCelEvaluator), (
        "unset RELAY_CEL_ENGINE must construct the celpy RelayCelEvaluator; "
        f"got {type(ev).__name__}"
    )
    assert not isinstance(ev, WasmCelEvaluator), (
        "unset RELAY_CEL_ENGINE must NOT construct the WasmCelEvaluator at M4 "
        f"(default flip is deferred to M5); got {type(ev).__name__}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-007")
def test_default_engine_is_celpy_when_env_blank_through_m4(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A set-but-BLANK ``RELAY_CEL_ENGINE=""`` is the standard 'no selection'
    signal and MUST resolve to the safe default (celpy), same as unset -- so the
    default-stays-celpy invariant cannot be bypassed with an empty export."""
    monkeypatch.setenv(_ENGINE_VAR, "")

    from relay_contracts.engine import _select_engine_name, make_cel_evaluator
    from relay_contracts.evaluator import RelayCelEvaluator
    from relay_contracts.wasm_backed_evaluator import WasmCelEvaluator

    assert _select_engine_name() == "celpy", (
        "blank RELAY_CEL_ENGINE='' must resolve to the celpy default through "
        f"M4; got {_select_engine_name()!r}"
    )
    ev = make_cel_evaluator(udfs=())
    assert isinstance(ev, RelayCelEvaluator)
    assert not isinstance(ev, WasmCelEvaluator)


# ---------------------------------------------------------------------------
# VAL-CWC-P4DUALRUN-008: RELAY_CEL_ENGINE read ONLY in the contracts factory
# ---------------------------------------------------------------------------
def _grep_rn(pattern: str, path: Path) -> subprocess.CompletedProcess[str]:
    """Run ``grep -rn <pattern> <path>`` exactly like the contract Evidence.

    grep exit codes: 0 = at least one match, 1 = no matches, >=2 = error.
    """
    return subprocess.run(
        ["grep", "-rn", pattern, str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_relay_cel_engine_absent_from_gate_src() -> None:
    """Contract Evidence: ``grep -rn 'RELAY_CEL_ENGINE' packages/gate/src`` has
    NO matches (exit 1). The gate decision must not depend on ambient process
    environment; a gate-src read would trip the VAL-W8-005 determinism grep."""
    assert GATE_SRC.is_dir(), f"gate src tree missing at {GATE_SRC}"

    res = _grep_rn(_ENGINE_VAR, GATE_SRC)
    offenders = res.stdout.strip()
    assert res.returncode == 1 and offenders == "", (
        "VAL-W8-005 / VAL-CWC-P4DUALRUN-008 gate-determinism grep broken: "
        f"'{_ENGINE_VAR}' must NEVER appear under packages/gate/src "
        "(engine selection must stay in the contracts factory). Offending "
        f"matches (grep exit {res.returncode}):\n{offenders or '(none)'}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_relay_cel_engine_read_site_is_only_engine_py() -> None:
    """The ONLY file under ``packages/contracts/src`` that READS the engine var
    is the factory ``engine.py``.

    Encodes the contract's complementary grep semantics precisely. A bare
    ``grep -rn 'RELAY_CEL_ENGINE' packages/contracts/src`` also matches
    docstring / comment prose in ``pipeline.py`` and ``wasm_backed_evaluator.py``
    that explicitly states the var is NOT read there (deliberate negative
    references). The invariant the contract protects is the READ site, not the
    appearance of the token, so this guard asserts on the env-READ pattern
    (``os.environ`` / ``os.getenv`` / ``getenv``) on a line that also names the
    var -- which never matches a string literal or comment -- and confirms
    exactly ONE such file: ``engine.py``.
    """
    assert CONTRACTS_SRC.is_dir(), f"contracts src tree missing at {CONTRACTS_SRC}"
    assert ENGINE_FILE.is_file(), f"factory engine.py missing at {ENGINE_FILE}"

    # First: the bare-substring grep must exit 0 (the token DOES appear -- in
    # engine.py as the real read, plus negative-reference prose elsewhere), so
    # the complementary Evidence command's exit code is honored.
    bare = _grep_rn(_ENGINE_VAR, CONTRACTS_SRC)
    assert bare.returncode == 0, (
        f"'{_ENGINE_VAR}' must appear under packages/contracts/src (at least in "
        f"the engine.py read site); got grep exit {bare.returncode}"
    )

    # Now isolate the REAL read sites: lines that both name the engine var (or
    # the _ENGINE_ENV_VAR constant that holds it) AND perform an env read.
    read_site_files: set[str] = set()
    for py in sorted(CONTRACTS_SRC.rglob("*.py")):
        rel = str(py.relative_to(REPO_ROOT)).replace("\\", "/")
        text = py.read_text(encoding="utf-8")
        for line in text.splitlines():
            if not any(tok in line for tok in _ENV_READ_TOKENS):
                continue
            # An env read that selects the engine: the read line names the var
            # or the constant holding it. (engine.py reads via the
            # ``_ENGINE_ENV_VAR`` constant -> os.environ.get(_ENGINE_ENV_VAR).)
            if _ENGINE_VAR in line or "_ENGINE_ENV_VAR" in line:
                read_site_files.add(rel)
                break

    engine_rel = str(ENGINE_FILE.relative_to(REPO_ROOT)).replace("\\", "/")
    assert read_site_files == {engine_rel}, (
        "engine selection (the RELAY_CEL_ENGINE env READ) must be performed in "
        f"EXACTLY one contracts-src file ({engine_rel}); found read sites: "
        f"{sorted(read_site_files)}. A new env read of RELAY_CEL_ENGINE outside "
        "engine.py would break the single-read-site determinism invariant "
        "(VAL-CWC-P4DUALRUN-008)."
    )

    # AST guard: catch a real env read split across lines that the line-level
    # check would miss (var named on one statement, ``os.environ.get`` on
    # another). A SUBSTRING scan cannot do this safely -- prose like
    # wasm_backed_evaluator.py's docstring "This module never touches
    # ``os.environ``" (one line below a ``RELAY_CEL_ENGINE`` mention) is text,
    # not a read, and would false-positive. So this walks the AST for a GENUINE
    # environment-access node (os.environ / os.getenv / getenv as attribute or
    # call -- never a string literal or comment) and only flags a contracts-src
    # file (other than engine.py) that BOTH performs such a read AND names the
    # engine var. engine.py is the sanctioned read site; every other file must
    # contain NO genuine env-access node when it names the engine var.
    for py in sorted(CONTRACTS_SRC.rglob("*.py")):
        rel = str(py.relative_to(REPO_ROOT)).replace("\\", "/")
        if rel == engine_rel:
            continue
        text = py.read_text(encoding="utf-8")
        if _ENGINE_VAR not in text:
            continue
        if _ast_reads_environment(ast.parse(text, filename=str(py))):
            raise AssertionError(
                f"{rel} names '{_ENGINE_VAR}' AND performs a genuine env read "
                f"(os.environ / os.getenv / getenv); engine selection must live "
                f"ONLY in {engine_rel}. A real RELAY_CEL_ENGINE read outside the "
                "factory breaks the single-read-site determinism invariant "
                "(VAL-CWC-P4DUALRUN-008)."
            )
