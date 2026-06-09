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
    var is ``engine.py``. Other contracts-src files (``pipeline.py``,
    ``wasm_backed_evaluator.py``) name the token ONLY in docstring / comment
    prose that explicitly states the var is NOT read there -- a deliberate
    negative reference, not a read. A bare substring grep is fooled by that
    prose.

Read-site detection -- the TWO covered forms (threat model):
  EVERY naturally-written environment read of the engine var names the engine
  key in ONE of two forms, and this guard flags BOTH:

  (a) The ENV-KEY STRING LITERAL form. A read that spells the key inline names
      the string ``"RELAY_CEL_ENGINE"`` somewhere --
      ``os.environ.get("RELAY_CEL_ENGINE")``, ``os.getenv("RELAY_CEL_ENGINE")``,
      ``os.environ["RELAY_CEL_ENGINE"]``, or the from-import form
      ``from os import environ; environ.get("RELAY_CEL_ENGINE")`` /
      ``from os import getenv; getenv("RELAY_CEL_ENGINE")``. The guard scans the
      parsed AST for a string-literal node (``ast.Constant`` with a ``str``
      value, INCLUDING the constant definition
      ``_ENGINE_ENV_VAR = "RELAY_CEL_ENGINE"``) whose value is EXACTLY
      ``RELAY_CEL_ENGINE`` and that is NOT a docstring (comments are not AST
      nodes, so they can never match).

  (b) The SANCTIONED-CONSTANT form. A read that does NOT spell the literal but
      instead names the engine var via the factory's sanctioned constant
      ``_ENGINE_ENV_VAR`` --
      ``from relay_contracts.engine import _ENGINE_ENV_VAR; os.environ.get(
      _ENGINE_ENV_VAR)`` (the EXACT roborev MED evasion). This file contains NO
      ``RELAY_CEL_ENGINE`` literal at all, so the form-(a) literal scan alone
      would skip it. The guard therefore ALSO flags any module (other than the
      factory ``engine.py`` itself) that references the sanctioned constant via
      EITHER (i) an ``ast.Name(id="_ENGINE_ENV_VAR")`` usage, OR (ii) a
      ``from ... import _ENGINE_ENV_VAR`` ``ast.ImportFrom`` name (including the
      aliased form ``import _ENGINE_ENV_VAR as X`` -- the import name is matched,
      so the aliased read site is caught at the import).

  Covering both (a) the literal and (b) the sanctioned-constant reference is the
  convergent fix for the roborev MED finding: the prior os-API-FORM detector
  (which matched only ``os.environ`` / ``os.getenv`` attribute access on the
  ``os`` name) was UNSOUND because ``from os import environ; environ.get(...)``
  named no ``os.<attr>`` node, and the literal-only successor was STILL evadable
  because importing ``_ENGINE_ENV_VAR`` reads the same env var WITHOUT spelling
  the literal. Scanning for both the unavoidable key literal AND the sanctioned
  constant that aliases it closes the loop -- mirroring the round-6 lesson and
  the TypeScript env-guard.

  Soundness vs. prose (no false positive):
    - ``#`` comments are NEVER AST nodes, so they can never match either form.
    - Form (a) EXCLUDES docstrings (the bare-string ``Expr`` first statement of
      a module / class / function body), so a docstring that merely names the
      literal as prose does not trip it.
    - Form (b) matches an ``ast.Name``/``ast.ImportFrom`` for ``_ENGINE_ENV_VAR``
      -- a docstring or comment that mentions the token ``_ENGINE_ENV_VAR`` as
      prose produces a string literal / no AST node, NEVER a ``Name`` or import,
      so prose does not trip it either.
  ``pipeline.py`` mentions ``RELAY_CEL_ENGINE`` only in ``#`` comments and
  ``wasm_backed_evaluator.py`` only in docstrings, and neither references
  ``_ENGINE_ENV_VAR`` as a Name/import, so neither trips the guard.

  Explicit, documented NON-GOAL: adversarial string-splitting
  (``"RELAY_" + "CEL_ENGINE"``, ``"".join(...)``, byte/char construction) is
  out of scope and is NOT detected -- identical posture to the TS env-guard. A
  developer who deliberately obfuscates the key to hide an env read is outside
  this guard's threat model.

Probe isolation (roborev LOW fix): the read-site scanner is a PURE function over
IN-MEMORY source (:func:`scan_source` takes ``(filename, source_text)`` and
returns a bool). The real-tree guard scans the actual contracts-src ``*.py``
files READ-ONLY (no writes anywhere). The non-vacuity probes feed in-memory
source STRINGS to the SAME pure scanner -- they NEVER write throwaway modules
into ``packages/contracts/src``. So the guard cannot observe a probe artifact
under parallel pytest, and the test never requires a writable source tree.

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
ENGINE_FILE = CONTRACTS_SRC / "relay_contracts" / "engine.py"

# The engine-selection env var (form (a): the inline string literal) and the
# factory's sanctioned constant that aliases it (form (b)).
_ENGINE_VAR = "RELAY_CEL_ENGINE"
_ENGINE_CONST = "_ENGINE_ENV_VAR"


def _module_docstring_node_ids(tree: ast.AST) -> set[int]:
    """Collect the ``id()`` of every bare-string ``ast.Constant`` that is a
    docstring -- the first statement of a module / class / function body.

    A docstring is the only place a string literal equal to the engine var can
    appear WITHOUT being a read (deliberate negative-reference prose, e.g.
    ``wasm_backed_evaluator.py``'s module docstring). Excluding these node ids
    from the form-(a) key-literal scan prevents a false positive on prose while
    keeping the scan sound against every real literal read (which names the key
    as a Call argument, Subscript index, or the engine-var constant definition
    -- never as a docstring).
    """
    docstring_ids: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body:
            first = body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                docstring_ids.add(id(first.value))
    return docstring_ids


def _names_engine_key_literal(tree: ast.AST) -> bool:
    """Form (a): True if the AST contains a STRING-LITERAL node whose value is
    EXACTLY ``RELAY_CEL_ENGINE`` and is NOT a docstring.

    EVERY read written with the key spelled inline names this literal --
    ``os.environ.get("RELAY_CEL_ENGINE")``, ``os.getenv("RELAY_CEL_ENGINE")``,
    ``os.environ["RELAY_CEL_ENGINE"]``, the from-import form
    ``from os import environ; environ.get("RELAY_CEL_ENGINE")``, or the engine
    factory's constant definition ``_ENGINE_ENV_VAR = "RELAY_CEL_ENGINE"``. The
    literal is the one UNAVOIDABLE token shared by all of them, so scanning for
    it catches the read regardless of which ``os`` import form is used.

    Soundness vs. prose: ``#`` comments are NOT AST nodes; docstrings are
    EXCLUDED via :func:`_module_docstring_node_ids`. A genuine key literal lands
    in a Call argument, a Subscript index, or an assignment value -- none of
    which are docstrings.
    """
    docstring_ids = _module_docstring_node_ids(tree)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value == _ENGINE_VAR
            and id(node) not in docstring_ids
        ):
            return True
    return False


def _references_engine_constant(tree: ast.AST) -> bool:
    """Form (b): True if the AST references the sanctioned constant
    ``_ENGINE_ENV_VAR`` via EITHER an ``ast.Name`` usage OR an ``ast.ImportFrom``
    that imports the name.

    This catches the read that does NOT spell the ``RELAY_CEL_ENGINE`` literal
    but instead reads the env var through the factory's sanctioned constant --
    ``from relay_contracts.engine import _ENGINE_ENV_VAR; os.environ.get(
    _ENGINE_ENV_VAR)`` (the roborev MED evasion). Two structural signals, either
    suffices:

      (i)  an ``ast.Name(id="_ENGINE_ENV_VAR")`` -- the constant USED as a value
           (e.g. as the Call argument / Subscript index of the env read, or in
           an f-string), and also its assignment target / Load in ``engine.py``.
      (ii) an ``ast.ImportFrom`` whose ``names`` include an alias with
           ``name == "_ENGINE_ENV_VAR"`` -- ``from relay_contracts.engine import
           _ENGINE_ENV_VAR`` AND the aliased form
           ``import _ENGINE_ENV_VAR as X`` (the import NAME is matched, not the
           local binding, so an aliased read site is caught at the import even
           when the later usage is the alias ``X``, not ``_ENGINE_ENV_VAR``).

    Soundness vs. prose: a docstring or ``#`` comment that mentions the token
    ``_ENGINE_ENV_VAR`` produces a string-literal / no AST node -- NEVER an
    ``ast.Name`` or ``ast.ImportFrom`` -- so prose does not trip this form.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == _ENGINE_CONST:
            return True
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == _ENGINE_CONST:
                    return True
    return False


def scan_source(filename: str, source_text: str) -> bool:
    """PURE read-site detector over in-memory source.

    Return True if ``source_text`` (parsed as a Python module named ``filename``)
    is an engine-var READ site -- i.e. it names the engine-selection key in
    EITHER covered form:

      (a) the ``RELAY_CEL_ENGINE`` string literal in a non-docstring position
          (:func:`_names_engine_key_literal`), OR
      (b) a reference to the sanctioned constant ``_ENGINE_ENV_VAR`` via an
          ``ast.Name`` usage or a ``from ... import _ENGINE_ENV_VAR`` import
          (:func:`_references_engine_constant`).

    This function performs NO filesystem access: it neither reads ``filename``
    from disk nor writes anything. ``filename`` is used only as the AST
    ``filename`` for clearer SyntaxError messages. The real-tree guard supplies
    on-disk source READ-ONLY; the non-vacuity probes supply in-memory strings.
    Keeping the scanner pure means a probe can never mutate the checkout and the
    guard can never observe a probe artifact under parallel pytest (roborev LOW).
    """
    tree = ast.parse(source_text, filename=filename)
    return _names_engine_key_literal(tree) or _references_engine_constant(tree)


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


def _engine_read_site_files(src_root: Path) -> set[str]:
    """Return the set of repo-relative .py paths under ``src_root`` that are
    engine-var READ sites, scanning the on-disk source READ-ONLY.

    Each ``*.py`` is read once (no writes) and handed to the PURE
    :func:`scan_source` detector, which flags BOTH the form-(a) key literal and
    the form-(b) sanctioned-constant reference. A cheap prefilter skips a file
    only when it contains NEITHER token (``RELAY_CEL_ENGINE`` nor
    ``_ENGINE_ENV_VAR``) anywhere -- such a file cannot hold either form, so it
    need not be parsed. (The MED evasion file holds ``_ENGINE_ENV_VAR`` without
    the literal, so it survives the prefilter and is parsed -- exactly the gap
    the prior literal-only prefilter left open.)
    """
    hits: set[str] = set()
    for py in sorted(src_root.rglob("*.py")):
        rel = str(py.relative_to(REPO_ROOT)).replace("\\", "/")
        text = py.read_text(encoding="utf-8")
        if _ENGINE_VAR not in text and _ENGINE_CONST not in text:
            continue
        if scan_source(str(py), text):
            hits.add(rel)
    return hits


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_relay_cel_engine_read_site_is_only_engine_py() -> None:
    """The ONLY file under ``packages/contracts/src`` that READS the engine var
    is the factory ``engine.py`` -- scanned READ-ONLY, no probe writes.

    Encodes the contract's complementary grep semantics precisely, but SOUNDLY.
    A bare ``grep -rn 'RELAY_CEL_ENGINE' packages/contracts/src`` also matches
    docstring / comment prose in ``pipeline.py`` and ``wasm_backed_evaluator.py``
    that explicitly states the var is NOT read there (deliberate negative
    references). The invariant the contract protects is the READ site, not the
    appearance of the token.

    The detector flags a file when it names the engine key in EITHER covered
    form: (a) the ``RELAY_CEL_ENGINE`` string literal in a non-docstring
    position, OR (b) a reference to the sanctioned constant ``_ENGINE_ENV_VAR``
    (``ast.Name`` usage or ``from ... import _ENGINE_ENV_VAR``). Form (b) is the
    convergent fix for the roborev MED finding: a read written
    ``from relay_contracts.engine import _ENGINE_ENV_VAR; os.environ.get(
    _ENGINE_ENV_VAR)`` reads the SAME env var without spelling the literal, so a
    literal-only scan would miss it. It confirms exactly ONE such file:
    ``engine.py`` (which both defines the literal ``_ENGINE_ENV_VAR =
    "RELAY_CEL_ENGINE"`` and uses the constant).
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

    engine_rel = str(ENGINE_FILE.relative_to(REPO_ROOT)).replace("\\", "/")
    read_site_files = _engine_read_site_files(CONTRACTS_SRC)
    assert read_site_files == {engine_rel}, (
        "engine selection (the RELAY_CEL_ENGINE env READ) must be performed in "
        f"EXACTLY one contracts-src file ({engine_rel}); found read sites: "
        f"{sorted(read_site_files)}. A new env read of RELAY_CEL_ENGINE outside "
        "engine.py -- whether it spells the 'RELAY_CEL_ENGINE' key literal OR "
        "reads it via the sanctioned constant _ENGINE_ENV_VAR -- would break the "
        "single-read-site determinism invariant (VAL-CWC-P4DUALRUN-008)."
    )


# ---------------------------------------------------------------------------
# Non-vacuity probes (roborev LOW fix): IN-MEMORY only -- no probe writes any
# file into packages/contracts/src. Each probe feeds an in-memory source STRING
# to the SAME pure :func:`scan_source` the real-tree guard uses, asserts the
# expected verdict, and mutates nothing on disk. This proves the guard BITES the
# evasions the prior os-API-form / literal-only detectors missed, and does NOT
# false-positive on prose -- without ever requiring a writable source tree or
# risking a parallel-pytest observation of a probe artifact.
# ---------------------------------------------------------------------------
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_bites_imported_constant_evasion() -> None:
    """The EXACT roborev MED evasion -- import the sanctioned constant and read
    through it, ``from relay_contracts.engine import _ENGINE_ENV_VAR`` then
    ``os.environ.get(_ENGINE_ENV_VAR)`` -- MUST be flagged.

    This file contains NO ``RELAY_CEL_ENGINE`` literal at all, so the form-(a)
    literal scan (and its literal-only prefilter) would skip it. Form (b) catches
    it via BOTH the ``ImportFrom`` of ``_ENGINE_ENV_VAR`` and the ``ast.Name``
    usage in the env read -- closing the single-read-site invariant against the
    sanctioned-constant alias.
    """
    body = (
        '"""Throwaway probe (in-memory): imported-constant MED evasion."""\n'
        "from relay_contracts.engine import _ENGINE_ENV_VAR\n"
        "import os\n\n\n"
        "def _read() -> str | None:\n"
        "    return os.environ.get(_ENGINE_ENV_VAR)\n"
    )
    assert _ENGINE_VAR not in body, (
        "probe sanity: the imported-constant evasion must contain NO "
        f"'{_ENGINE_VAR}' literal (that is the whole point); body names only "
        f"the sanctioned constant {_ENGINE_CONST}"
    )
    assert scan_source("_probe_imported_constant.py", body), (
        "GUARD VACUOUS: the imported-constant MED evasion (read via "
        f"{_ENGINE_CONST}, with NO '{_ENGINE_VAR}' literal) was NOT flagged. "
        "Form (b) must flag it via the ImportFrom and/or the Name usage."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_bites_imported_constant_aliased_evasion() -> None:
    """The aliased imported-constant form -- ``from relay_contracts.engine
    import _ENGINE_ENV_VAR as KEY`` then ``os.environ.get(KEY)`` -- MUST be
    flagged via the ImportFrom NAME (the import name is ``_ENGINE_ENV_VAR`` even
    though the local binding is ``KEY``), so an aliased read site is caught at
    the import even when no later ``_ENGINE_ENV_VAR`` Name appears."""
    body = (
        '"""Throwaway probe (in-memory): aliased imported-constant evasion."""\n'
        "from relay_contracts.engine import _ENGINE_ENV_VAR as KEY\n"
        "import os\n\n\n"
        "def _read() -> str | None:\n"
        "    return os.environ.get(KEY)\n"
    )
    assert _ENGINE_VAR not in body
    assert scan_source("_probe_imported_constant_aliased.py", body), (
        "GUARD VACUOUS: the ALIASED imported-constant evasion was NOT flagged. "
        f"The ImportFrom name '{_ENGINE_CONST}' must be matched even under an "
        "`as` alias."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_bites_os_environ_subscript_evasion() -> None:
    """A subscript read ``os.environ["RELAY_CEL_ENGINE"]`` MUST be flagged.

    The key literal appears as a Subscript index -- a read position -- so the
    form-(a) literal scan flags it regardless of the access form.
    """
    body = (
        '"""Throwaway probe (in-memory): os.environ subscript evasion."""\n'
        "import os\n\n\n"
        "def _read() -> str:\n"
        '    return os.environ["RELAY_CEL_ENGINE"]\n'
    )
    assert scan_source("_probe_environ_subscript.py", body), (
        "GUARD VACUOUS: the os.environ subscript evasion was NOT flagged; the "
        "key literal in the Subscript index must trip form (a)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_bites_from_os_import_environ_evasion() -> None:
    """The prior round's evasion -- ``from os import environ`` then
    ``environ.get("RELAY_CEL_ENGINE")`` -- MUST be flagged.

    The original os-API-form detector matched only ``os.<attr>`` access, so this
    from-import read named no ``os.environ`` node and bypassed it. The form-(a)
    literal scan catches it because the read still names the unavoidable
    ``"RELAY_CEL_ENGINE"`` key string.
    """
    body = (
        '"""Throwaway probe (in-memory): from-os-import environ evasion."""\n'
        "from os import environ\n\n\n"
        "def _read() -> str | None:\n"
        '    return environ.get("RELAY_CEL_ENGINE")\n'
    )
    assert scan_source("_probe_from_import_environ.py", body), (
        "GUARD VACUOUS: the from-os-import-environ evasion was NOT flagged; the "
        "key literal in the Call argument must trip form (a)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_ignores_docstring_and_comment_only_mentions() -> None:
    """A file that mentions ``RELAY_CEL_ENGINE`` / ``_ENGINE_ENV_VAR`` ONLY in a
    docstring and a ``#`` comment MUST NOT be flagged (no false positive).

    This mirrors the real tree: ``pipeline.py`` mentions the token only in
    comments and ``wasm_backed_evaluator.py`` only in docstrings, and neither
    reads the env var. Form (a) excludes docstrings (bare-string first
    statements) and comments (not AST nodes); form (b) matches only an
    ``ast.Name``/``ast.ImportFrom`` for the constant, never a prose mention, so
    neither form trips.
    """
    body = (
        '"""Engine selection (RELAY_CEL_ENGINE / _ENGINE_ENV_VAR) is NOT read '
        'here -- prose."""\n'
        "# This module never reads RELAY_CEL_ENGINE; the factory owns it.\n"
        "# It does not import or use _ENGINE_ENV_VAR either.\n\n\n"
        "def _noop() -> None:\n"
        '    """RELAY_CEL_ENGINE / _ENGINE_ENV_VAR named here only as prose."""\n'
        "    return None\n"
    )
    assert not scan_source("_probe_prose_only.py", body), (
        "FALSE POSITIVE: a docstring/comment-only mention of "
        f"'{_ENGINE_VAR}' / '{_ENGINE_CONST}' was wrongly flagged as a read "
        "site. Form (a) must exclude docstrings (bare-string first statements) "
        "and comments (not AST nodes); form (b) must match only an "
        "ast.Name/ast.ImportFrom, never prose."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_real_contracts_src_pipeline_and_wasm_evaluator_not_flagged() -> None:
    """The real prose-mention files in contracts-src (``pipeline.py``,
    ``wasm_backed_evaluator.py``) must NOT be flagged by the real-tree scan.

    These files name ``RELAY_CEL_ENGINE`` only in negative-reference prose
    (comments / docstrings) and do not reference ``_ENGINE_ENV_VAR`` as a
    Name/import, so :func:`scan_source` over their ON-DISK source (READ-ONLY)
    must return False -- they must not be in the real-tree read-site set. This
    directly confirms the inverse-PASS clause of the probe matrix against the
    actual checkout.
    """
    read_site_files = _engine_read_site_files(CONTRACTS_SRC)
    for name in ("pipeline.py", "wasm_backed_evaluator.py"):
        candidate = CONTRACTS_SRC / "relay_contracts" / name
        if not candidate.is_file():
            continue
        rel = str(candidate.relative_to(REPO_ROOT)).replace("\\", "/")
        text = candidate.read_text(encoding="utf-8")
        # Sanity: the file is a real prose-mention file (else this assertion is
        # vacuous for it). Only assert non-flag when the token actually appears.
        if _ENGINE_VAR in text or _ENGINE_CONST in text:
            assert rel not in read_site_files, (
                f"FALSE POSITIVE on the real tree: {rel} mentions the engine "
                "token only in prose (it does not read the env var) but was "
                f"flagged as a read site. Real read-site set: "
                f"{sorted(read_site_files)}"
            )
