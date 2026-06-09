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

Read-site detection -- TOKEN-PRESENCE scan (threat model):
  The prior rounds of this guard FAILED by enumerating access FORMS (first the
  ``os.<attr>`` API shape, then the ``RELAY_CEL_ENGINE`` literal, then
  ``ast.Name`` + ``ast.ImportFrom`` of ``_ENGINE_ENV_VAR``). Each form-branch
  left a tail: ``from os import environ`` named no ``os.<attr>`` node; importing
  ``_ENGINE_ENV_VAR`` named no literal; and the roborev MED form
  ``import relay_contracts.engine as engine; os.environ.get(
  engine._ENGINE_ENV_VAR)`` reads the SAME env var through an
  ``ast.Attribute.attr`` -- neither an ``ast.Name`` nor an ``ImportFrom`` name,
  so the form-(b) enumeration skipped it. Enumerating forms is a losing game.

  This round STOPS enumerating forms and switches to a SOUND TOKEN-PRESENCE scan
  (the round-6 lesson from the TS env-guard). The engine-selection key can be
  named non-adversarially only TWO ways, and BOTH leave an unavoidable token in
  an AST node field:

  (a) The ENV-KEY STRING LITERAL ``"RELAY_CEL_ENGINE"``. EVERY read that spells
      the key inline names this string -- ``os.environ.get("RELAY_CEL_ENGINE")``,
      ``os.getenv("RELAY_CEL_ENGINE")``, ``os.environ["RELAY_CEL_ENGINE"]``, the
      from-import form ``from os import environ; environ.get("RELAY_CEL_ENGINE")``,
      or the constant definition ``_ENGINE_ENV_VAR = "RELAY_CEL_ENGINE"``. The
      guard flags any non-docstring ``ast.Constant`` ``str`` node equal to
      ``RELAY_CEL_ENGINE`` (comments are not AST nodes, so they never match).

  (b) The SANCTIONED CONSTANT IDENTIFIER ``_ENGINE_ENV_VAR``. A read that does
      NOT spell the literal instead names the factory's sanctioned constant.
      EVERY such reference -- ``_ENGINE_ENV_VAR`` (Name),
      ``engine._ENGINE_ENV_VAR`` (Attribute.attr; the roborev MED form),
      ``from relay_contracts.engine import _ENGINE_ENV_VAR`` (alias.name),
      ``import ... import _ENGINE_ENV_VAR as K`` (alias.name), and any future
      access path -- contains the IDENTIFIER TOKEN ``_ENGINE_ENV_VAR`` SOMEWHERE
      in an identifier-bearing node field. So the guard walks the AST and flags
      the file when ANY node carries the string ``_ENGINE_ENV_VAR`` in an
      identifier field -- ``ast.Name.id``, ``ast.Attribute.attr``,
      ``ast.alias.name`` / ``ast.alias.asname``, ``ast.keyword.arg``,
      function / class / param names (``.name`` / ``.arg``), etc. By keying on
      the identifier TOKEN rather than a specific node shape, this subsumes Name
      + ImportFrom + Attribute + every future access path with NO remaining
      form-tail. There is nothing left to enumerate.

  Why token-presence is the convergent fix: the detector keys on the two
  UNAVOIDABLE tokens -- ``RELAY_CEL_ENGINE`` (the key literal) and
  ``_ENGINE_ENV_VAR`` (the sanctioned constant) -- so EVERY non-adversarial
  reference is covered BY CONSTRUCTION, independent of which os-import form,
  attribute path, or import alias the read happens to use. This mirrors the
  round-6 TS env-guard lesson: detect the token, not the shape.

  Soundness vs. prose (no false positive):
    - ``#`` comments are NEVER AST nodes, so they can never match either arm.
    - Arm (a) EXCLUDES docstrings (the bare-string ``Expr`` first statement of
      a module / class / function body), so a docstring that merely names the
      literal as prose does not trip it.
    - Arm (b) matches the token ``_ENGINE_ENV_VAR`` only in an IDENTIFIER field
      (``id`` / ``attr`` / ``name`` / ``asname`` / ``arg``). A docstring or
      comment that mentions the token as prose produces a string-literal
      ``ast.Constant`` (whose ``.value`` is NOT an identifier field) or no AST
      node at all, so prose does not trip it either.
  ``pipeline.py`` mentions ``RELAY_CEL_ENGINE`` only in ``#`` comments and
  ``wasm_backed_evaluator.py`` only in docstrings, and neither carries the
  ``_ENGINE_ENV_VAR`` identifier token in any node field, so neither trips.

  Explicit, documented NON-GOAL: adversarial string-splitting
  (``"RELAY_" + "CEL_ENGINE"``, ``"".join(...)``, byte/char construction, or
  ``getattr(engine, "_ENGINE" + "_ENV_VAR")``) is out of scope and is NOT
  detected -- identical posture to the TS env-guard. A developer who
  deliberately obfuscates the key to hide an env read is outside this guard's
  threat model. The detector keys on the unavoidable tokens
  ``RELAY_CEL_ENGINE`` (key literal) and ``_ENGINE_ENV_VAR`` (sanctioned
  constant), covering every non-adversarial reference by construction.

Probe isolation (roborev LOW fix): the non-vacuity probes drive the REAL on-disk
read path :func:`_engine_read_site_files` (its cheap two-token PREFILTER followed
by the AST :func:`scan_source`) over an ISOLATED scan root (pytest ``tmp_path``),
NOT :func:`scan_source` in isolation. Each probe writes its throwaway module into
the tmp root -- NEVER into ``packages/contracts/src`` -- and asserts
``_engine_read_site_files(tmp_root)`` reports the expected verdict. Driving the
real prefilter+scan locks the prefilter regression: if someone reverts the
prefilter to literal-only, the ``_ENGINE_ENV_VAR``-only probe through the real
path FAILS (the prior LOW left the prefilter unexercised by calling
``scan_source`` directly). The real contracts-src tree is still scanned
READ-ONLY; probes touch only the isolated tmp root.

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


# The AST node attributes that carry a Python IDENTIFIER (a bound or referenced
# name), as opposed to arbitrary string DATA. A reference to the sanctioned
# constant lands the token ``_ENGINE_ENV_VAR`` in exactly these fields, never in
# a string-literal ``ast.Constant.value`` (which is DATA, not an identifier).
# Single-identifier fields hold a ``str``; list fields (``Global``/``Nonlocal``
# ``names``) hold a ``list[str]``.
_IDENTIFIER_STR_FIELDS: tuple[str, ...] = (
    "id",  # ast.Name
    "attr",  # ast.Attribute (the roborev MED form: engine._ENGINE_ENV_VAR)
    "name",  # ast.alias / FunctionDef / AsyncFunctionDef / ClassDef / ExceptHandler
    "asname",  # ast.alias (the `import ... as X` binding)
    "arg",  # ast.arg (parameter name) / ast.keyword (kwarg name)
)
_IDENTIFIER_LIST_FIELDS: tuple[str, ...] = (
    "names",  # ast.Global / ast.Nonlocal hold a list[str] of identifiers
)


def _names_engine_constant_token(tree: ast.AST) -> bool:
    """Arm (b): True if the IDENTIFIER token ``_ENGINE_ENV_VAR`` appears in ANY
    identifier-bearing node field anywhere in the AST.

    This is a SOUND TOKEN-PRESENCE scan, NOT a form enumeration. The prior
    rounds enumerated access FORMS (``ast.Name`` usage, then also
    ``ast.ImportFrom`` name) and each left a tail -- most recently the roborev
    MED form ``import relay_contracts.engine as engine; os.environ.get(
    engine._ENGINE_ENV_VAR)`` where ``_ENGINE_ENV_VAR`` is an
    ``ast.Attribute.attr``, neither a ``Name`` nor an ``ImportFrom`` name. We
    STOP enumerating forms: EVERY non-adversarial reference to the sanctioned
    constant -- ``_ENGINE_ENV_VAR`` (Name.id), ``engine._ENGINE_ENV_VAR``
    (Attribute.attr), ``from ... import _ENGINE_ENV_VAR`` (alias.name),
    ``import _ENGINE_ENV_VAR as K`` (alias.name), a param / function named after
    it (arg / name), and any future access path -- places the IDENTIFIER TOKEN
    ``_ENGINE_ENV_VAR`` in one of the identifier fields enumerated by
    :data:`_IDENTIFIER_STR_FIELDS` / :data:`_IDENTIFIER_LIST_FIELDS`. Walking the
    AST and checking those fields subsumes Name + ImportFrom + Attribute + every
    future form with NO remaining tail.

    Soundness vs. prose (no false positive): the token is matched ONLY in an
    identifier field. A docstring or ``#`` comment that mentions
    ``_ENGINE_ENV_VAR`` as prose produces a string-literal ``ast.Constant``
    (whose ``.value`` is DATA, not in the identifier set) or no AST node at all,
    so prose never trips this arm. The documented NON-GOAL stands: a
    dynamically-assembled identifier (``getattr(engine, "_ENGINE" +
    "_ENV_VAR")``) hides the token in a split string literal and is out of
    scope, exactly like the TS env-guard.
    """
    for node in ast.walk(tree):
        for field in _IDENTIFIER_STR_FIELDS:
            value = getattr(node, field, None)
            if isinstance(value, str) and value == _ENGINE_CONST:
                return True
        for field in _IDENTIFIER_LIST_FIELDS:
            value = getattr(node, field, None)
            if isinstance(value, list) and _ENGINE_CONST in value:
                return True
    return False


def scan_source(filename: str, source_text: str) -> bool:
    """PURE read-site detector over in-memory source (TOKEN-PRESENCE scan).

    Return True if ``source_text`` (parsed as a Python module named ``filename``)
    is an engine-var READ site -- i.e. it carries EITHER of the two unavoidable
    engine-selection tokens, by construction covering every non-adversarial
    reference (no form enumeration):

      (a) the ``RELAY_CEL_ENGINE`` string literal in a non-docstring position
          (:func:`_names_engine_key_literal`), OR
      (b) the IDENTIFIER token ``_ENGINE_ENV_VAR`` in ANY identifier-bearing AST
          node field -- ``Name.id``, ``Attribute.attr``, ``alias.name`` /
          ``asname``, ``arg``, function / class names, etc.
          (:func:`_names_engine_constant_token`). This subsumes the Name,
          ImportFrom, AND ``ast.Attribute.attr`` (roborev MED) access paths.

    This function performs NO filesystem access: it neither reads ``filename``
    from disk nor writes anything. ``filename`` is used only as the AST
    ``filename`` for clearer SyntaxError messages. The real-tree guard and the
    non-vacuity probes both reach this scanner through
    :func:`_engine_read_site_files` (the real two-token prefilter + AST scan);
    the probes point that path at an isolated ``tmp_path`` root so a probe can
    never mutate the checkout or be observed under parallel pytest (roborev LOW).
    """
    tree = ast.parse(source_text, filename=filename)
    return _names_engine_key_literal(tree) or _names_engine_constant_token(tree)


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


def _engine_read_site_files(src_root: Path = CONTRACTS_SRC) -> set[str]:
    """Return the set of ``src_root``-relative .py paths under ``src_root`` that
    are engine-var READ sites, scanning the on-disk source READ-ONLY.

    This is the REAL read path: a cheap two-token PREFILTER followed by the AST
    :func:`scan_source`. ``src_root`` defaults to the real ``packages/contracts/
    src`` tree (so the real-tree guard calls it bare), but the non-vacuity probes
    pass an ISOLATED pytest ``tmp_path`` root so they exercise THIS prefilter +
    scan -- not :func:`scan_source` alone -- over throwaway modules written into
    the tmp root, never into the real checkout (roborev LOW fix).

    Each ``*.py`` is read once (no writes). The PREFILTER skips a file only when
    it contains NEITHER token (``RELAY_CEL_ENGINE`` nor ``_ENGINE_ENV_VAR``)
    anywhere -- such a file cannot hold a read in either arm, so it need not be
    parsed. The prefilter keys on BOTH tokens precisely so a
    ``_ENGINE_ENV_VAR``-only file (the roborev MED form, which holds NO
    ``RELAY_CEL_ENGINE`` literal) survives the prefilter and is parsed -- the gap
    a literal-only prefilter would leave open. Reverting the prefilter to
    literal-only makes the ``_ENGINE_ENV_VAR``-only probe (driven through THIS
    function over the tmp root) fail, which is exactly the regression lock.

    Returned paths are relative to ``src_root`` (NOT ``REPO_ROOT``) so the helper
    is meaningful for an isolated tmp root that lives outside the repo.
    """
    hits: set[str] = set()
    for py in sorted(src_root.rglob("*.py")):
        rel = str(py.relative_to(src_root)).replace("\\", "/")
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

    The detector is a TOKEN-PRESENCE scan: it flags a file that carries EITHER
    unavoidable token: (a) the ``RELAY_CEL_ENGINE`` string literal in a
    non-docstring position, OR (b) the IDENTIFIER token ``_ENGINE_ENV_VAR`` in
    ANY identifier-bearing node field (``Name.id`` / ``Attribute.attr`` /
    ``alias.name`` / ``asname`` / ``arg`` / ...). Arm (b) is the convergent fix
    for the roborev MED finding: a read written ``import relay_contracts.engine
    as engine; os.environ.get(engine._ENGINE_ENV_VAR)`` reads the SAME env var
    via an ``ast.Attribute.attr`` -- no literal, no ``ast.Name``, no
    ``ImportFrom`` -- so the prior form enumeration missed it. Token-presence
    covers Name + Attribute + import alias + every future access path with no
    remaining tail. It confirms exactly ONE such file: ``engine.py`` (which both
    defines the literal ``_ENGINE_ENV_VAR = "RELAY_CEL_ENGINE"`` and uses the
    constant).
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

    # _engine_read_site_files returns paths relative to its scan root
    # (CONTRACTS_SRC here), so compute the expected engine path the same way.
    engine_rel = str(ENGINE_FILE.relative_to(CONTRACTS_SRC)).replace("\\", "/")
    read_site_files = _engine_read_site_files(CONTRACTS_SRC)
    assert read_site_files == {engine_rel}, (
        "engine selection (the RELAY_CEL_ENGINE env READ) must be performed in "
        f"EXACTLY one contracts-src file ({engine_rel}); found read sites: "
        f"{sorted(read_site_files)}. A new env read of RELAY_CEL_ENGINE outside "
        "engine.py -- whether it spells the 'RELAY_CEL_ENGINE' key literal OR "
        "reads it via the sanctioned constant _ENGINE_ENV_VAR in ANY identifier "
        "field (Name / Attribute.attr / import alias) -- would break the "
        "single-read-site determinism invariant (VAL-CWC-P4DUALRUN-008)."
    )


# ---------------------------------------------------------------------------
# Non-vacuity probes (roborev LOW fix): each probe drives the REAL on-disk read
# path :func:`_engine_read_site_files` (its two-token PREFILTER + AST
# :func:`scan_source`) over an ISOLATED pytest ``tmp_path`` root. The probe
# WRITES its throwaway module into the tmp root -- NEVER into
# packages/contracts/src -- and asserts the real path's verdict. Driving the
# real prefilter+scan (not :func:`scan_source` in isolation) is the roborev LOW
# fix: it LOCKS the prefilter regression -- reverting the prefilter to
# literal-only makes the ``_ENGINE_ENV_VAR``-only probe FAIL through the real
# path. The real checkout is untouched; only the isolated tmp root is written.
# ---------------------------------------------------------------------------
def _flagged_via_real_path(tmp_path: Path, filename: str, body: str) -> bool:
    """Write ``body`` as ``filename`` into the ISOLATED ``tmp_path`` scan root,
    then run the REAL on-disk read path :func:`_engine_read_site_files` over that
    root and return whether the file was flagged as a read site.

    This exercises the genuine prefilter + AST scan (the same code the real-tree
    guard runs), not :func:`scan_source` alone -- so the prefilter cannot silently
    regress to literal-only without a probe failing. Writes land ONLY under
    ``tmp_path`` (pytest's per-test isolated dir); the real source tree is never
    touched.
    """
    target = tmp_path / filename
    target.write_text(body, encoding="utf-8")
    hits = _engine_read_site_files(tmp_path)
    return filename in hits


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_bites_module_attribute_constant_evasion(tmp_path: Path) -> None:
    """The EXACT roborev MED evasion -- a MODULE-ATTRIBUTE reference to the
    sanctioned constant, ``import relay_contracts.engine as engine`` then
    ``os.environ.get(engine._ENGINE_ENV_VAR)`` -- MUST be flagged through the
    real read path.

    Here ``_ENGINE_ENV_VAR`` is an ``ast.Attribute.attr`` -- NOT an ``ast.Name``,
    NOT an ``ImportFrom`` name -- and the file holds NO ``RELAY_CEL_ENGINE``
    literal. The prior Name+ImportFrom form enumeration skipped it entirely (the
    finding). The token-presence scan flags it because ``_ENGINE_ENV_VAR`` lands
    in the ``attr`` identifier field, and the two-token prefilter parses the file
    because ``_ENGINE_ENV_VAR`` appears as a substring.
    """
    body = (
        '"""Throwaway probe: module-attribute constant (roborev MED)."""\n'
        "import relay_contracts.engine as engine\n"
        "import os\n\n\n"
        "def _read() -> str | None:\n"
        "    return os.environ.get(engine._ENGINE_ENV_VAR)\n"
    )
    assert _ENGINE_VAR not in body, (
        "probe sanity: the module-attribute evasion must contain NO "
        f"'{_ENGINE_VAR}' literal (that is the whole point); it names the "
        f"constant only via the attribute {_ENGINE_CONST}"
    )
    assert _flagged_via_real_path(tmp_path, "_probe_module_attr.py", body), (
        "GUARD VACUOUS: the roborev MED module-attribute evasion (read via "
        f"engine.{_ENGINE_CONST}, an ast.Attribute.attr, with NO '{_ENGINE_VAR}' "
        "literal) was NOT flagged through the real prefilter+scan path. The "
        "token-presence scan must match the identifier in the attr field."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_bites_imported_constant_evasion(tmp_path: Path) -> None:
    """The imported-constant evasion -- ``from relay_contracts.engine import
    _ENGINE_ENV_VAR`` then ``os.environ.get(_ENGINE_ENV_VAR)`` -- MUST be flagged
    through the real read path.

    This file contains NO ``RELAY_CEL_ENGINE`` literal at all, so a literal-only
    prefilter would SKIP it before any AST parse. The two-token prefilter keeps
    it (``_ENGINE_ENV_VAR`` is present), and the token-presence scan flags it via
    the ``alias.name`` of the import AND the ``ast.Name`` usage in the read --
    locking the prefilter regression through the real path (roborev LOW).
    """
    body = (
        '"""Throwaway probe: imported-constant evasion."""\n'
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
    assert _flagged_via_real_path(tmp_path, "_probe_imported_constant.py", body), (
        "GUARD VACUOUS: the imported-constant evasion (read via "
        f"{_ENGINE_CONST}, with NO '{_ENGINE_VAR}' literal) was NOT flagged "
        "through the real prefilter+scan path. The two-token prefilter must keep "
        "the file and the token-presence scan must match the alias name / Name."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_bites_imported_constant_aliased_evasion(tmp_path: Path) -> None:
    """The aliased imported-constant form -- ``from relay_contracts.engine
    import _ENGINE_ENV_VAR as KEY`` then ``os.environ.get(KEY)`` -- MUST be
    flagged through the real read path via the import ``alias.name`` (which is
    ``_ENGINE_ENV_VAR`` even though the local binding is ``KEY``), so an aliased
    read site is caught at the import even when no later ``_ENGINE_ENV_VAR`` Name
    appears."""
    body = (
        '"""Throwaway probe: aliased imported-constant evasion."""\n'
        "from relay_contracts.engine import _ENGINE_ENV_VAR as KEY\n"
        "import os\n\n\n"
        "def _read() -> str | None:\n"
        "    return os.environ.get(KEY)\n"
    )
    assert _ENGINE_VAR not in body
    assert _flagged_via_real_path(
        tmp_path, "_probe_imported_constant_aliased.py", body
    ), (
        "GUARD VACUOUS: the ALIASED imported-constant evasion was NOT flagged "
        f"through the real path. The import alias.name '{_ENGINE_CONST}' must be "
        "matched even under an `as` alias."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_bites_os_environ_subscript_literal_evasion(tmp_path: Path) -> None:
    """A subscript read ``os.environ["RELAY_CEL_ENGINE"]`` -- the key literal in
    a read position -- MUST be flagged through the real read path.

    The key literal appears as a Subscript index, so the literal arm flags it
    regardless of the access form; the two-token prefilter keeps the file because
    ``RELAY_CEL_ENGINE`` is present.
    """
    body = (
        '"""Throwaway probe: os.environ subscript literal."""\n'
        "import os\n\n\n"
        "def _read() -> str:\n"
        '    return os.environ["RELAY_CEL_ENGINE"]\n'
    )
    assert _flagged_via_real_path(tmp_path, "_probe_environ_subscript.py", body), (
        "GUARD VACUOUS: the os.environ subscript literal was NOT flagged through "
        "the real path; the key literal in the Subscript index must trip arm (a)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_ignores_docstring_and_comment_only_mentions(tmp_path: Path) -> None:
    """A file that mentions ``RELAY_CEL_ENGINE`` / ``_ENGINE_ENV_VAR`` ONLY in a
    docstring and a ``#`` comment MUST NOT be flagged through the real read path
    (no false positive).

    This mirrors the real tree: ``pipeline.py`` mentions the token only in
    comments and ``wasm_backed_evaluator.py`` only in docstrings, and neither
    reads the env var. The literal arm excludes docstrings (bare-string first
    statements) and comments (not AST nodes); the token-presence arm matches
    ``_ENGINE_ENV_VAR`` ONLY in an identifier field (id / attr / alias name /
    arg), never in a docstring ``ast.Constant.value`` (which is DATA), so prose
    does not trip it.
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
    # Sanity: the body really does carry both tokens (so the prefilter cannot
    # vacuously skip it and the no-false-positive claim is non-trivial -- the
    # file IS parsed and the AST scan IS the thing rejecting it).
    assert _ENGINE_VAR in body and _ENGINE_CONST in body, (
        "probe sanity: the prose body must contain BOTH tokens so the prefilter "
        "parses it and the AST scan (not the prefilter) is what declines it"
    )
    assert not _flagged_via_real_path(tmp_path, "_probe_prose_only.py", body), (
        "FALSE POSITIVE: a docstring/comment-only mention of "
        f"'{_ENGINE_VAR}' / '{_ENGINE_CONST}' was wrongly flagged as a read "
        "site through the real path. The literal arm must exclude docstrings and "
        "comments; the token-presence arm must match the identifier ONLY in an "
        "identifier field, never in a docstring/comment prose mention."
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
        # _engine_read_site_files returns CONTRACTS_SRC-relative paths.
        rel = str(candidate.relative_to(CONTRACTS_SRC)).replace("\\", "/")
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
