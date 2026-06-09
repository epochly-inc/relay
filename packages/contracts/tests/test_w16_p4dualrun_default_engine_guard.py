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

Read-site detection -- the ENV-KEY STRING LITERAL scan (threat model):
  EVERY real environment read of the engine var MUST name the key STRING
  ``"RELAY_CEL_ENGINE"`` somewhere -- ``os.environ.get("RELAY_CEL_ENGINE")``,
  ``os.getenv("RELAY_CEL_ENGINE")``, ``os.environ["RELAY_CEL_ENGINE"]``, or the
  from-import form ``from os import environ; environ.get("RELAY_CEL_ENGINE")``
  / ``from os import getenv; getenv("RELAY_CEL_ENGINE")``. The key is the one
  UNAVOIDABLE token shared by all of them. So this guard scans the parsed AST
  of each contracts-src module for a string-literal node (``ast.Constant`` with
  a ``str`` value, INCLUDING the constant definition
  ``_ENGINE_ENV_VAR = "RELAY_CEL_ENGINE"``) whose value is EXACTLY
  ``RELAY_CEL_ENGINE`` and that is used in a READ position (not a docstring,
  not a comment).

  This supersedes the earlier os-API-FORM detector (which matched only
  ``os.environ`` / ``os.getenv`` attribute access on the ``os`` name, plus a
  bare ``getenv(...)`` call). That form-based detector was UNSOUND: a read
  written ``from os import environ; environ.get("RELAY_CEL_ENGINE")`` (the
  exact roborev MED evasion) named no ``os.<attr>`` node and bypassed it, so
  the single-read-site invariant was not actually locked. Scanning the KEY
  LITERAL instead of the os-API form catches every naturally-written read
  regardless of import style -- it is convergent on the unavoidable token,
  mirroring the lesson learned on the TypeScript env-guard.

  Soundness vs. prose (no false positive): a string-literal AST node is NEVER
  produced by a ``#`` comment (comments are not AST nodes), and the scan
  EXCLUDES docstrings (the bare-string ``Expr`` that is the first statement of
  a module / class / function body). ``pipeline.py`` mentions the token only in
  ``#`` comments and ``wasm_backed_evaluator.py`` only in docstrings, so neither
  trips the guard. The scan is further tightened to READ positions (Call
  argument or Subscript index, plus the engine-var constant DEFINITION) so any
  remaining prose-as-string-literal mention would also be excluded structurally.

  Explicit, documented NON-GOAL: adversarial string-splitting
  (``"RELAY_" + "CEL_ENGINE"``, ``"".join(...)``, byte/char construction) is
  out of scope and is NOT detected -- identical posture to the TS env-guard. A
  developer who deliberately obfuscates the key to hide an env read is outside
  this guard's threat model; the guard locks the invariant against every
  NATURALLY written read.

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

_ENGINE_VAR = "RELAY_CEL_ENGINE"


def _module_docstring_node_ids(tree: ast.AST) -> set[int]:
    """Collect the ``id()`` of every bare-string ``ast.Constant`` that is a
    docstring -- the first statement of a module / class / function body.

    A docstring is the only place a string literal equal to the engine var can
    appear WITHOUT being a read (deliberate negative-reference prose, e.g.
    ``wasm_backed_evaluator.py``'s module docstring). Excluding these node ids
    from the key-literal scan prevents a false positive on prose while keeping
    the scan sound against every real read (which names the key as a Call
    argument, Subscript index, or the engine-var constant definition -- never
    as a docstring).
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


def _names_engine_key_in_read_position(tree: ast.AST) -> bool:
    """True if the AST contains a STRING-LITERAL node whose value is EXACTLY
    ``RELAY_CEL_ENGINE`` used in a READ position (NOT a docstring, NOT a
    comment).

    This is the SOUND read-site detector. EVERY naturally-written environment
    read of the engine var MUST name the key string ``"RELAY_CEL_ENGINE"`` --
    whether via ``os.environ.get("RELAY_CEL_ENGINE")``,
    ``os.getenv("RELAY_CEL_ENGINE")``, ``os.environ["RELAY_CEL_ENGINE"]``, the
    from-import form ``from os import environ; environ.get("RELAY_CEL_ENGINE")``
    /  ``from os import getenv; getenv("RELAY_CEL_ENGINE")``, or the engine
    factory's constant definition ``_ENGINE_ENV_VAR = "RELAY_CEL_ENGINE"``. The
    key literal is the one UNAVOIDABLE token shared by all of them, so scanning
    for it catches the read regardless of which ``os`` import form is used --
    defeating the ``from os import environ`` evasion by construction.

    Soundness vs. prose:
      - ``#`` comments are NOT AST nodes, so they can never match.
      - Docstrings (bare-string ``Expr`` first statements) are EXCLUDED via
        :func:`_module_docstring_node_ids`.
    A genuine key literal lands in a Call argument, a Subscript index, or an
    assignment value (the constant definition) -- all READ positions, none of
    which are docstrings. ``pipeline.py`` (comment-only mentions) and
    ``wasm_backed_evaluator.py`` (docstring-only mentions) therefore do NOT
    match.

    NON-GOAL (documented, same posture as the TS env-guard): adversarial
    string-splitting (``"RELAY_" + "CEL_ENGINE"``) is deliberately NOT detected.
    A developer who obfuscates the key to hide an env read is outside this
    guard's threat model.
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


def _key_literal_read_site_files(src_root: Path) -> set[str]:
    """Return the set of repo-relative .py paths under ``src_root`` that contain
    a key-literal READ of the engine var (an ``ast.Constant`` str node equal to
    ``RELAY_CEL_ENGINE`` that is NOT a docstring).

    This is the convergent read-site detector (see module docstring): it scans
    for the UNAVOIDABLE key string literal, so it catches every naturally
    written env read regardless of which ``os`` import form names the read.
    """
    hits: set[str] = set()
    for py in sorted(src_root.rglob("*.py")):
        rel = str(py.relative_to(REPO_ROOT)).replace("\\", "/")
        text = py.read_text(encoding="utf-8")
        # Cheap prefilter: a file with no occurrence of the token at all cannot
        # hold a key literal (or prose). Skip parsing it.
        if _ENGINE_VAR not in text:
            continue
        if _names_engine_key_in_read_position(ast.parse(text, filename=str(py))):
            hits.add(rel)
    return hits


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_relay_cel_engine_read_site_is_only_engine_py() -> None:
    """The ONLY file under ``packages/contracts/src`` that READS the engine var
    is the factory ``engine.py``.

    Encodes the contract's complementary grep semantics precisely, but SOUNDLY.
    A bare ``grep -rn 'RELAY_CEL_ENGINE' packages/contracts/src`` also matches
    docstring / comment prose in ``pipeline.py`` and ``wasm_backed_evaluator.py``
    that explicitly states the var is NOT read there (deliberate negative
    references). The invariant the contract protects is the READ site, not the
    appearance of the token.

    The detector scans for the ENV-KEY STRING LITERAL (``ast.Constant`` str ==
    ``RELAY_CEL_ENGINE`` in a read position, excluding docstrings) rather than
    the os-API FORM. Every naturally-written read MUST name that key literal --
    ``os.environ.get(...)``, ``os.getenv(...)``, ``os.environ[...]``, or the
    from-import form ``from os import environ; environ.get("RELAY_CEL_ENGINE")``
    -- so the scan catches all of them, INCLUDING the from-import evasion that
    the prior os-API-form detector missed (the roborev MED finding). It confirms
    exactly ONE such file: ``engine.py`` (which names the key in its constant
    definition ``_ENGINE_ENV_VAR = "RELAY_CEL_ENGINE"``).
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
    read_site_files = _key_literal_read_site_files(CONTRACTS_SRC)
    assert read_site_files == {engine_rel}, (
        "engine selection (the RELAY_CEL_ENGINE env READ) must be performed in "
        f"EXACTLY one contracts-src file ({engine_rel}); found key-literal read "
        f"sites: {sorted(read_site_files)}. A new env read of RELAY_CEL_ENGINE "
        "outside engine.py (in ANY os-import form, since the read must name the "
        "'RELAY_CEL_ENGINE' key string) would break the single-read-site "
        "determinism invariant (VAL-CWC-P4DUALRUN-008)."
    )


# ---------------------------------------------------------------------------
# Non-vacuity probes: prove the key-literal guard BITES the evasions the prior
# os-API-form detector missed, and does NOT false-positive on prose. Each probe
# plants a throwaway file under contracts/src, runs the SAME detector the guard
# uses, asserts the expected verdict, then removes the file in a finally block
# (no throwaway file is ever left behind, even on assertion failure).
# ---------------------------------------------------------------------------
def _write_probe(rel_name: str, body: str) -> Path:
    """Write a throwaway probe module under contracts/src; return its path."""
    path = CONTRACTS_SRC / "relay_contracts" / rel_name
    path.write_text(body, encoding="utf-8")
    return path


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_bites_from_os_import_environ_evasion() -> None:
    """The EXACT roborev MED evasion -- ``from os import environ`` then
    ``environ.get("RELAY_CEL_ENGINE")`` -- MUST be detected as a read site.

    The prior os-API-form detector matched only ``os.<attr>`` access and a bare
    ``getenv(...)`` call, so this from-import read named no ``os.environ`` node
    and bypassed the guard. The key-literal scan catches it because the read
    still names the unavoidable ``"RELAY_CEL_ENGINE"`` key string.
    """
    probe = _write_probe(
        "_probe_from_import_environ.py",
        '"""Throwaway probe: from-os-import environ evasion."""\n'
        "from os import environ\n\n\n"
        "def _read() -> str | None:\n"
        '    return environ.get("RELAY_CEL_ENGINE")\n',
    )
    try:
        engine_rel = str(ENGINE_FILE.relative_to(REPO_ROOT)).replace("\\", "/")
        probe_rel = str(probe.relative_to(REPO_ROOT)).replace("\\", "/")
        hits = _key_literal_read_site_files(CONTRACTS_SRC)
        assert probe_rel in hits, (
            "GUARD VACUOUS: the from-os-import-environ evasion "
            f"({probe_rel}) was NOT detected as a read site. The key-literal "
            "scan must flag it because it names the 'RELAY_CEL_ENGINE' key "
            f"string in a Call argument. Detected sites: {sorted(hits)}"
        )
        # And the top-level guard verdict must now be FAILURE (more than just
        # engine.py reads the key).
        assert hits != {engine_rel}, (
            "GUARD VACUOUS: with the evasion planted the read-site set must no "
            f"longer equal {{engine.py}}; got {sorted(hits)}"
        )
    finally:
        probe.unlink(missing_ok=True)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_bites_os_environ_subscript_evasion() -> None:
    """A subscript read ``os.environ["RELAY_CEL_ENGINE"]`` MUST be detected.

    The key literal appears as a Subscript index -- a read position -- so the
    key-literal scan flags it regardless of the access form.
    """
    probe = _write_probe(
        "_probe_environ_subscript.py",
        '"""Throwaway probe: os.environ subscript evasion."""\n'
        "import os\n\n\n"
        "def _read() -> str:\n"
        '    return os.environ["RELAY_CEL_ENGINE"]\n',
    )
    try:
        probe_rel = str(probe.relative_to(REPO_ROOT)).replace("\\", "/")
        hits = _key_literal_read_site_files(CONTRACTS_SRC)
        assert probe_rel in hits, (
            "GUARD VACUOUS: the os.environ subscript evasion "
            f"({probe_rel}) was NOT detected as a read site; the key literal in "
            f"the Subscript index must be flagged. Detected sites: {sorted(hits)}"
        )
    finally:
        probe.unlink(missing_ok=True)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-008")
def test_guard_ignores_docstring_and_comment_only_mentions() -> None:
    """A file that mentions ``RELAY_CEL_ENGINE`` ONLY in a docstring and a
    ``#`` comment MUST NOT be detected as a read site (no false positive).

    This mirrors the real tree: ``pipeline.py`` mentions the token only in
    comments and ``wasm_backed_evaluator.py`` only in docstrings, and neither
    reads the env var. The key-literal scan excludes docstrings (bare-string
    first statements) and comments (not AST nodes), so prose never trips it.
    """
    probe = _write_probe(
        "_probe_prose_only.py",
        '"""Engine selection (RELAY_CEL_ENGINE) is NOT read here -- prose."""\n'
        "# This module never reads RELAY_CEL_ENGINE; the factory owns it.\n\n\n"
        "def _noop() -> None:\n"
        '    """RELAY_CEL_ENGINE is named here only as documentation prose."""\n'
        "    return None\n",
    )
    try:
        probe_rel = str(probe.relative_to(REPO_ROOT)).replace("\\", "/")
        hits = _key_literal_read_site_files(CONTRACTS_SRC)
        assert probe_rel not in hits, (
            "FALSE POSITIVE: a docstring/comment-only mention of "
            f"'{_ENGINE_VAR}' ({probe_rel}) was wrongly flagged as a read site. "
            "The key-literal scan must exclude docstrings (bare-string first "
            "statements) and comments (not AST nodes). Detected sites: "
            f"{sorted(hits)}"
        )
    finally:
        probe.unlink(missing_ok=True)
