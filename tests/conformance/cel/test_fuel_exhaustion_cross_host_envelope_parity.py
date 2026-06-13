"""VAL-CWC-P7EDGE-004: fuel-exhaustion RELAY-CEL-003 envelope byte-identical
across the Python (wasmtime) and Node hosts.

This is the WS-J cross-host counterpart of the dual-run corpus gate
(``test_dual_run_cross_host_wasm_parity.py``): where that gate proves Py-wasm ==
Node-wasm over the SUCCESS/error corpus by comparing a per-case
``sha256(jcs(value))`` digest (success) or ``code``+``subtype`` (error), THIS
gate proves the FUEL-EXHAUSTION error ENVELOPE is byte-identical at the WIRE
level: for a FIXED fuel-exhausting expression + FIXED budget, the Python loader
and the Node loader -- both loading the SAME pinned ``relay_cel_wasm.wasm`` --
emit the IDENTICAL serialized envelope bytes (same key order, same code
RELAY-CEL-003, same subtype RELAY-CEL-TIMEOUT-001, same message bytes).

Why a SEPARATE wire-byte gate (not just code+subtype)
-----------------------------------------------------
The dual-run corpus gate compares an error case by ``code``+``subtype`` only --
a deliberately host-marshalling-agnostic SIGNATURE. The fuel-exhaustion contract
(VAL-CWC-P7EDGE-004) is STRONGER: it requires the ENTIRE serialized envelope to
be byte-identical, including the human-readable ``error`` MESSAGE (which embeds
the budget integer) and the key ORDER. A divergence in the message text or key
order would pass the corpus gate's ``code``+``subtype`` check but is a real
cross-host wire divergence -- exactly what this gate catches. To make the claim
genuine this test captures the RAW envelope bytes EACH host reads out of wasm
linear memory (BEFORE any ``json.loads`` / ``JSON.parse`` re-serialization), so
the comparison is over the exact bytes the wasm wrote, not a host-normalized
re-encoding.

Driving fuel WITHOUT depending on the in-flight loader fuel surface
-------------------------------------------------------------------
The Python loader (``relay_cel_wasm.RelayCel.eval``) already accepts
``fuel_budget`` and forwards it into the wasm request. The Node ``.mjs`` loader's
optional fuel surface is being wired by a CONCURRENT work-stream; to keep THIS
gate independent of that in-flight change, the Node harness
(``fuel_exhaustion_cross_host.mjs``) drives the wasm eval request JSON DIRECTLY
with the ``fuel_budget`` field set, marshaling memory in/out through the wasm's
own ``alloc``/``eval``/``dealloc`` exports (the SAME marshaling the loader uses),
bypassing the loader's optional-param surface. The Python side here does the
SAME direct marshaling so BOTH sides capture the raw wasm-emitted bytes
identically. Both hosts instantiate with an EMPTY import object (no-WASI reactor;
the fuel counter is in-wasm), so neither side needs a host clock or fuel hook.

Fixed fixture (the cross-host contract is over a SPECIFIC expr+budget)
---------------------------------------------------------------------
The expression is the canonical triple-nested ``.map`` comprehension (10*10*10
inner iterations) and the budget is 8 -- the SAME pathological fixture the crate
native ``fuel_tests`` and the Python-host ``test_wsj_fuel_timeout.py`` use, so
every layer (native Rust, Python host, Node host) exhausts on the identical
fixture by construction.

All tests are tier-1 plumbing (offline, against the committed pinned wasm).
ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

# Repo root: this file lives at relay/tests/conformance/cel/test_*.py
REPO_ROOT = Path(__file__).resolve().parents[3]

# The Node cross-host harness that drives the FIXED fuel-exhausting expr+budget
# DIRECTLY through the wasm exports (bypassing the .mjs loader's in-flight fuel
# surface) and emits the raw envelope bytes as {len, sha256, hex, envelope_text}.
NODE_HARNESS = (
    REPO_ROOT
    / "packages"
    / "cel-wasm"
    / "conformance"
    / "harness"
    / "fuel_exhaustion_cross_host.mjs"
)

# The (gitignored) crate/target build -- the local-dev fallback when neither
# $CEL_WASM nor the committed package-data wasm is present.
CRATE_TARGET_WASM = (
    REPO_ROOT
    / "packages"
    / "cel-wasm"
    / "crate"
    / "target"
    / "wasm32-unknown-unknown"
    / "release"
    / "relay_cel_wasm.wasm"
)

# Make the canonical wasm resolver importable (relay_contracts IS installed
# editable; the explicit insert keeps the import robust to invocation cwd).
sys.path.insert(0, str(REPO_ROOT / "packages" / "contracts" / "src"))

from relay_contracts.wasm_artifact import (  # noqa: E402  -- after sys.path
    WASM_PINNED_SHA256,
    resolve_packaged_wasm_path,
    sha256_of_path,
)

# ---------------------------------------------------------------------------
# The FIXED fuel-exhaustion fixture (cross-host contract is over THIS expr+budget).
#
# A triple-nested .map comprehension (10*10*10 inner iterations) whose evaluated-
# node count far exceeds a budget of 8 -- the SAME PATHOLOGICAL_EXPR/Some(8) the
# crate native fuel_tests and test_wsj_fuel_timeout.py use, so every layer
# (native Rust, Python host, Node host) exhausts on the identical fixture.
# ---------------------------------------------------------------------------
PATHOLOGICAL_EXPR = (
    "[0,1,2,3,4,5,6,7,8,9].map(x, "
    "[0,1,2,3,4,5,6,7,8,9].map(y, "
    "[0,1,2,3,4,5,6,7,8,9].map(z, x + y + z)))"
)
EXHAUSTING_BUDGET = 8

# The cross-host (code, subtype) timeout contract -- MUST match the crate
# codes::TIMEOUT / subtypes::TIMEOUT and every host's fuel path.
TIMEOUT_CODE = "RELAY-CEL-003"
TIMEOUT_SUBTYPE = "RELAY-CEL-TIMEOUT-001"


def _wasm_path() -> str:
    """The wasm BOTH hosts load (the SAME bytes -- byte-parity is void otherwise).

    Resolution precedence:
      1. $CEL_WASM when set -- the explicit CI override.
      2. The COMMITTED, git-tracked PACKAGE-DATA wasm, resolved via the canonical
         resolver. Defense-in-depth: its sha256 MUST equal WASM_PINNED_SHA256, so
         a stale/tampered vendored wasm FAILS LOUD here rather than producing a
         misleading "parity" pass on the wrong bytes.
      3. The (gitignored) crate/target build -- a LOCAL-DEV fallback only.
    """
    override = os.environ.get("CEL_WASM")
    if override:
        return override
    packaged = resolve_packaged_wasm_path()
    if packaged is not None:
        actual = sha256_of_path(packaged)
        assert actual == WASM_PINNED_SHA256, (
            "VAL-CWC-P7EDGE-004: the committed package-data wasm at "
            f"{packaged} hashes to {actual}, NOT the pinned "
            f"{WASM_PINNED_SHA256}. Cross-host envelope parity on the wrong bytes "
            "would be a misleading pass; refusing to run on a stale/tampered wasm."
        )
        return str(packaged)
    return str(CRATE_TARGET_WASM)


def _python_fuel_envelope_bytes(wasm_path: str) -> bytes:
    """Drive the FIXED fuel-exhausting expr+budget through the Python wasmtime host
    and return the RAW envelope bytes EXACTLY as the wasm wrote them to linear
    memory (BEFORE any json.loads re-serialization).

    This marshals memory in/out through the wasm's own alloc/eval/dealloc exports
    -- the SAME marshaling the Python loader (relay_cel_wasm.py) performs -- with
    the fuel_budget field set directly on the request JSON. It instantiates with
    an empty import list ([]) (the no-WASI reactor; the fuel counter is in-wasm).
    Imported at call time so collection on a checkout without wasmtime/the wasm
    does not error at import.
    """
    from wasmtime import (  # noqa: PLC0415  -- runtime loader import (cel-wasm convention)
        Engine,
        Func,
        Instance,
        Memory,
        Module,
        Store,
    )

    engine = Engine()
    module = Module.from_file(engine, wasm_path)
    store = Store(engine)
    instance = Instance(store, module, [])
    exports = instance.exports(store)
    # cast() narrows the wasmtime export union (Func|Global|Memory|Table|...) for
    # the type checker; a runtime no-op, mirroring relay_cel_wasm.py:81-84.
    memory = cast(Memory, exports["memory"])
    alloc = cast(Func, exports["alloc"])
    eval_fn = cast(Func, exports["eval"])
    dealloc = cast(Func, exports["dealloc"])

    # The request JSON with the fuel_budget field set directly -- the field order
    # here does NOT affect the OUTPUT bytes (the wasm re-serializes its own
    # response), so this is purely the input the wasm parses.
    req = {"expr": PATHOLOGICAL_EXPR, "fuel_budget": EXHAUSTING_BUDGET}
    inp = json.dumps(req).encode("utf-8")
    n = len(inp)

    ptr = alloc(store, n)
    memory.write(store, inp, ptr)
    packed = eval_fn(store, ptr, n) & ((1 << 64) - 1)
    out_ptr = packed >> 32
    out_len = packed & 0xFFFFFFFF
    out = bytes(memory.read(store, out_ptr, out_ptr + out_len))
    dealloc(store, out_ptr, out_len)
    dealloc(store, ptr, n)
    return out


def _node_fuel_envelope(wasm_path: str) -> dict[str, Any]:
    """Invoke the Node fuel-exhaustion harness once and return its parsed JSON
    envelope ``{len, sha256, hex, envelope_text}`` (the raw wasm-emitted bytes
    captured on the Node host before JSON.parse).

    The harness fails LOUD (non-zero) on a missing wasm; a non-zero exit fails
    this test with the harness diagnostics rather than being silently tolerated
    (a silent skip would let a cross-host byte divergence ship undetected --
    keystone invariant #16)."""
    assert NODE_HARNESS.exists(), (
        f"VAL-CWC-P7EDGE-004: missing Node fuel-exhaustion harness at {NODE_HARNESS}."
    )
    env = dict(os.environ)
    env["CEL_WASM"] = wasm_path
    proc = subprocess.run(
        ["node", str(NODE_HARNESS)],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            "VAL-CWC-P7EDGE-004: Node fuel-exhaustion harness exited "
            f"{proc.returncode} (could not drive the fuel-exhausting expr through "
            "the .wasm). The harness fails loud on a missing wasm; build it via "
            "`make -C packages/cel-wasm build` or set $CEL_WASM.\n"
            f"  stderr: {proc.stderr[-3000:]}\n  stdout: {proc.stdout[-1500:]}"
        )
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        pytest.fail(
            "VAL-CWC-P7EDGE-004: Node fuel-exhaustion harness produced unparseable "
            f"output: {exc}\n  stdout: {proc.stdout[-2000:]}"
        )
    raise AssertionError("unreachable")  # pragma: no cover -- pytest.fail raises


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P7EDGE-004")
def test_python_fuel_exhaustion_envelope_is_a_relay_cel_003_timeout() -> None:
    """Guard: the Python-host raw envelope IS a fuel-exhaustion RELAY-CEL-003 /
    RELAY-CEL-TIMEOUT-001 timeout (ok==false), so the cross-host byte-identity
    assertion below is over a genuine TIMEOUT envelope and not a stale/success
    response that happened to match."""
    raw = _python_fuel_envelope_bytes(_wasm_path())
    parsed = json.loads(raw.decode("utf-8"))
    assert parsed.get("ok") is False, f"fuel exhaustion must fail the eval: {parsed}"
    assert parsed.get("code") == TIMEOUT_CODE, (
        f"fuel exhaustion must surface RELAY-CEL-003: {parsed}"
    )
    assert parsed.get("subtype") == TIMEOUT_SUBTYPE, (
        f"fuel exhaustion must carry the TIMEOUT subtype: {parsed}"
    )
    assert "value" not in parsed, f"a timeout envelope carries no value: {parsed}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P7EDGE-004")
def test_fuel_exhaustion_envelope_byte_identical_python_vs_node() -> None:
    """The CORE VAL-CWC-P7EDGE-004 assertion: for the FIXED fuel-exhausting
    expr+budget, the Python (wasmtime) host and the Node host -- both loading the
    SAME pinned wasm -- emit the BYTE-IDENTICAL serialized envelope (same key
    order, same code, same subtype, same message bytes). Compared at the RAW wire
    level (the exact bytes each host read out of wasm memory), so a divergence in
    the message text or key order -- which a code+subtype check would miss -- is
    caught here."""
    wasm = _wasm_path()

    # (a) Python host raw envelope bytes.
    py_bytes = _python_fuel_envelope_bytes(wasm)
    py_sha = hashlib.sha256(py_bytes).hexdigest()

    # (b) Node host raw envelope (the harness reports len, sha256, hex, text).
    node = _node_fuel_envelope(wasm)
    node_hex = node.get("hex")
    node_sha = node.get("sha256")
    node_len = node.get("len")
    node_text = node.get("envelope_text")
    assert isinstance(node_hex, str) and node_hex, (
        f"Node harness must report the raw envelope hex; got {node!r}"
    )
    node_bytes = bytes.fromhex(node_hex)

    # Byte-identity at every level: length, raw bytes, and sha256. Surface the
    # full decoded envelopes on divergence so the diff is self-explanatory.
    assert py_bytes == node_bytes, (
        "VAL-CWC-P7EDGE-004: fuel-exhaustion envelope BYTES diverge across hosts "
        "(BOTH load the SAME wasm, so ANY divergence is a host-marshalling P0).\n"
        f"  python ({len(py_bytes)} bytes): {py_bytes.decode('utf-8', 'replace')!r}\n"
        f"  node   ({len(node_bytes)} bytes): {node_bytes.decode('utf-8', 'replace')!r}"
    )
    assert py_sha == node_sha, (
        "VAL-CWC-P7EDGE-004: envelope sha256 diverges across hosts despite equal "
        f"bytes (impossible unless a host hashed differently): py={py_sha} "
        f"node={node_sha}"
    )
    assert len(py_bytes) == node_len, (
        f"VAL-CWC-P7EDGE-004: envelope length diverges: py={len(py_bytes)} "
        f"node={node_len}"
    )

    # The shared envelope MUST be the timeout (not a coincidentally-equal success):
    # both decode to the SAME RELAY-CEL-003 / RELAY-CEL-TIMEOUT-001 timeout, and
    # the harness's own decoded text matches the bytes it reported.
    shared = json.loads(py_bytes.decode("utf-8"))
    assert shared.get("code") == TIMEOUT_CODE and shared.get("subtype") == (
        TIMEOUT_SUBTYPE
    ), f"the byte-identical envelope must be the timeout: {shared}"
    assert node_text == py_bytes.decode("utf-8"), (
        "VAL-CWC-P7EDGE-004: the Node harness's reported envelope_text must equal "
        f"the shared envelope bytes; node_text={node_text!r}"
    )

    print(
        "[fuel-exhaustion-cross-host-envelope-parity] PASS: "
        f"len={len(py_bytes)}, sha256={py_sha}, "
        f"envelope={py_bytes.decode('utf-8')}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P7EDGE-004")
def test_byte_comparison_is_non_vacuous() -> None:
    """Negative control: the byte-identity comparison MUST detect a one-byte
    difference, so the zero-divergence pass above is a real assertion (not a
    vacuous one that would pass even if the two hosts produced different bytes)."""
    a = b'{"code":"RELAY-CEL-003","ok":false}'
    b = b'{"code":"RELAY-CEL-004","ok":false}'
    assert a != b, "comparator must detect a byte divergence (003 vs 004)"
    assert hashlib.sha256(a).hexdigest() != hashlib.sha256(b).hexdigest(), (
        "sha256 comparator must detect a byte divergence"
    )
    # And identical bytes compare equal (no spurious divergence).
    assert a == bytes(a)
    assert hashlib.sha256(a).hexdigest() == hashlib.sha256(bytes(a)).hexdigest()
