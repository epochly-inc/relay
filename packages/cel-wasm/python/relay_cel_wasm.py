"""Python loader for the relay-cel-wasm single CEL engine.

This is the OSS-portable Python entrypoint: load the SAME signed `.wasm` reactor
that the TS/edge runtime loads and evaluate CEL expressions over it. It is the
future replacement for the cel-python evaluation core (NOT wired into
packages/contracts yet -- that is a later work-stream).

Usage:
    from relay_cel_wasm import RelayCel
    cel = RelayCel()                 # loads the release wasm (or CEL_WASM)
    cel.eval("1 + 2")                # {"ok": True, "value": {"t":"int","v":"3"}}
    cel.eval("x > 0", {"x": {"t": "int", "v": "5"}})

Typed-canonical value form (the cross-host byte-parity contract; see
crate/src/lib.rs):
    int   {"t":"int","v":"<dec>"}     uint   {"t":"uint","v":"<dec>"}
    double{"t":"double","v":"<canon>"}string {"t":"string","v":"..."}
    bool  {"t":"bool","v":true|false} null   {"t":"null"}
    bytes {"t":"bytes","v":"<hex>"}   list   {"t":"list","v":[...]}
    map   {"t":"map","v":[[k,v],...]} (sorted)
    duration {"t":"duration","v":"<s.ns>"}  timestamp {"t":"timestamp","v":"<rfc3339 Z>"}

Errors surface as {"ok": False, "error": "<msg>", "code": "RELAY-CEL-NNN"}.
A wasm trap (which should not happen for in-profile inputs after the G1 fence)
is caught, the instance re-instantiated, and reported as ENGINE_PANIC.

A successful response that executed one or more relay.* UDFs also carries a
top-level `udf_trace` field (WS-B): an object mapping each executed UDF name
(relay.coverage / relay.tool_arg / relay.schema_match) to a LIST of its typed-
canonical return values in CALL ORDER, e.g.
    {"ok": True, "value": {"t":"bool","v":True},
     "udf_trace": {"relay.coverage": [{"t":"bool","v":True}]}}
A short-circuited (never-evaluated) UDF branch is NOT recorded, and the field is
ABSENT when no relay.* UDF executed. The M1 pipeline reconstructs
udf_outputs_jcs / udfs_invoked from this field on the wasm path. The field is
additive metadata: it never changes the eval `value`, and because both hosts
load the SAME .wasm it is byte-identical across hosts by construction.
"""
from __future__ import annotations

import json
import os
from typing import Any

from wasmtime import Engine, Instance, Module, Store, Trap

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_WASM = os.path.normpath(
    os.path.join(
        _HERE,
        "..",
        "crate",
        "target",
        "wasm32-unknown-unknown",
        "release",
        "relay_cel_wasm.wasm",
    )
)


class RelayCel:
    """A reusable handle over one wasm module. Not thread-safe (one Store);
    create one instance per thread, or pool them. A later embedding work-stream
    adds the per-thread Store pool + signature verification."""

    def __init__(self, wasm_path: str | None = None):
        path = wasm_path or os.environ.get("CEL_WASM", _DEFAULT_WASM)
        self._engine = Engine()
        self._module = Module.from_file(self._engine, path)
        self._reinit()

    def _reinit(self) -> None:
        self._store = Store(self._engine)
        self._instance = Instance(self._store, self._module, [])
        ex = self._instance.exports(self._store)
        self._memory = ex["memory"]
        self._alloc = ex["alloc"]
        self._eval = ex["eval"]
        self._dealloc = ex["dealloc"]

    def eval(
        self,
        expr: str,
        bindings: dict[str, Any] | None = None,
        container: str | None = None,
        relay_profile: bool = False,
    ) -> dict[str, Any]:
        """Evaluate `expr` with optional typed `bindings` and an optional CEL
        resolution `container` (namespace, e.g. "com.example"). Always returns a
        dict (never raises for evaluation errors): success carries `value`,
        failure carries `error` + `code` (+ `subtype` for profile rejections).

        `relay_profile=True` turns on the Relay CEL profile's call-level
        restrictions: dyn()/timestamp()/duration() global calls are rejected
        with RELAY-CEL-002 and the matching subtype. The Relay host wrapper sets
        this; the cel-spec conformance harness leaves it off."""
        req: dict[str, Any] = {"expr": expr}
        if bindings:
            req["bindings"] = bindings
        if container:
            req["container"] = container
        if relay_profile:
            req["relay_profile"] = True
        inp = json.dumps(req).encode("utf-8")
        n = len(inp)
        try:
            ptr = self._alloc(self._store, n)
            self._memory.write(self._store, inp, ptr)
            packed = self._eval(self._store, ptr, n) & ((1 << 64) - 1)
            out_ptr = packed >> 32
            out_len = packed & 0xFFFFFFFF
            data = bytes(
                self._memory.read(self._store, out_ptr, out_ptr + out_len)
            )
            self._dealloc(self._store, out_ptr, out_len)
            self._dealloc(self._store, ptr, n)
            return json.loads(data.decode("utf-8"))
        except Trap as t:
            self._reinit()
            return {
                "ok": False,
                "error": "ENGINE_PANIC",
                "code": "RELAY-CEL-PANIC",
                "trap": str(t).splitlines()[0],
            }


if __name__ == "__main__":
    cel = RelayCel()
    # "size('\u00ff')" stays ASCII in source; the CEL string is U+00FF at runtime.
    for e in ["1 + 2", "dyn(1)", "double(1e12)", "size('\u00ff')", "Foo{a: 1}"]:
        print(e, "=>", json.dumps(cel.eval(e)))
