"""Thin wasmtime-py loader exposing relay-cel-wasm typed evaluation.

evaluate(expr, bindings=None) -> dict:
  {"ok": True,  "value": <typed-canonical-value>}            on success
  {"ok": False, "error": "<msg>", "code": "RELAY-CEL-NNN"}   on engine error

The typed-canonical-value form is the one emitted by crate/src/lib.rs
value_to_typed. A wasm trap (a Rust panic under panic="abort") poisons the
Store, so we re-instantiate and surface a structured ENGINE_PANIC marker --
a panic is itself a conformance finding. After the G1 fence, struct/message
construction returns a clean RELAY-CEL-002 error instead of trapping, so an
ENGINE_PANIC from a profile-rejected input is now a regression.
"""
import json
import os

from wasmtime import Engine, Instance, Module, Store, Trap

# Default to the repo's release wasm; override with CEL_WASM for a signed
# artifact or an alternate build.
_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_WASM = os.path.normpath(
    os.path.join(
        _HERE,
        "..",
        "..",
        "crate",
        "target",
        "wasm32-unknown-unknown",
        "release",
        "relay_cel_wasm.wasm",
    )
)
WASM = os.environ.get("CEL_WASM", _DEFAULT_WASM)

_engine = Engine()
_module = Module.from_file(_engine, WASM)


class WasmCel:
    def __init__(self):
        self._reinit()

    def _reinit(self):
        self.store = Store(_engine)
        self.instance = Instance(self.store, _module, [])
        ex = self.instance.exports(self.store)
        self.memory = ex["memory"]
        self.alloc = ex["alloc"]
        self.eval_fn = ex["eval"]
        self.dealloc = ex["dealloc"]

    def _evaluate_raw(self, expr, bindings=None):
        req = {"expr": expr}
        if bindings:
            req["bindings"] = bindings
        inp = json.dumps(req).encode("utf-8")
        n = len(inp)
        ptr = self.alloc(self.store, n)
        self.memory.write(self.store, inp, ptr)
        packed = self.eval_fn(self.store, ptr, n)
        packed &= (1 << 64) - 1
        out_ptr = packed >> 32
        out_len = packed & 0xFFFFFFFF
        data = bytes(self.memory.read(self.store, out_ptr, out_ptr + out_len))
        self.dealloc(self.store, out_ptr, out_len)
        self.dealloc(self.store, ptr, n)
        return json.loads(data.decode("utf-8"))

    def evaluate(self, expr, bindings=None):
        try:
            return self._evaluate_raw(expr, bindings)
        except Trap as t:
            self._reinit()
            return {
                "ok": False,
                "error": "ENGINE_PANIC",
                "trap": str(t).splitlines()[0],
            }


_default = None


def evaluate(expr, bindings=None):
    global _default
    if _default is None:
        _default = WasmCel()
    return _default.evaluate(expr, bindings)


if __name__ == "__main__":
    smoke = [
        "1 + 2",
        "1.0 == 1",
        "dyn(1) == dyn(1u)",
        "double(1000000000000)",
        "size('\u00ff')",
        "bytes(b'abc')",
        "timestamp('2009-02-13T23:31:30Z')",
        "google.protobuf.BoolValue{value: true}",  # G1 fence -> clean error
        "Foo{a: 1}",  # G1 fence -> clean error
    ]
    for e in smoke:
        print(e, "=>", json.dumps(evaluate(e)))
