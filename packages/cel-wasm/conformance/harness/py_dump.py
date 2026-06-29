"""Cross-host byte-parity check (Python side): evaluate every in-scope corpus
expr (+bindings) through the SAME wasm under wasmtime-py, dumping raw output
bytes as hex per record. Compared byte-for-byte against js_dump.mjs.

This is the ADR keystone tripwire: with one engine in one wasm, Python and the
TS/edge runtime MUST produce byte-identical output. A diff is a P0."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_eval import WasmCel  # noqa: E402
from wasmtime import Trap  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.environ.get("ORACLE_RECORDS", os.path.join(_HERE, "oracle_records.jsonl"))
OUT = os.environ.get("PY_DUMP", os.path.join(_HERE, "py_dump.txt"))


def main():
    engine = WasmCel()
    with open(ORACLE) as oracle_fh:
        records = [json.loads(line) for line in oracle_fh]
    lines = []
    for r in records:
        bindings = r.get("bindings")
        req = {"expr": r["expr"]}
        if bindings:
            req["bindings"] = bindings
        container = r.get("container")
        if container:
            req["container"] = container
        inp = json.dumps(req).encode("utf-8")
        n = len(inp)
        try:
            ptr = engine.alloc(engine.store, n)
            engine.memory.write(engine.store, inp, ptr)
            packed = engine.eval_fn(engine.store, ptr, n) & ((1 << 64) - 1)
            out_ptr = packed >> 32
            out_len = packed & 0xFFFFFFFF
            data = bytes(engine.memory.read(engine.store, out_ptr, out_ptr + out_len))
            engine.dealloc(engine.store, out_ptr, out_len)
            engine.dealloc(engine.store, ptr, n)
            lines.append(data.hex())
        except Trap:
            engine._reinit()
            lines.append("PANIC")
    with open(OUT, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("PY dumped", len(lines), "records ->", OUT)


if __name__ == "__main__":
    main()
