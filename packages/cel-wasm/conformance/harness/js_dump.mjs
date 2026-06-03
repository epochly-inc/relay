// Cross-host byte-parity check (Node side): evaluate every in-scope corpus expr
// (+bindings) through the SAME wasm under Node's WebAssembly.instantiate,
// dumping raw output bytes as hex per record. Compared byte-for-byte against
// py_dump.py. A diff is a P0 (the ADR keystone is byte-identical Py<->TS).
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const WASM =
  process.env.CEL_WASM ||
  normalize(
    join(
      HERE,
      "..",
      "..",
      "crate",
      "target",
      "wasm32-unknown-unknown",
      "release",
      "relay_cel_wasm.wasm",
    ),
  );
const ORACLE = process.env.ORACLE_RECORDS || join(HERE, "oracle_records.jsonl");
const OUT = process.env.JS_DUMP || join(HERE, "js_dump.txt");

const bytes = readFileSync(WASM);
let { instance } = await WebAssembly.instantiate(bytes, {});
let { memory, alloc, eval: evalFn, dealloc } = instance.exports;
const enc = new TextEncoder();

async function reinit() {
  ({ instance } = await WebAssembly.instantiate(bytes, {}));
  ({ memory, alloc, eval: evalFn, dealloc } = instance.exports);
}

async function evalHex(expr, bindings) {
  const req = bindings ? { expr, bindings } : { expr };
  const inp = enc.encode(JSON.stringify(req));
  const n = inp.length;
  try {
    const ptr = alloc(n);
    new Uint8Array(memory.buffer, ptr, n).set(inp);
    let packed = BigInt.asUintN(64, evalFn(ptr, n));
    const outPtr = Number(packed >> 32n);
    const outLen = Number(packed & 0xffffffffn);
    const out = new Uint8Array(memory.buffer.slice(outPtr, outPtr + outLen));
    dealloc(outPtr, outLen);
    dealloc(ptr, n);
    return Buffer.from(out).toString("hex");
  } catch (e) {
    await reinit();
    return "PANIC";
  }
}

const records = readFileSync(ORACLE, "utf-8")
  .trim()
  .split("\n")
  .map((l) => JSON.parse(l));

const out = [];
for (const r of records) {
  const hex = await evalHex(r.expr, r.bindings);
  out.push(hex);
}
writeFileSync(OUT, out.join("\n") + "\n");
console.log("JS dumped", out.length, "records ->", OUT);
