// W17.3 cel-js subprocess runner (VAL-W17-012).
//
// Spawned by pytest in tests/conformance/cel-spec/test_w17_3_celspec_corpus.py
// to drive cel-js across the profile-included vector set. Reads a JSON
// payload from stdin of the form:
//   {"vectors": [{"vector_id": "...", "expression": "...", "bindings": {...}, "expected_value": ...}, ...]}
// Writes a JSON payload to stdout of the form:
//   {"results": [{"vector_id": "...", "ok": true|false, "value": <any>|null, "error": <str>|null}, ...]}
//
// Per-vector failure is reported in the `ok=false` record; runner-level
// failure (parse error, cel-js import failure) exits non-zero with a
// human-readable message on stderr.
//
// This file is a test-only helper. Per CLAUDE.md "no mocks in non-test
// paths", it lives under packages/contracts-typescript/test/ and is
// NOT included in the published npm tarball (the package's `files`
// array names only `dist`, `src`, `README.md`).
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { evaluate } from "cel-js";

async function readAllStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf-8");
}

function normaliseValue(v) {
  // cel-js returns JSON-compatible values (numbers, booleans, strings,
  // arrays, plain objects). Convert undefined -> null for stable
  // JSON.stringify output; the Python comparator treats both as
  // "absent value" but null round-trips cleanly through JSON.
  if (v === undefined) return null;
  if (Array.isArray(v)) return v.map(normaliseValue);
  if (v !== null && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v).sort()) {
      out[k] = normaliseValue(v[k]);
    }
    return out;
  }
  return v;
}

async function main() {
  let payloadText;
  try {
    payloadText = await readAllStdin();
  } catch (e) {
    process.stderr.write(`RELAY-W17-3-CELJS-STDIN-READ-FAIL: ${e.message}\n`);
    process.exit(2);
  }

  let payload;
  try {
    payload = JSON.parse(payloadText);
  } catch (e) {
    process.stderr.write(
      `RELAY-W17-3-CELJS-PAYLOAD-PARSE-FAIL: ${e.message}\n`,
    );
    process.exit(2);
  }

  if (!payload || !Array.isArray(payload.vectors)) {
    process.stderr.write(
      "RELAY-W17-3-CELJS-PAYLOAD-SHAPE: expected {vectors: [...]}\n",
    );
    process.exit(2);
  }

  const results = [];
  for (const vec of payload.vectors) {
    const vid = vec.vector_id;
    const expr = vec.expression;
    const bindings = vec.bindings || {};
    if (typeof expr !== "string") {
      results.push({
        vector_id: vid,
        ok: false,
        value: null,
        error: "vector missing 'expression' string field",
      });
      continue;
    }
    try {
      const raw = evaluate(expr, bindings, {});
      results.push({
        vector_id: vid,
        ok: true,
        value: normaliseValue(raw),
        error: null,
      });
    } catch (e) {
      results.push({
        vector_id: vid,
        ok: false,
        value: null,
        error: `${e && e.name ? e.name : "Error"}: ${e && e.message ? e.message : String(e)}`,
      });
    }
  }

  process.stdout.write(JSON.stringify({ results }));
}

main().catch((e) => {
  process.stderr.write(`RELAY-W17-3-CELJS-RUNNER-CRASH: ${e.stack || e.message || String(e)}\n`);
  process.exit(2);
});
