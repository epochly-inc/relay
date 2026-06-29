"""Conformance comparison: relay-cel-wasm vs cel-spec textproto ground truth.

Reads oracle_records.jsonl (produced by the Go oracle: textproto-expected +
cel-go reference, both normalized to the typed-canonical form). For each record:

  - Drives the expr (+bindings) through relay-cel-wasm (harness/wasm_eval.py).
  - Compares relay-cel-wasm output to the textproto EXPECTED (ground truth).
  - Also records cel-go-vs-textproto agreement (oracle faithfulness check).

Outputs (paths overridable via env):
  - RESULTS (results.jsonl) : per-test verdict (pass/fail/skip + outputs + category)
  - SUMMARY (summary.json)  : machine-readable summary for the conformance gate:
      passed/measured/% (raw + ex-proto), per-file, oracle faithfulness,
      failure-category histogram + representative examples, and the
      proto-message / dyn feature-class splits used in the WS1 report.
  - A printed human summary.

Comparison semantics:
  - expected_kind in {"value","typed_value"}: wasm must return ok=True and a
    typed value byte-equal to expected_typed.
  - expected_kind in {"error","any_errors"}: wasm must return ok=False.
  - expected_kind in {"unknown","unsupported"}: SKIPPED (not measured).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wasm_eval import WasmCel  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.environ.get(
    "ORACLE_RECORDS", os.path.join(_HERE, "oracle_records.jsonl")
)
RESULTS = os.environ.get("RESULTS", os.path.join(_HERE, "results.jsonl"))
SUMMARY = os.environ.get("SUMMARY", os.path.join(_HERE, "summary.json"))


def canon(v):
    """Stable canonical string for a typed value (for byte comparison)."""
    return json.dumps(v, sort_keys=True, separators=(",", ":"))


def is_proto_case(record):
    """A proto-message case: the expression constructs/accesses a protobuf
    message. cel-rust 0.13 has no message model; the WS1 brief scopes these
    out. We detect them so the ex-proto number can be reported separately."""
    expr = record.get("expr", "")
    markers = (
        "google.protobuf.",
        "TestAllTypes",
        ".single_",
        ".repeated_",
        ".map_",
        "NestedTestAllTypes",
        "NullValue",
    )
    if any(m in expr for m in markers):
        return True
    # A struct/message literal anywhere: Name{...} with a dotted or capitalized
    # type. The wasm reports these as RELAY-CEL-002 PROFILE-STRUCT-DISABLED.
    rust = record.get("rust") or {}
    return rust.get("code") == "RELAY-CEL-002"


def is_dyn_case(record):
    return "dyn(" in record.get("expr", "")


def categorize(record, rust):
    """Assign a coarse failure category to a relay-cel-wasm mismatch."""
    exp_kind = record["expected_kind"]
    rust_ok = rust.get("ok") is True
    rust_err = rust.get("error", "") if not rust_ok else ""
    exp_typed = record.get("expected_typed")
    rust_val = rust.get("value")

    if exp_kind in ("error", "any_errors"):
        if rust_ok:
            return "error_expected_got_value"
        return "ok"

    if not rust_ok:
        e = rust_err
        if "ENGINE_PANIC" in e:
            return "engine_panic"
        if rust.get("code") == "RELAY-CEL-002":
            return "profile_rejected_struct"
        if "UndeclaredReference" in e:
            return "missing_builtin_or_function"
        if "Overflow" in e:
            return "integer_overflow_is_error"
        if "NoSuchOverload" in e:
            return "missing_overload"
        if "compile:" in e or "parse" in e.lower():
            return "parse_compile_failure"
        if "DivisionByZero" in e or "Modulo" in e:
            return "div_mod_semantics"
        if "binding" in e.lower():
            return "binding_unsupported"
        return "other_engine_error:" + e.split("(")[0][:40]

    et = exp_typed.get("t") if isinstance(exp_typed, dict) else None
    rt = rust_val.get("t") if isinstance(rust_val, dict) else None
    if et != rt:
        if {et, rt} <= {"int", "uint", "double"}:
            return "numeric_type_mismatch"
        return f"type_mismatch:{et}->{rt}"
    if et == "double":
        return "double_format_mismatch"
    if et == "map":
        return "map_value_mismatch"
    if et == "string":
        return "string_value_mismatch"
    if et == "bool":
        return "cross_numeric_equality_or_bool"
    return f"value_mismatch:{et}"


def main():
    engine = WasmCel()
    with open(ORACLE) as oracle_fh:
        records = [json.loads(line) for line in oracle_fh]

    # Accumulate per-record result lines and flush them to RESULTS once at the
    # end (single context-managed write). Order is preserved, so the RESULTS
    # file is byte-identical to the prior incremental writes.
    result_lines: list[str] = []
    summary = {"total": 0, "measured": 0, "passed": 0, "failed": 0, "skipped": 0}
    # ex-proto view: measured/passed excluding proto-message cases.
    exproto = {"measured": 0, "passed": 0}
    per_file = {}
    oracle_faithful = {"agree": 0, "disagree": 0, "na": 0}
    fail_categories = {}
    fail_examples = {}
    feature_split = {"proto_message": 0, "dyn": 0, "cel_core": 0}

    for r in records:
        summary["total"] += 1
        f = r["file"]
        pf = per_file.setdefault(
            f, {"measured": 0, "passed": 0, "failed": 0, "skipped": 0}
        )

        exp_kind = r["expected_kind"]

        if exp_kind in ("unknown", "unsupported"):
            summary["skipped"] += 1
            pf["skipped"] += 1
            r["verdict"] = "skip"
            r["skip_why"] = r.get("skip_reason") or exp_kind
            result_lines.append(canon(r) + "\n")
            continue

        # Oracle faithfulness.
        if exp_kind in ("value", "typed_value"):
            if r["celgo_kind"] == "value" and r.get("celgo_typed") is not None:
                if canon(r["celgo_typed"]) == canon(r["expected_typed"]):
                    oracle_faithful["agree"] += 1
                else:
                    oracle_faithful["disagree"] += 1
            else:
                oracle_faithful["disagree"] += 1
        elif exp_kind in ("error", "any_errors"):
            if r["celgo_kind"] == "error":
                oracle_faithful["agree"] += 1
            else:
                oracle_faithful["disagree"] += 1
        else:
            oracle_faithful["na"] += 1

        # Drive relay-cel-wasm.
        bindings = r.get("bindings")
        container = r.get("container") or None
        rust = engine.evaluate(r["expr"], bindings, container)
        r["rust"] = rust

        summary["measured"] += 1
        pf["measured"] += 1

        proto = is_proto_case(r)
        if not proto:
            exproto["measured"] += 1

        ok = False
        if exp_kind in ("value", "typed_value"):
            if rust.get("ok") is True and canon(rust.get("value")) == canon(
                r["expected_typed"]
            ):
                ok = True
        elif exp_kind in ("error", "any_errors") and rust.get("ok") is False:
            ok = True

        if ok:
            summary["passed"] += 1
            pf["passed"] += 1
            r["verdict"] = "pass"
            if not proto:
                exproto["passed"] += 1
        else:
            summary["failed"] += 1
            pf["failed"] += 1
            r["verdict"] = "fail"
            cat = categorize(r, rust)
            r["fail_category"] = cat
            fail_categories[cat] = fail_categories.get(cat, 0) + 1
            # feature-class split over failures
            if proto:
                feature_split["proto_message"] += 1
            elif is_dyn_case(r):
                feature_split["dyn"] += 1
            else:
                feature_split["cel_core"] += 1
            if cat not in fail_examples:
                fail_examples[cat] = {
                    "file": f,
                    "name": r["name"],
                    "expr": r["expr"],
                    "expected": r.get("expected_typed")
                    if exp_kind in ("value", "typed_value")
                    else f"<{exp_kind}>",
                    "rust": rust,
                    "celgo": r.get("celgo_typed")
                    if r["celgo_kind"] == "value"
                    else f"<error:{r.get('celgo_error','')[:40]}>",
                }
        result_lines.append(canon(r) + "\n")

    with open(RESULTS, "w") as out:
        out.writelines(result_lines)

    # ---- Print summary ----
    print("=" * 72)
    print("RELAY-CEL-WASM vs CEL-SPEC CONFORMANCE (typed value model)")
    print("=" * 72)
    m = summary["measured"]
    p = summary["passed"]
    pct = (100.0 * p / m) if m else 0.0
    em = exproto["measured"]
    ep = exproto["passed"]
    epct = (100.0 * ep / em) if em else 0.0
    print(f"\nHEADLINE (RAW)      : {p} / {m} measured pass = {pct:.1f}%")
    print(f"HEADLINE (EX-PROTO) : {ep} / {em} measured pass = {epct:.1f}%")
    print(f"  total corpus records (in-scope files): {summary['total']}")
    print(f"  skipped (unknown/unsupported/typecheck): {summary['skipped']}")

    of = oracle_faithful
    of_total = of["agree"] + of["disagree"]
    of_pct = (100.0 * of["agree"] / of_total) if of_total else 0.0
    print(
        f"\nOracle faithfulness (cel-go vs textproto): "
        f"{of['agree']}/{of_total} agree = {of_pct:.1f}%  "
        f"(disagree={of['disagree']})"
    )

    print("\nPer-file (measured / passed / failed / skipped):")
    for f in sorted(per_file):
        d = per_file[f]
        fp = (100.0 * d["passed"] / d["measured"]) if d["measured"] else 0.0
        print(
            f"  {f:16s} {d['measured']:5d} / {d['passed']:5d} / "
            f"{d['failed']:5d} / {d['skipped']:5d}   ({fp:5.1f}%)"
        )

    print("\nFailure feature-class split:")
    for k, v in feature_split.items():
        print(f"  {v:5d}  {k}")

    print("\nFailure categories (count):")
    for cat in sorted(fail_categories, key=lambda c: -fail_categories[c]):
        print(f"  {fail_categories[cat]:5d}  {cat}")

    print("\nRepresentative failing examples per category:")
    for cat in sorted(fail_categories, key=lambda c: -fail_categories[c]):
        ex = fail_examples[cat]
        print(f"\n  [{cat}]  ({fail_categories[cat]} cases)")
        print(f"    file/name : {ex['file']} / {ex['name']}")
        print(f"    expr      : {ex['expr']}")
        print(f"    expected  : {ex['expected']}")
        print(f"    relay-wasm: {ex['rust']}")
        print(f"    cel-go    : {ex['celgo']}")

    with open(SUMMARY, "w") as fh:
        json.dump(
            {
                "summary": summary,
                "headline_raw_pct": pct,
                "headline_exproto": exproto,
                "headline_exproto_pct": epct,
                "per_file": per_file,
                "oracle_faithful": oracle_faithful,
                "feature_split": feature_split,
                "fail_categories": fail_categories,
                "fail_examples": fail_examples,
            },
            fh,
            indent=2,
        )
    print(f"\nWrote {RESULTS} and {SUMMARY}")


if __name__ == "__main__":
    main()
