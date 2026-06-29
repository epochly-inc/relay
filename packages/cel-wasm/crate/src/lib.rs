// relay-cel-wasm: the single Relay CEL engine, compiled to a
// wasm32-unknown-unknown reactor (no WASI, no Emscripten).
//
// ABI (the reactor surface; both the Python wasmtime loader and the TS/edge
// loader hand-write glue against exactly these three exports + `memory`):
//   alloc(size: usize) -> ptr           : allocate `size` bytes of linear memory
//   eval(ptr: *const u8, len: usize)    : evaluate the UTF-8 JSON request at
//        -> u64 packed (out_ptr<<32|out_len)  [ptr,ptr+len); returns a freshly
//                                             alloc'd UTF-8 JSON response. The
//                                             CALLER MUST dealloc(out_ptr,out_len)
//                                             AND dealloc(ptr,len).
//   dealloc(ptr: *mut u8, size: usize)  : free a prior allocation
//
// Input  (UTF-8 JSON): {"expr": "<CEL>"}  OR  {"expr": "<CEL>", "bindings": {<name>: <typed-value>, ...}}
//   where <typed-value> is the SAME typed canonical form this module emits.
// Output (UTF-8 JSON):
//   success: {"ok": true,  "value": <typed-canonical-value>}
//   error  : {"ok": false, "error": "<msg>", "code": "RELAY-CEL-NNN"}
//
// Typed canonical value form (so int/uint/double are distinguishable and map
// order is fixed -- this is the cross-host byte-parity contract):
//   int       -> {"t":"int","v":"<decimal i64 as string>"}
//   uint      -> {"t":"uint","v":"<decimal u64 as string>"}
//   double    -> {"t":"double","v":"<CEL canonical f64, or 'inf'/'-inf'/'nan'>"}
//   string    -> {"t":"string","v":"<utf8>"}
//   bool      -> {"t":"bool","v":true|false}
//   null      -> {"t":"null"}
//   bytes     -> {"t":"bytes","v":"<lowercase hex>"}
//   list      -> {"t":"list","v":[<typed-value>, ...]}            (order preserved)
//   map       -> {"t":"map","v":[[<typed-key>,<typed-value>], ...]} (sorted by canonical key string)
//   duration  -> {"t":"duration","v":"<seconds.nanos as decimal string>"}
//   timestamp -> {"t":"timestamp","v":"<RFC3339, 'Z' UTC offset>"}
//
// Relay-specific behavior authored ONCE here (so it is byte-identical by
// construction across hosts): the proto/struct profile fence (G1), the
// conformance shims (G2 dyn, G9/G14 double/timestamp formatting, G11 code-point
// size, G12 idempotent conversions, G3 type()/type identifiers on top of the
// fork's Value::Type), and the structured error envelope. The engine-internal
// halves of the HARD semantic gaps live in the vendored fork (G6 cross-numeric
// equality, G3 the Value::Type model + qualified-name resolution); the
// remaining HARD gaps (G4 macros2, G5/G7/G8 lexer) are still fork work -- see
// HARDENING.md.

use std::alloc::{alloc as sys_alloc, dealloc as sys_dealloc, Layout};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use cel::common::ast::{EntryExpr, Expr, IdedExpr};
use cel::extractors::This;
use cel::objects::{Key, Map};
use cel::{Context, ExecutionError, Program, Value};
use serde_json::{json, Value as J};

// ---------------------------------------------------------------------------
// Reactor ABI
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    if size == 0 {
        return std::ptr::null_mut();
    }
    unsafe { sys_alloc(Layout::from_size_align_unchecked(size, 1)) }
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    unsafe { sys_dealloc(ptr, Layout::from_size_align_unchecked(size, 1)) }
}

#[no_mangle]
pub extern "C" fn eval(ptr: *const u8, len: usize) -> u64 {
    let input = unsafe { std::slice::from_raw_parts(ptr, len) };
    let out = eval_impl(input);
    let out_len = out.len();
    let out_ptr = alloc(out_len);
    unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), out_ptr, out_len) };
    ((out_ptr as u64) << 32) | (out_len as u64)
}

// ---------------------------------------------------------------------------
// Relay CEL profile error envelope
// ---------------------------------------------------------------------------

/// Relay structured error codes (subset; aligned with packages/contracts errors.py).
mod codes {
    /// Parse / compile failure (malformed CEL).
    pub const COMPILE: &str = "RELAY-CEL-001";
    /// Relay CEL profile rejection (a construct the profile disables).
    pub const PROFILE: &str = "RELAY-CEL-002";
    /// WS-J: the per-eval deterministic fuel/step budget was exhausted -- a
    /// portable, in-engine timeout. Distinct from a wall-clock host timeout: it
    /// is produced by the in-wasm fuel counter (no host clock), so a
    /// Cloudflare-Workers-shaped path (no worker_threads / Worker.terminate) can
    /// still emit a structured timeout byte-identically across hosts.
    pub const TIMEOUT: &str = "RELAY-CEL-003";
    /// Runtime execution error (overload missing, division by zero, etc.).
    pub const EXEC: &str = "RELAY-CEL-004";
    /// Malformed request envelope (bad JSON, missing expr, bad binding).
    pub const REQUEST: &str = "RELAY-CEL-006";
}

/// Profile-rejection subtypes (the `(code, subtype)` cross-runtime contract;
/// aligned with packages/contracts errors.py SUBTYPE_PROFILE_*). Emitting a
/// structured `subtype` lets the host map a RELAY-CEL-002 to the right
/// RelayCelProfileError without parsing the message string.
mod subtypes {
    pub const STRUCT: &str = "RELAY-CEL-PROFILE-STRUCT-DISABLED";
    pub const DYN: &str = "RELAY-CEL-PROFILE-DYN-DISABLED";
    pub const TS: &str = "RELAY-CEL-PROFILE-TS-DISABLED";
    pub const DUR: &str = "RELAY-CEL-PROFILE-DUR-DISABLED";
    /// WS-J: the (code, subtype) pair for a fuel-budget exhaustion -- the
    /// in-engine timeout. Pairs with codes::TIMEOUT (RELAY-CEL-003) so the host
    /// maps it to the typed RelayCelTimeoutError without parsing the message.
    pub const TIMEOUT: &str = "RELAY-CEL-TIMEOUT-001";
}

struct CelError {
    code: &'static str,
    message: String,
    subtype: Option<&'static str>,
}

impl CelError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        CelError {
            code,
            message: message.into(),
            subtype: None,
        }
    }

    /// A profile rejection (RELAY-CEL-002) carrying a structured subtype.
    fn profile(message: impl Into<String>, subtype: &'static str) -> Self {
        CelError {
            code: codes::PROFILE,
            message: message.into(),
            subtype: Some(subtype),
        }
    }

    /// WS-J: a fuel-budget exhaustion (RELAY-CEL-003) carrying the structured
    /// TIMEOUT subtype, so the host maps (code, subtype) -> RelayCelTimeoutError
    /// without parsing the message string. This is the dedicated mapping for the
    /// engine's deterministic in-wasm timeout; it must NOT be folded into the
    /// generic EXEC (RELAY-CEL-004) path.
    fn timeout(message: impl Into<String>) -> Self {
        CelError {
            code: codes::TIMEOUT,
            message: message.into(),
            subtype: Some(subtypes::TIMEOUT),
        }
    }
}

// ---------------------------------------------------------------------------
// WS-B: UDF execution trace (the udf_trace response field)
//
// Each EXECUTED relay.* UDF records its typed-canonical return value here, in
// CALL ORDER. eval_impl CLEARS this first (so a prior eval on the same thread
// never leaks), runs the program, then DRAINS this into a `udf_trace` response
// field keyed per UDF name. The host (M1 pipeline) reconstructs `udf_outputs_jcs`
// + `udfs_invoked` from it.
//
// DETERMINISM (or `make repro`/byte-parity break): the trace is an ORDER-
// PRESERVING Vec<(name, typed_value)> drained in insertion (call) order, never a
// HashMap iterated for the field. A short-circuited (`&&`/`||`/ternary) UDF
// branch is never CALLED, so recording in the function body's return path
// naturally records nothing for it. `udf_trace` is ADDITIVE metadata: it never
// changes the eval RESULT value and (both hosts load the SAME .wasm) is byte-
// identical across hosts by construction.
// ---------------------------------------------------------------------------

thread_local! {
    /// Per-thread, order-preserving record of (udf_name, typed-canonical value)
    /// for every relay.* UDF that EXECUTED during the current eval. Cleared at
    /// the start of eval_impl; drained at the end into the response.
    static UDF_TRACE: RefCell<Vec<(&'static str, J)>> = const { RefCell::new(Vec::new()) };
}

/// Clear the per-thread UDF trace. Called first in eval_impl so a prior eval on
/// the same thread (or a host wall-clock timeout that orphaned a worker thread)
/// never leaks entries into the next eval.
fn udf_trace_clear() {
    UDF_TRACE.with(|t| t.borrow_mut().clear());
}

/// Record one executed relay.* UDF's return value (typed-canonical) in call
/// order. `name` is the static dotted CEL name; `value` is the UDF's result,
/// serialized through the SAME value_to_typed serializer the response uses.
fn udf_trace_record(name: &'static str, value: &Value) {
    let typed = value_to_typed(value);
    UDF_TRACE.with(|t| t.borrow_mut().push((name, typed)));
}

/// Drain the per-thread trace into the `udf_trace` response object: a per-name
/// list of typed-canonical entries in CALL ORDER. Built by appending to an
/// order-preserving Vec keyed by first-seen name, so iteration order is
/// deterministic (call order), never HashMap iteration order. Returns None when
/// no relay.* UDF executed (so a non-UDF eval omits the field entirely).
fn udf_trace_drain() -> Option<J> {
    UDF_TRACE.with(|t| {
        let entries = t.borrow_mut().drain(..).collect::<Vec<(&'static str, J)>>();
        if entries.is_empty() {
            return None;
        }
        // Group by UDF name into per-name lists, each in CALL ORDER (the Vec was
        // already in call order; pushing in iteration order preserves it). The
        // per-name call-order list is the load-bearing contract: the host (M1
        // pipeline) reconstructs udf_outputs_jcs per-name in call order from it.
        //
        // serde_json::Map here is a BTreeMap (preserve_order is NOT enabled, and
        // is deliberately left off so the rest of the crate's response/value byte
        // layout is unchanged), so the OBJECT KEYS emit in a fixed alphabetical
        // order. That is fully DETERMINISTIC run-to-run -- repro and cross-host
        // byte-parity hold -- and does not perturb the per-name call-order lists.
        let mut obj = serde_json::Map::new();
        for (name, value) in entries {
            match obj.get_mut(name) {
                Some(J::Array(list)) => list.push(value),
                _ => {
                    obj.insert(name.to_string(), J::Array(vec![value]));
                }
            }
        }
        Some(J::Object(obj))
    })
}

// ---------------------------------------------------------------------------
// eval pipeline
// ---------------------------------------------------------------------------

fn eval_impl(input: &[u8]) -> Vec<u8> {
    // Clear the per-thread UDF trace FIRST, before any UDF can run, so a prior
    // eval (or an orphaned worker thread) never leaks entries into this one.
    udf_trace_clear();
    let result = (|| -> Result<J, CelError> {
        let req: J = serde_json::from_slice(input)
            .map_err(|e| CelError::new(codes::REQUEST, e.to_string()))?;
        let expr = req
            .get("expr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CelError::new(codes::REQUEST, "missing 'expr'"))?;

        let program = Program::compile(expr)
            .map_err(|e| CelError::new(codes::COMPILE, format!("compile: {e:?}")))?;

        // `relay_profile` (default false) turns ON the Relay CEL profile's
        // call-level restrictions: dyn()/timestamp()/duration() global CALLS are
        // rejected (the host's _check_profile does this at compile). It is
        // FLAG-GATED because the cel-spec conformance harness drives those as
        // legitimate spec builtins -- it omits the flag (so conformance stays
        // 100%), and the Relay host wrapper SETS it (so Py and TS reject the
        // identical set by construction). The struct/Unspecified fence below is
        // ALWAYS on (cel 0.13 PANICS on those -- a P0 DoS surface -- regardless
        // of profile).
        let relay_profile = req
            .get("relay_profile")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // FENCE: reject struct/message construction (always) + the
        // profile-disabled dyn/ts/dur calls (when relay_profile) with a clean
        // error BEFORE execute() can reach a panic.
        if let Some((reason, subtype)) =
            find_profile_rejection(program.expression(), relay_profile)
        {
            return Err(CelError::profile(reason, subtype));
        }

        let mut context = relay_context();

        // G16: the optional resolution container (CEL namespace). cel-go
        // resolves a bare/qualified name most-qualified to least within the
        // container; the fork's Context carries it (set_container) and applies
        // the candidate order in Expr::Ident / Expr::Select resolution.
        if let Some(container) = req.get("container").and_then(|v| v.as_str()) {
            context.set_container(container);
        }

        if let Some(bindings) = req.get("bindings").and_then(|v| v.as_object()) {
            for (name, typed) in bindings {
                let v = typed_to_value(typed).map_err(|e| {
                    CelError::new(codes::REQUEST, format!("binding '{name}': {e}"))
                })?;
                context.add_variable_from_value(name.clone(), v);
            }
        }

        // WS-J: the optional per-eval deterministic fuel/step budget. ABSENT or
        // the disabled sentinel 0 => UNBOUNDED (no limit), preserving conformance
        // byte-for-byte (the harness omits the field). A positive value caps the
        // evaluated-node count. A negative or non-integer value is treated as the
        // disabled sentinel (unbounded) rather than an error, so a malformed
        // budget never changes a successful eval's RESULT bytes -- the budget is
        // a guard, not part of the contract surface. The counter is an in-wasm
        // thread-local (see cel::fuel): NO host import, NO wall clock.
        let fuel_budget = req
            .get("fuel_budget")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        cel::fuel::set_budget(fuel_budget);

        let value = program.execute(&context).map_err(|e| match e {
            // WS-J: a fuel-budget exhaustion maps to the dedicated RELAY-CEL-003 /
            // RELAY-CEL-TIMEOUT-001 envelope (a portable in-engine timeout), NOT
            // the generic EXEC (RELAY-CEL-004) path. Every other ExecutionError is
            // a genuine runtime exec failure.
            ExecutionError::FuelExhausted { budget } => CelError::timeout(format!(
                "fuel budget exhausted: evaluation exceeded the step budget of {budget}"
            )),
            other => CelError::new(codes::EXEC, format!("exec: {other:?}")),
        })?;
        Ok(value_to_typed(&value))
    })();

    // WS-J: disarm the budget (back to unbounded) regardless of success/error, so
    // a later eval on this thread (or a host wall-clock timeout that orphans a
    // worker thread) never inherits a stale budget. Mirrors the udf_trace clear-
    // first / drain-once discipline.
    cel::fuel::reset();

    // Drain the per-thread UDF trace exactly once, regardless of success/error,
    // so the buffer never carries stale entries into a later eval on this thread.
    let udf_trace = udf_trace_drain();

    let out = match result {
        Ok(v) => {
            let mut obj = json!({"ok": true, "value": v});
            // ADDITIVE metadata: attach the executed-UDF trace (per-name list in
            // call order) only when a relay.* UDF actually ran. A non-UDF eval
            // omits the field entirely. This never changes the `value` above.
            if let Some(trace) = udf_trace {
                obj["udf_trace"] = trace;
            }
            obj
        }
        Err(e) => {
            let mut obj = json!({"ok": false, "error": e.message, "code": e.code});
            // Emit `subtype` only for the profile rejections that carry one (and
            // the WS-J fuel-timeout, which carries TIMEOUT), so the host maps
            // (code, subtype) -> the typed RelayCelError without parsing the
            // message string. Errors with no subtype omit it.
            if let Some(st) = e.subtype {
                obj["subtype"] = json!(st);
            }
            // BATCHED FIX (deferred crate udf_trace-on-error): attach the drained
            // udf_trace to the ERROR envelope too. A relay.* UDF can RUN (and
            // record forensics) before a LATER part of the expression fails (e.g.
            // `size(relay.tool_arg(...)) + (1 / 0)` -- the UDF ran, then the
            // division errors). Previously the trace was attached only on the
            // success path, so this partial forensic record was LOST on a failed
            // eval. Attaching it here (same per-name / call-order structure as the
            // success path) preserves the partial UDF trace across a failure. The
            // field is ABSENT when no relay.* UDF executed (udf_trace is None), so
            // a non-UDF error is byte-identical to before. The host pipeline treats
            // udf_trace on an error envelope as forensic-only (it does not resolve
            // a canonical outcome from a failed eval), so this is additive and
            // does not change error handling.
            if let Some(trace) = udf_trace {
                obj["udf_trace"] = trace;
            }
            obj
        }
    };
    serde_json::to_vec(&out).unwrap_or_else(|_| {
        format!(
            "{{\"ok\":false,\"error\":\"serialize\",\"code\":\"{}\"}}",
            codes::EXEC
        )
        .into_bytes()
    })
}

// ---------------------------------------------------------------------------
// G1: profile fence -- reject struct/message construction before it can panic
// ---------------------------------------------------------------------------

/// Walk the parsed AST. Return Some((reason, subtype)) if it contains any node
/// the Relay CEL profile rejects. Two classes:
///   - ALWAYS (a safety fence): struct/message construction (`Foo{...}`,
///     `google.protobuf.BoolValue{...}`), struct-field entries embedded in
///     map/list literals, and Unspecified nodes -- cel 0.13 PANICS on these
///     (objects.rs `todo!()` / `panic!("WAT?")`), a P0 DoS surface.
///   - When `relay_profile`: the global CALL forms `dyn(...)`, `timestamp(...)`,
///     `duration(...)`. These EVALUATE fine (the wrapper registers them for the
///     conformance corpus), but the Relay profile disallows them as calls
///     (use schema-typed inputs / cross-numeric equality instead). This mirrors
///     the host's _check_profile bare-call (`ident_arg`) detection.
fn find_profile_rejection(expr: &IdedExpr, relay_profile: bool) -> Option<(String, &'static str)> {
    match &expr.expr {
        Expr::Struct(s) => Some((
            format!(
                "Relay CEL profile disables message/struct construction '{}{{...}}': \
                 proto/message values are not part of the Relay contract surface",
                s.type_name
            ),
            subtypes::STRUCT,
        )),
        Expr::Unspecified => Some((
            "Relay CEL profile: unspecified expression node".to_string(),
            subtypes::STRUCT,
        )),
        Expr::Call(call) => {
            // Relay-profile call fence: only the GLOBAL call form (no receiver),
            // matching the host's bare-call `ident_arg` detection.
            if relay_profile && call.target.is_none() {
                if let Some(hit) = disabled_call_rejection(call.func_name.as_str()) {
                    return Some(hit);
                }
            }
            if let Some(target) = &call.target {
                if let Some(r) = find_profile_rejection(target, relay_profile) {
                    return Some(r);
                }
            }
            call.args
                .iter()
                .find_map(|a| find_profile_rejection(a, relay_profile))
        }
        Expr::Comprehension(c) => find_profile_rejection(&c.iter_range, relay_profile)
            .or_else(|| find_profile_rejection(&c.accu_init, relay_profile))
            .or_else(|| find_profile_rejection(&c.loop_cond, relay_profile))
            .or_else(|| find_profile_rejection(&c.loop_step, relay_profile))
            .or_else(|| find_profile_rejection(&c.result, relay_profile)),
        Expr::List(l) => l
            .elements
            .iter()
            .find_map(|e| find_profile_rejection(e, relay_profile)),
        Expr::Map(m) => m
            .entries
            .iter()
            .find_map(|e| entry_rejection(&e.expr, relay_profile)),
        Expr::Select(s) => find_profile_rejection(&s.operand, relay_profile),
        Expr::Ident(_) | Expr::Literal(_) => None,
    }
}

/// The Relay-profile-disabled global builtins (the call form). Mirrors the
/// host's _DISABLED_BUILTINS (dyn / timestamp / duration), each with its
/// (code, subtype) cross-runtime pair.
fn disabled_call_rejection(name: &str) -> Option<(String, &'static str)> {
    let (msg, subtype): (&str, &'static str) = match name {
        "dyn" => (
            "Relay CEL profile disables 'dyn(...)': dynamic typing is not part of \
             the Relay contract surface",
            subtypes::DYN,
        ),
        "timestamp" => (
            "Relay CEL profile disables native 'timestamp(...)': use schema-typed \
             timestamp inputs instead",
            subtypes::TS,
        ),
        "duration" => (
            "Relay CEL profile disables native 'duration(...)': use schema-typed \
             duration inputs instead",
            subtypes::DUR,
        ),
        _ => return None,
    };
    Some((msg.to_string(), subtype))
}

fn entry_rejection(entry: &EntryExpr, relay_profile: bool) -> Option<(String, &'static str)> {
    match entry {
        // A StructField entry inside a Map literal is exactly the construct that
        // makes cel 0.13 `panic!("WAT?")` (objects.rs Expr::Map). Fence it.
        EntryExpr::StructField(_) => Some((
            "Relay CEL profile disables struct-field construction".to_string(),
            subtypes::STRUCT,
        )),
        EntryExpr::MapEntry(e) => find_profile_rejection(&e.key, relay_profile)
            .or_else(|| find_profile_rejection(&e.value, relay_profile)),
    }
}

// ---------------------------------------------------------------------------
// Relay context: cel defaults + the Relay conformance shims
// ---------------------------------------------------------------------------

/// Build the evaluation context: cel 0.13 default builtins, then the Relay
/// shims layered on top. `Context::default()` registers size/string/bytes/
/// double/int/uint/duration/timestamp/etc.; re-`add_function` with the same
/// name REPLACES (the registry is a HashMap insert -- magic.rs add()), so the
/// overrides below shadow the stock builtins.
fn relay_context<'a>() -> Context<'a> {
    let mut ctx = Context::default();

    // G2: dyn(x) = x. cel 0.13 has no `dyn` builtin (it is type erasure /
    // identity at runtime). Register it as identity. Cross-numeric equality
    // that dyn() forms exercise underneath is G6 (needs the fork). The closure
    // returns Result<Value, ExecutionError> because that is the only Value-bearing
    // type that implements IntoResolveResult (magic.rs).
    ctx.add_function("dyn", |arg: Value| -> Result<Value, ExecutionError> { Ok(arg) });

    // G13 (wrapper): bool() conversion. cel 0.13 has no `bool` builtin, so
    // `bool('1')` / `bool(true)` were UndeclaredReference. cel-go's bool()
    // overloads (common/types/string.go ConvertToType / bool identity):
    //   bool(bool)   -> identity
    //   bool(string) -> "1","t","true","TRUE","True" => true;
    //                   "0","f","false","FALSE","False" => false;
    //                   anything else => "Type conversion error".
    // (cel-go uses strconv.ParseBool, whose accepted set is exactly those.)
    ctx.add_function("bool", relay_bool);

    // G13 (wrapper): string() over bytes must ERROR on invalid UTF-8 rather
    // than lossily substituting U+FFFD (cel 0.13 builtin uses
    // String::from_utf8_lossy). cel-go errors: "invalid UTF-8 in bytes,
    // cannot convert to string". All other string() arms (number/bool/
    // duration/timestamp/string identity) delegate to the cel-go-canonical
    // serializer so they stay byte-parity-correct (G14 'Z' timestamps, the
    // Go-style duration string, the G9 double format).
    ctx.add_function("string", relay_string);

    // G11: size() over a string must count Unicode code points, not UTF-8
    // bytes. cel 0.13's builtin uses s.len() (byte length). Override for the
    // string case; list/map/bytes keep element/byte counts (those ARE the CEL
    // semantics). Works as a method (this) or a function (first arg).
    ctx.add_function("size", relay_size);

    // G12: idempotent conversion overloads. cel 0.13's bytes()/duration()/
    // timestamp() only accept string input and error (UnexpectedType) on an
    // already-typed arg. string()/int()/uint()/double() already accept many
    // types, so only these three need overriding.
    ctx.add_function("bytes", relay_bytes);
    #[cfg(feature = "chrono")]
    {
        ctx.add_function("duration", relay_duration);
        ctx.add_function("timestamp", relay_timestamp);
    }

    // G10 + G13: re-register int()/uint() so a DOUBLE argument is range-checked
    // with the cel-spec's exact-representability rule (cel 0.13 only bounds-
    // checks against i64/u64 MIN/MAX, which clamps 2**63 / 2**64 instead of
    // erroring), and so int() also accepts a timestamp argument (epoch seconds).
    // All non-double / non-timestamp arms preserve the stock cel 0.13 behavior.
    ctx.add_function("int", relay_int);
    ctx.add_function("uint", relay_uint);

    // G3: the CEL type-value model. cel 0.13 has no `type()` builtin and leaves
    // the type identifiers (`int`, `uint`, ...) unbound, so `type(1)` was an
    // UndeclaredReference. The fork added a first-class `Value::Type` (see
    // vendor/cel objects.rs / common/types/type_value.rs `Relay fork (G3)`);
    // here we register `type(x)` and bind the type identifiers as type values.
    //
    // `type(x)` returns the runtime type of x as a type value (e.g.
    // `Value::Type("int")`). The type of a type value is the meta-type `type`,
    // so `type(type(1))` is `Value::Type("type")`. The names are the cel-go
    // canonical runtime type names (the oracle uses `ref.Val.TypeName()`).
    ctx.add_function("type", relay_type);

    // Bind the ten simple type identifiers + the two proto-qualified
    // duration/timestamp type names so that a bare type denotation (`int`,
    // `null_type`, ..., `google.protobuf.Timestamp`) resolves to its type value.
    // The dotted names resolve via the fork's qualified-name lookup in
    // Expr::Select (`Relay fork (G3)`).
    for name in [
        "int",
        "uint",
        "double",
        "bool",
        "string",
        "bytes",
        "list",
        "map",
        "null_type",
        "type",
        "google.protobuf.Timestamp",
        "google.protobuf.Duration",
    ] {
        ctx.add_variable_from_value(name.to_string(), Value::Type(Arc::from(name)));
    }

    // WS4 cutover (step 1): the 3 Relay contract-DSL UDFs, ported from
    // packages/contracts/src/relay_contracts/udfs/{coverage,tool_arg,schema_match}.py
    // as native Rust so the Python and TS hosts call the SAME bytes by
    // construction (retiring the per-runtime UDF parity grind). They are pure,
    // deterministic, and TOTAL -- a shape mismatch yields false/null, never an
    // error. Authored against the DOCUMENTED contract (the intended
    // shape-tolerant semantics + VAL-PARITY-002), which is what the
    // direct-callable Python path produces with plain dicts; the wasm is the
    // single source of truth. (cel-python driven THROUGH CEL violates that
    // contract -- celpy MapType.get raises on a missing key and celpy
    // BoolType/DoubleType break the isinstance screens -- so the wasm is the
    // CORRECT implementation the cutover standardizes on.) Registered under the
    // dotted CEL name; `relay.<fn>(...)` routes here via the fork's
    // qualified-name function resolution (objects.rs Expr::Call `Some(target)`).
    ctx.add_function("relay.coverage", relay_coverage);
    ctx.add_function("relay.tool_arg", relay_tool_arg);
    ctx.add_function("relay.schema_match", relay_schema_match);

    ctx
}

/// G3: the canonical cel-go runtime type NAME of a CEL value, used by `type(x)`.
/// These match the oracle's `ref.Val.TypeName()`: the scalar names plus the
/// proto-qualified `google.protobuf.{Timestamp,Duration}`, and `type` for the
/// runtime type of a type value (the meta-type).
fn type_name_of(v: &Value) -> &'static str {
    match v {
        Value::Int(_) => "int",
        Value::UInt(_) => "uint",
        Value::Float(_) => "double",
        Value::Bool(_) => "bool",
        Value::String(_) => "string",
        Value::Bytes(_) => "bytes",
        Value::List(_) => "list",
        Value::Map(_) => "map",
        Value::Null => "null_type",
        #[cfg(feature = "chrono")]
        Value::Duration(_) => "google.protobuf.Duration",
        #[cfg(feature = "chrono")]
        Value::Timestamp(_) => "google.protobuf.Timestamp",
        // The runtime type of a type value is the meta-type `type`.
        Value::Type(_) => "type",
        // A function reference / opaque value has no CEL type in the Relay
        // profile surface; report its structural kind for diagnostics. These
        // are not reachable from the conformance corpus.
        Value::Function(_, _) => "function",
        Value::Opaque(_) => "opaque",
    }
}

/// G3: `type(x)` -> the type value of x's runtime type. Uses `This<Value>` so it
/// works as a function (`type(1)`); CEL's `type` is function-only (not a method),
/// but This covers both dispatch forms uniformly with the other shims.
fn relay_type(This(this): This<Value>) -> Result<Value, ExecutionError> {
    Ok(Value::Type(Arc::from(type_name_of(&this))))
}

/// G10 + G13: int() conversion with the cel-spec range/exactness rule for the
/// double case and the G13 timestamp -> epoch-seconds overload.
///
/// cel-spec / cel-go (common/types/overflow.go doubleToInt64Checked) errors when
/// the double is NaN/Inf or `v <= float64(i64::MIN)` or `v >= float64(i64::MAX)`.
/// `i64::MAX as f64` rounds UP to 2**63 and `i64::MIN as f64` is exactly -2**63,
/// so this single comparison reproduces the not-exactly-representable boundary:
/// `int(9223372036854775807.0)` (the f64 is 2**63) and `int(-9223372036854775808.0)`
/// (the f64 is -2**63) both error, while `int(double(2**55))` stays in range.
///
/// All other argument types fall through to the stock cel 0.13 semantics:
///   - string  -> parse as i64 (string parse error on failure)
///   - int     -> identity
///   - uint    -> checked into i64 (integer overflow on out-of-range)
fn relay_int(This(this): This<Value>) -> Result<Value, ExecutionError> {
    match this {
        Value::Float(v) => {
            // cel-go: v <= float64(MinInt64) || v >= float64(MaxInt64) || NaN/Inf.
            if v.is_nan()
                || v.is_infinite()
                || v <= i64::MIN as f64
                || v >= i64::MAX as f64
            {
                return Err(ExecutionError::function_error(
                    "int",
                    format!("range: double {v} is outside the int64 range"),
                ));
            }
            // Truncate toward zero (the C-style `as i64` cast on a finite,
            // in-range f64 truncates toward zero, matching int(v) semantics).
            Ok(Value::Int(v as i64))
        }
        #[cfg(feature = "chrono")]
        Value::Timestamp(t) => {
            // G13: int(timestamp) -> Unix epoch SECONDS as an int.
            Ok(Value::Int(t.timestamp()))
        }
        Value::String(s) => s
            .parse::<i64>()
            .map(Value::Int)
            .map_err(|e| ExecutionError::function_error("int", format!("string parse error: {e}"))),
        Value::Int(v) => Ok(Value::Int(v)),
        Value::UInt(v) => i64::try_from(v)
            .map(Value::Int)
            .map_err(|_| ExecutionError::function_error("int", "integer overflow")),
        other => Err(ExecutionError::function_error(
            "int",
            format!("cannot convert {other:?} to int"),
        )),
    }
}

/// G10: uint() conversion with the cel-spec range/exactness rule for the double
/// case. cel-spec / cel-go (doubleToUint64Checked) errors when the double is
/// NaN/Inf or `v < 0` or `v >= 2**64`. `u64::MAX as f64` rounds UP to 2**64, so
/// the comparison `v >= u64::MAX as f64` reproduces the `>= 2**64` boundary
/// (`int(18446744073709551615.0)` / a uint of 2**64 errors). All other argument
/// types fall through to the stock cel 0.13 semantics.
fn relay_uint(This(this): This<Value>) -> Result<Value, ExecutionError> {
    match this {
        Value::Float(v) => {
            // cel-go: v < 0 || v >= 2**64 || NaN/Inf. (u64::MAX as f64 == 2**64.)
            if v.is_nan() || v.is_infinite() || v < 0.0 || v >= u64::MAX as f64 {
                return Err(ExecutionError::function_error(
                    "uint",
                    format!("range: double {v} is outside the uint64 range"),
                ));
            }
            Ok(Value::UInt(v as u64))
        }
        Value::String(s) => s
            .parse::<u64>()
            .map(Value::UInt)
            .map_err(|e| {
                ExecutionError::function_error("uint", format!("string parse error: {e}"))
            }),
        Value::Int(v) => u64::try_from(v)
            .map(Value::UInt)
            .map_err(|_| ExecutionError::function_error("uint", "unsigned integer overflow")),
        Value::UInt(v) => Ok(Value::UInt(v)),
        other => Err(ExecutionError::function_error(
            "uint",
            format!("cannot convert {other:?} to uint"),
        )),
    }
}

/// G11 size(): code points for strings, element/byte counts otherwise.
/// Uses `This<Value>` so it works both as a method (`'abc'.size()`, where the
/// string is `this`) and as a function (`size('abc')`, where it is args[0]) --
/// matching the stock cel 0.13 size() dual dispatch. A plain `Value` arg would
/// read args[0] and PANIC on the method form (empty args).
fn relay_size(This(this): This<Value>) -> Result<Value, ExecutionError> {
    let n = match &this {
        Value::String(s) => s.chars().count(),
        Value::Bytes(b) => b.len(),
        Value::List(l) => l.len(),
        Value::Map(m) => m.map.len(),
        other => {
            return Err(ExecutionError::function_error(
                "size",
                format!("cannot determine the size of {other:?}"),
            ))
        }
    };
    Ok(Value::Int(n as i64))
}

/// G12 bytes(): accept an already-`bytes` value idempotently; otherwise convert
/// from string (the stock behavior).
fn relay_bytes(arg: Value) -> Result<Value, cel::ExecutionError> {
    match arg {
        Value::Bytes(b) => Ok(Value::Bytes(b)),
        Value::String(s) => Ok(Value::Bytes(Arc::new(s.as_bytes().to_vec()))),
        other => Err(cel::ExecutionError::function_error(
            "bytes",
            format!("cannot convert {other:?} to bytes"),
        )),
    }
}

/// G12 duration(): accept an already-`duration` value idempotently; otherwise
/// parse from string via cel's parser.
#[cfg(feature = "chrono")]
fn relay_duration(arg: Value) -> Result<Value, cel::ExecutionError> {
    match arg {
        Value::Duration(d) => Ok(Value::Duration(d)),
        Value::String(s) => parse_duration_string(&s),
        other => Err(cel::ExecutionError::function_error(
            "duration",
            format!("cannot convert {other:?} to duration"),
        )),
    }
}

/// G12 + G13 timestamp(): accept an already-`timestamp` value idempotently
/// (G12); accept an INT as Unix epoch SECONDS (G13, cel-go's
/// timestamp(int)->Timestamp overload); otherwise parse from an RFC3339 string.
#[cfg(feature = "chrono")]
fn relay_timestamp(arg: Value) -> Result<Value, cel::ExecutionError> {
    match arg {
        Value::Timestamp(t) => Ok(Value::Timestamp(t)),
        // G13: timestamp(int) -> the Unix epoch SECONDS as a UTC timestamp,
        // the inverse of int(timestamp). cel-go uses
        // time.Unix(seconds, 0).UTC(); out-of-range seconds error.
        Value::Int(secs) => chrono::DateTime::from_timestamp(secs, 0)
            .map(|dt| Value::Timestamp(dt.fixed_offset()))
            .ok_or_else(|| {
                cel::ExecutionError::function_error(
                    "timestamp",
                    format!("epoch seconds {secs} out of timestamp range"),
                )
            }),
        Value::String(s) => parse_timestamp_string(&s),
        other => Err(cel::ExecutionError::function_error(
            "timestamp",
            format!("cannot convert {other:?} to timestamp"),
        )),
    }
}

/// G13 (wrapper) bool(): cel-go's bool() conversion overloads.
///   bool(bool)   -> identity
///   bool(string) -> strconv.ParseBool semantics:
///                   "1","t","T","TRUE","true","True" => true
///                   "0","f","F","FALSE","false","False" => false
///                   anything else => Type conversion error.
fn relay_bool(arg: Value) -> Result<Value, ExecutionError> {
    match arg {
        Value::Bool(b) => Ok(Value::Bool(b)),
        Value::String(s) => match s.as_str() {
            "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(Value::Bool(true)),
            "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(Value::Bool(false)),
            other => Err(ExecutionError::function_error(
                "bool",
                format!("Type conversion error: cannot convert '{other}' to bool"),
            )),
        },
        other => Err(ExecutionError::function_error(
            "bool",
            format!("cannot convert {other:?} to bool"),
        )),
    }
}

/// G13 (wrapper) string(): cel-go's string() conversion. The load-bearing fix
/// is the BYTES arm: invalid UTF-8 must ERROR ("invalid UTF-8 in bytes,
/// cannot convert to string"), not lossily substitute U+FFFD the way cel
/// 0.13's builtin does (String::from_utf8_lossy). All other arms reproduce
/// cel-go's canonical string forms (and reuse the serializer's G9/G14
/// double/timestamp formatting so round-tripping stays byte-parity-correct).
fn relay_string(arg: Value) -> Result<Value, ExecutionError> {
    let s = match arg {
        Value::String(s) => return Ok(Value::String(s)),
        Value::Bytes(b) => String::from_utf8(b.as_ref().clone()).map_err(|_| {
            ExecutionError::function_error(
                "string",
                "invalid UTF-8 in bytes, cannot convert to string",
            )
        })?,
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::UInt(u) => u.to_string(),
        // Reuse the serializer's Go 'g' canonical double format so
        // string(1.5e12) matches cel-go and the cross-host byte contract.
        Value::Float(f) => canonical_double(f),
        #[cfg(feature = "chrono")]
        Value::Duration(d) => format_duration_go(&d),
        #[cfg(feature = "chrono")]
        Value::Timestamp(t) => rfc3339_utc_z(&t),
        other => {
            return Err(ExecutionError::function_error(
                "string",
                format!("cannot convert {other:?} to string"),
            ))
        }
    };
    Ok(Value::String(Arc::new(s)))
}

/// Parse a CEL duration string (e.g. "60s", "1h30m") into Value::Duration,
/// matching cel 0.13's duration() string semantics. cel uses chrono::Duration
/// internally; we mirror its grammar via a tolerant unit parser.
#[cfg(feature = "chrono")]
fn parse_duration_string(s: &str) -> Result<Value, cel::ExecutionError> {
    let total_nanos = parse_duration_nanos(s).ok_or_else(|| {
        cel::ExecutionError::function_error("duration", format!("invalid duration string '{s}'"))
    })?;
    Ok(Value::Duration(chrono::Duration::nanoseconds(total_nanos)))
}

/// Parse a Go/CEL-style duration ("1h", "30m", "1.5s", "100ms", "10us", "5ns",
/// signed) into total nanoseconds. Returns None on malformed input.
#[cfg(feature = "chrono")]
fn parse_duration_nanos(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (sign, rest) = match s.strip_prefix('-') {
        Some(r) => (-1i128, r),
        None => (1i128, s.strip_prefix('+').unwrap_or(s)),
    };
    if rest.is_empty() {
        return None;
    }
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    let mut total: i128 = 0;
    while i < bytes.len() {
        // number (with optional fractional part)
        let num_start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        if i == num_start {
            return None;
        }
        let num: f64 = rest[num_start..i].parse().ok()?;
        // unit
        let unit_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_digit() && bytes[i] != b'.' && bytes[i] != b'-' {
            i += 1;
        }
        let unit = &rest[unit_start..i];
        let scale: f64 = match unit {
            "ns" => 1.0,
            "us" | "\u{00b5}s" => 1_000.0,
            "ms" => 1_000_000.0,
            "s" => 1_000_000_000.0,
            "m" => 60.0 * 1_000_000_000.0,
            "h" => 3_600.0 * 1_000_000_000.0,
            _ => return None,
        };
        total = total.checked_add((num * scale).round() as i128)?;
    }
    let signed = sign * total;
    if signed > i64::MAX as i128 || signed < i64::MIN as i128 {
        return None;
    }
    Some(signed as i64)
}

/// Parse an RFC3339 timestamp string into Value::Timestamp, enforcing the
/// cel-spec timestamp range `[0001-01-01T00:00:00Z,
/// 9999-12-31T23:59:59.999999999Z]`. A year-0 (or otherwise out-of-range)
/// timestamp string parses fine in chrono but is NOT a valid CEL timestamp;
/// cel-go errors on it (timestamps.textproto from_string_under). We reject it
/// here so `timestamp('0000-01-01T00:00:00Z')` is an error, not a value.
#[cfg(feature = "chrono")]
fn parse_timestamp_string(s: &str) -> Result<Value, cel::ExecutionError> {
    let dt = chrono::DateTime::parse_from_rfc3339(s).map_err(|e| {
        cel::ExecutionError::function_error("timestamp", format!("invalid timestamp '{s}': {e}"))
    })?;
    check_timestamp_range(dt, s)
}

/// cel-spec timestamp bounds: year 1 .. year 9999 inclusive (UTC). Returns the
/// timestamp value or a range error.
#[cfg(feature = "chrono")]
fn check_timestamp_range(
    dt: chrono::DateTime<chrono::FixedOffset>,
    s: &str,
) -> Result<Value, cel::ExecutionError> {
    use chrono::Datelike;
    let utc = dt.with_timezone(&chrono::Utc);
    let year = utc.year();
    if !(1..=9999).contains(&year) {
        return Err(cel::ExecutionError::function_error(
            "timestamp",
            format!("timestamp '{s}' is outside the valid CEL range [0001..9999]"),
        ));
    }
    Ok(Value::Timestamp(dt))
}

// ---------------------------------------------------------------------------
// Relay contract-DSL UDFs (WS4 cutover step 1)
//
// relay.coverage / relay.tool_arg / relay.schema_match, ported from
// packages/contracts/src/relay_contracts/udfs/{coverage,tool_arg,schema_match}.py.
// Pure, deterministic, and TOTAL (never Err -- a shape mismatch yields
// false/null), so a single shared wasm implementation is byte-identical across
// the Python and TS hosts BY CONSTRUCTION. Each output is a pure reduction
// (coverage = OR over steps, schema_match = AND over constraints) or a single
// lookup (tool_arg), so the result is independent of HashMap iteration order.
// ---------------------------------------------------------------------------

/// Look up a STRING key in a CEL map's backing HashMap.
fn map_get_str<'a>(m: &'a Map, key: &str) -> Option<&'a Value> {
    m.map.get(&Key::String(Arc::new(key.to_string())))
}

/// Schema-FIELD access with the intended `.get()`-style semantics: a missing
/// key OR a present `null` value both mean "field not specified" -> None. The
/// Python source reads schema fields with `.get()`, which returns Python None
/// for a present CEL null (cel-python maps CEL null to None) AND is INTENDED to
/// skip an absent field (the documented "shape-tolerant, never raises"
/// contract). (cel-python's MapType.get actually RAISES on an absent key -- a
/// latent bug this wasm, the single source of truth, does NOT reproduce.)
fn schema_field<'a>(m: &'a Map, key: &str) -> Option<&'a Value> {
    match map_get_str(m, key) {
        None | Some(Value::Null) => None,
        some => some,
    }
}

/// relay.coverage(trace, step_name) -> bool. True iff `trace` is a map whose
/// "steps" is a list containing an entry map whose "name" string equals
/// `step_name` (exact codepoint `==`, no case/locale fold). Total: any shape
/// mismatch -> false. (coverage.py relay_coverage)
fn relay_coverage(trace: Value, step_name: Value) -> Result<Value, ExecutionError> {
    let out = Value::Bool(coverage_match(&trace, &step_name));
    // WS-B: record the executed UDF's return value (typed-canonical) in call
    // order. Only reached when this UDF actually runs (a short-circuited branch
    // never calls it), so the trace contains exactly the evaluated UDF calls.
    udf_trace_record("relay.coverage", &out);
    Ok(out)
}

fn coverage_match(trace: &Value, step_name: &Value) -> bool {
    let Value::Map(m) = trace else { return false };
    let Value::String(step) = step_name else { return false };
    // Reject a non-list "steps" (incl. absent -> None, or a bare string): a
    // shape error yields false rather than iterating characters.
    let Some(Value::List(steps)) = map_get_str(m, "steps") else {
        return false;
    };
    for entry in steps.iter() {
        let Value::Map(em) = entry else { continue };
        if let Some(Value::String(name)) = map_get_str(em, "name") {
            if name == step {
                return true;
            }
        }
    }
    false
}

/// relay.tool_arg(call, key) -> any. `call["args"][key]` when present, else
/// null. A key whose value is null is indistinguishable from a missing key
/// (both yield null) -- the v0.1 contract. Total: any shape mismatch / missing
/// -> null. The returned value is passed back unchanged through the typed-
/// canonical serializer. (tool_arg.py relay_tool_arg)
fn relay_tool_arg(call: Value, key: Value) -> Result<Value, ExecutionError> {
    let out = tool_arg_lookup(&call, &key);
    // WS-B: record the executed UDF's return value (typed-canonical) in call
    // order. Computed once (tool_arg_lookup) so EVERY shape -- a found value, a
    // present-null, a missing key, a non-map call/args, a non-string key -- is
    // recorded identically to what the response value would serialize.
    udf_trace_record("relay.tool_arg", &out);
    Ok(out)
}

/// The total `call["args"][key]` lookup: a found value (cloned), else null. A
/// present-null and a missing key both yield null (the v0.1 contract); any shape
/// mismatch (non-map call/args, non-string key) also yields null.
fn tool_arg_lookup(call: &Value, key: &Value) -> Value {
    let Value::Map(m) = call else { return Value::Null };
    let Value::String(k) = key else { return Value::Null };
    let Some(Value::Map(args)) = map_get_str(m, "args") else {
        return Value::Null;
    };
    match args.map.get(&Key::String(k.clone())) {
        Some(v) => v.clone(),
        None => Value::Null,
    }
}

/// Defense-in-depth bound on recursive descent into nested schemas (the host's
/// wall-clock timeout is the primary guard). Mirrors schema_match.py MAX_DEPTH.
const SCHEMA_MATCH_MAX_DEPTH: u32 = 64;

/// The frozen JSON-Schema type-name set (schema_match.py _VALID_TYPES).
const SCHEMA_VALID_TYPES: [&str; 7] = [
    "string", "number", "integer", "boolean", "object", "array", "null",
];

/// relay.schema_match(payload, schema) -> bool. True iff `payload` conforms to
/// the minimal JSON-Schema subset declared by `schema` (type/required/
/// properties/items). Total: a malformed schema yields false. (schema_match.py)
fn relay_schema_match(payload: Value, schema: Value) -> Result<Value, ExecutionError> {
    let out = Value::Bool(schema_validate(&payload, &schema, 0));
    // WS-B: record the executed UDF's return value (typed-canonical) in call
    // order. Only reached when this UDF actually runs.
    udf_trace_record("relay.schema_match", &out);
    Ok(out)
}

/// JSON-Schema "number": a FINITE int/uint/double. Booleans are NOT numbers;
/// NaN/Inf are NOT finite. (schema_match.py _is_finite_number; the bool exclusion
/// is load-bearing -- celpy BoolType breaks this in cel-python, the wasm does not.)
fn schema_is_finite_number(v: &Value) -> bool {
    match v {
        Value::Bool(_) => false,
        Value::Int(_) | Value::UInt(_) => true,
        Value::Float(f) => f.is_finite(),
        _ => false,
    }
}

/// JSON-Schema "integer" (VAL-PARITY-002): a finite number with an integral
/// value. An integral CEL double (e.g. 1.0) IS an integer, matching cel-js
/// Number.isInteger; booleans and NaN/Inf are excluded by the finiteness screen.
/// (schema_match.py _is_integer)
fn schema_is_integer(v: &Value) -> bool {
    if !schema_is_finite_number(v) {
        return false;
    }
    match v {
        Value::Float(f) => *f == f.trunc(),
        // Remaining finite-number case is a non-bool Int/UInt -> integral.
        _ => true,
    }
}

/// schema_match.py _matches_type, with the same boolean-first ordering.
fn schema_matches_type(payload: &Value, type_name: &str) -> bool {
    match type_name {
        "boolean" => matches!(payload, Value::Bool(_)),
        "null" => matches!(payload, Value::Null),
        "string" => matches!(payload, Value::String(_)),
        "integer" => schema_is_integer(payload),
        "number" => schema_is_finite_number(payload),
        "object" => matches!(payload, Value::Map(_)),
        "array" => matches!(payload, Value::List(_)),
        // Unknown type names are screened by the caller (SCHEMA_VALID_TYPES).
        _ => false,
    }
}

/// schema_match.py _validate, ported over cel::Value with an explicit depth.
fn schema_validate(payload: &Value, schema: &Value, depth: u32) -> bool {
    if depth > SCHEMA_MATCH_MAX_DEPTH {
        return false;
    }
    let Value::Map(schema_map) = schema else { return false };
    // Empty schema validates anything (JSON Schema {} / true semantics). Uses
    // raw key count, NOT the null-aware field count.
    if schema_map.map.is_empty() {
        return true;
    }
    if let Some(type_value) = schema_field(schema_map, "type") {
        let Value::String(type_name) = type_value else { return false };
        if !SCHEMA_VALID_TYPES.contains(&type_name.as_str()) {
            return false;
        }
        if !schema_matches_type(payload, type_name) {
            return false;
        }
    }
    // Object-shape constraints (consulted only when payload is a map; if
    // "type":"object" is set the type check above already gated this).
    if let Value::Map(payload_map) = payload {
        if let Some(required) = schema_field(schema_map, "required") {
            let Value::List(required_list) = required else { return false };
            for name in required_list.iter() {
                let Value::String(name_str) = name else { return false };
                if !payload_map.map.contains_key(&Key::String(name_str.clone())) {
                    return false;
                }
            }
        }
        if let Some(properties) = schema_field(schema_map, "properties") {
            let Value::Map(properties_map) = properties else { return false };
            for (prop_key, prop_schema) in properties_map.map.iter() {
                let Key::String(prop_name) = prop_key else { return false };
                // Only present properties are validated (missing ones are
                // covered by "required"). The payload value -- including a CEL
                // null -- is validated as-is (a null child fails a typed schema).
                if let Some(child) = payload_map.map.get(&Key::String(prop_name.clone())) {
                    if !schema_validate(child, prop_schema, depth + 1) {
                        return false;
                    }
                }
            }
        }
    }
    // Array-shape constraints (consulted only when payload is a list).
    if let Value::List(payload_list) = payload {
        if let Some(items) = schema_field(schema_map, "items") {
            // v0.1 supports only a single Map item-schema (tuple validation is
            // unsupported); a non-map "items" -> false.
            if !matches!(items, Value::Map(_)) {
                return false;
            }
            for element in payload_list.iter() {
                if !schema_validate(element, items, depth + 1) {
                    return false;
                }
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Serializer: cel::Value -> typed canonical JSON
// ---------------------------------------------------------------------------

/// Canonical f64 -> string in CEL/cel-go format (G9):
///   - inf/-inf/nan as those literals
///   - exponential notation for large/small magnitudes (e.g. 1e+12, 1e-07)
///     matching cel-go's strconv.FormatFloat(f, 'g', -1, 64)
///   - otherwise shortest round-trip decimal, always with a decimal point so
///     1.0 is textually distinct from the int 1.
fn canonical_double(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_string();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    format_double_g(f)
}

/// Reproduce Go's strconv.FormatFloat(f, 'g', -1, 64): shortest decimal that
/// round-trips, choosing %e vs %f the way Go's 'g' verb does. Go's rule (from
/// strconv/ftoa.go fmtE/fmtF selection for 'g'): let `exp` be the decimal
/// exponent of the shortest representation; use %e when exp < -4 or exp >= 21,
/// else %f. The exponent in %e form is printed with a sign and at least two
/// digits (e.g. e+12, e-07, e+100).
fn format_double_g(f: f64) -> String {
    if f == 0.0 {
        // Go prints 0 as "0"; our typed form forces a decimal point downstream.
        return if f.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }

    // Rust's {} for f64 yields the shortest decimal that round-trips. Parse out
    // its digits + decimal exponent so we can apply Go's 'g' verb thresholds.
    let shortest = format!("{f}"); // e.g. "1000000000000", "0.0000001", "1.5"
    let neg = shortest.starts_with('-');
    let mag = shortest.trim_start_matches('-');

    // Split mantissa digits from the decimal point; compute the base-10
    // exponent of the leading significant digit.
    let (int_part, frac_part) = match mag.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mag, ""),
    };

    // Significant digits, leading zeros stripped, and the exponent of the
    // most-significant digit relative to the units place.
    let mut digits = String::new();
    let exp10: i32;
    if int_part != "0" && !int_part.is_empty() {
        // exponent = (len(int_part) - 1)
        exp10 = int_part.len() as i32 - 1;
        digits.push_str(int_part);
        digits.push_str(frac_part);
    } else {
        // 0.xxxx -- find first nonzero in frac
        let lead_zeros = frac_part.chars().take_while(|c| *c == '0').count();
        exp10 = -(lead_zeros as i32) - 1;
        digits.push_str(&frac_part[lead_zeros..]);
    }
    // Strip trailing zeros of the significand (shortest form has few, but be safe).
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    if digits.is_empty() {
        digits.push('0');
    }

    let sign = if neg { "-" } else { "" };

    // Go strconv.FormatFloat(f, 'g', -1, 64) -- the shortest-'g' rule cel-go
    // uses for the conformance ground truth. For shortest formatting Go fixes
    // eprec=6, so it switches to %e when exp < -4 or exp >= 6 (exp = position of
    // the leading significant digit). Empirically verified across exp -6..23:
    // exp in [-4, 5] -> %f, otherwise %e (1e6 -> "1e+06", 1e5 -> "100000",
    // 1e-5 -> "1e-05", 1e-4 -> "0.0001").
    if exp10 < -4 || exp10 >= 6 {
        // %e: d.dddde(+/-)XX
        let first = &digits[..1];
        let rest = &digits[1..];
        let mantissa = if rest.is_empty() {
            first.to_string()
        } else {
            format!("{first}.{rest}")
        };
        let esign = if exp10 < 0 { '-' } else { '+' };
        let eabs = exp10.unsigned_abs();
        format!("{sign}{mantissa}e{esign}{eabs:02}")
    } else {
        // %f form -- reconstruct from digits + exp10, then force a decimal point.
        let s = reconstruct_fixed(&digits, exp10);
        let s = if s.contains('.') { s } else { format!("{s}.0") };
        format!("{sign}{s}")
    }
}

/// Reconstruct fixed-point text from significand digits and the base-10
/// exponent of the leading digit (units place exponent).
fn reconstruct_fixed(digits: &str, exp10: i32) -> String {
    let d: Vec<char> = digits.chars().collect();
    if exp10 >= 0 {
        let int_len = exp10 as usize + 1;
        if d.len() <= int_len {
            // pad with trailing zeros: e.g. digits="1", exp=12 -> 1000000000000
            let mut s: String = d.iter().collect();
            s.push_str(&"0".repeat(int_len - d.len()));
            s
        } else {
            let int: String = d[..int_len].iter().collect();
            let frac: String = d[int_len..].iter().collect();
            format!("{int}.{frac}")
        }
    } else {
        // 0.00..digits  with (-exp10 - 1) leading zeros after the point
        let lead = (-exp10 - 1) as usize;
        let frac: String = d.iter().collect();
        format!("0.{}{}", "0".repeat(lead), frac)
    }
}

fn key_to_typed(k: &Key) -> J {
    match k {
        Key::Int(i) => json!({"t":"int","v": i.to_string()}),
        Key::Uint(u) => json!({"t":"uint","v": u.to_string()}),
        Key::String(s) => json!({"t":"string","v": (**s).clone()}),
        Key::Bool(b) => json!({"t":"bool","v": *b}),
    }
}

/// Stable sort key for a map entry: a string that totally orders typed keys.
fn key_sort_string(k: &Key) -> String {
    match k {
        Key::Bool(b) => format!("0:bool:{b}"),
        Key::Int(i) => format!("1:int:{:020}", *i as i128 + (1i128 << 63)),
        Key::Uint(u) => format!("2:uint:{:020}", u),
        Key::String(s) => format!("3:string:{}", s),
    }
}

fn value_to_typed(v: &Value) -> J {
    match v {
        Value::Int(i) => json!({"t":"int","v": i.to_string()}),
        Value::UInt(u) => json!({"t":"uint","v": u.to_string()}),
        Value::Float(f) => json!({"t":"double","v": canonical_double(*f)}),
        Value::String(s) => json!({"t":"string","v": (**s).clone()}),
        Value::Bool(b) => json!({"t":"bool","v": *b}),
        Value::Null => json!({"t":"null"}),
        Value::Bytes(b) => {
            let hex: String = b.iter().map(|byte| format!("{byte:02x}")).collect();
            json!({"t":"bytes","v": hex})
        }
        Value::List(l) => {
            let items: Vec<J> = l.iter().map(value_to_typed).collect();
            json!({"t":"list","v": items})
        }
        Value::Map(m) => {
            let map: &HashMap<Key, Value> = &m.map;
            let mut entries: Vec<(String, J, J)> = map
                .iter()
                .map(|(k, val)| (key_sort_string(k), key_to_typed(k), value_to_typed(val)))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let pairs: Vec<J> = entries
                .into_iter()
                .map(|(_, k, val)| json!([k, val]))
                .collect();
            json!({"t":"map","v": pairs})
        }
        #[cfg(feature = "chrono")]
        Value::Duration(d) => {
            // The typed-canonical duration form is "<secs>.<9-digit-nanos>" with
            // the sign on the WHOLE value. Derive the second count from
            // num_seconds() -- NOT num_nanoseconds(), which overflows i64 for any
            // duration beyond ~292 years (a huge host BINDING) and would
            // saturate/corrupt it. num_seconds() truncates TOWARD ZERO, so for a
            // duration in the open interval (-1s, 0s) it is 0 and the sign lives
            // only in the sub-second remainder; carry the sign from the whole
            // value (negative iff secs < 0, OR secs == 0 and the remainder is
            // negative). Byte-identical to the historical form for every duration
            // OUTSIDE (-1s, 0s) -- including the full second count of a huge
            // binding -- and now also sign-correct inside it.
            let secs = d.num_seconds();
            let rem_nanos = (*d - chrono::Duration::seconds(secs))
                .num_nanoseconds()
                .unwrap_or(0);
            let neg = secs < 0 || (secs == 0 && rem_nanos < 0);
            let sign = if neg { "-" } else { "" };
            let abs_secs = secs.unsigned_abs();
            let abs_nanos = rem_nanos.unsigned_abs();
            json!({"t":"duration","v": format!("{sign}{abs_secs}.{abs_nanos:09}")})
        }
        #[cfg(feature = "chrono")]
        Value::Timestamp(t) => {
            // G14: CEL canonical timestamp string uses 'Z' for the UTC offset,
            // not '+00:00'. chrono's to_rfc3339() emits +00:00; rewrite to a
            // Z-suffixed UTC form to match cel-go's Format("...Z07:00").
            json!({"t":"timestamp","v": rfc3339_utc_z(t)})
        }
        // G3: a type value. The "v" is the canonical cel-go runtime type name
        // (`int`, `google.protobuf.Timestamp`, `type`, ...). This is the
        // ground-truth form the oracle emits for `*types.Type` (TypeName()).
        Value::Type(name) => json!({"t":"type","v": (**name).to_string()}),
        other => json!({"t":"unknown","v": format!("{other:?}")}),
    }
}

/// Format a timestamp as RFC3339 in UTC with a 'Z' suffix (CEL canonical),
/// preserving sub-second precision only when nonzero (matching cel-go's
/// Format("2006-01-02T15:04:05Z07:00") which omits a zero fractional part).
#[cfg(feature = "chrono")]
fn rfc3339_utc_z(t: &chrono::DateTime<chrono::FixedOffset>) -> String {
    use chrono::{SecondsFormat, Utc};
    let utc = t.with_timezone(&Utc);
    // AutoSi: print sub-second only if nonzero, no trailing zeros; UTC -> 'Z'.
    utc.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

/// G13 (wrapper): cel-go's duration -> string form, used by string(duration).
/// cel-go (common/types/duration.go ConvertToType STRING) emits
/// `strconv.FormatFloat(d.Seconds(), 'f', -1, 64) + "s"`: the total seconds as
/// a shortest fixed-point decimal, then a trailing 's'. A whole-second duration
/// has NO decimal point (`1000000s`, not `1000000.0s`); a sub-second duration
/// keeps only the significant fractional digits (`1.5s`, `0.000000001s`).
/// We build it from total nanoseconds (exact) rather than f64 seconds to avoid
/// precision loss on large durations.
#[cfg(feature = "chrono")]
fn format_duration_go(d: &chrono::Duration) -> String {
    // Derive the second count from num_seconds() (truncates TOWARD ZERO; full
    // range) plus the sub-second remainder -- NOT num_nanoseconds(), which
    // overflows i64 for any duration beyond ~292 years and would SATURATE a huge
    // accepted binding (e.g. 9e15 s -> "9223372036.854775807s") instead of its
    // real value. Mirrors the value_to_typed Duration serializer. The sign rides
    // on the WHOLE value (negative iff secs < 0, OR secs == 0 and the sub-second
    // remainder is negative -- the (-1s, 0s) interval). Byte-identical to the
    // prior form for every in-range duration; correct for a huge binding too.
    let whole_secs = d.num_seconds();
    let rem_nanos = (*d - chrono::Duration::seconds(whole_secs))
        .num_nanoseconds()
        .unwrap_or(0);
    let neg = whole_secs < 0 || (whole_secs == 0 && rem_nanos < 0);
    let sign = if neg { "-" } else { "" };
    let abs_secs = whole_secs.unsigned_abs();
    let abs_nanos = rem_nanos.unsigned_abs();
    if abs_nanos == 0 {
        format!("{sign}{abs_secs}s")
    } else {
        // Trim trailing zeros from the 9-digit fractional part.
        let frac = format!("{abs_nanos:09}");
        let frac = frac.trim_end_matches('0');
        format!("{sign}{abs_secs}.{frac}s")
    }
}

// ---------------------------------------------------------------------------
// Deserializer: typed canonical JSON -> cel::Value (for bindings)
// ---------------------------------------------------------------------------

fn typed_to_value(j: &J) -> Result<Value, String> {
    let obj = j.as_object().ok_or("binding must be a typed object")?;
    let t = obj
        .get("t")
        .and_then(|v| v.as_str())
        .ok_or("binding missing 't'")?;
    match t {
        "int" => {
            let s = obj
                .get("v")
                .and_then(|v| v.as_str())
                .ok_or("int needs string v")?;
            let i: i64 = s.parse().map_err(|_| format!("bad int '{s}'"))?;
            Ok(Value::Int(i))
        }
        "uint" => {
            let s = obj
                .get("v")
                .and_then(|v| v.as_str())
                .ok_or("uint needs string v")?;
            let u: u64 = s.parse().map_err(|_| format!("bad uint '{s}'"))?;
            Ok(Value::UInt(u))
        }
        "double" => {
            let vv = obj.get("v").ok_or("double needs v")?;
            let f = if let Some(s) = vv.as_str() {
                match s {
                    "inf" => f64::INFINITY,
                    "-inf" => f64::NEG_INFINITY,
                    "nan" => f64::NAN,
                    _ => s.parse().map_err(|_| format!("bad double '{s}'"))?,
                }
            } else if let Some(n) = vv.as_f64() {
                n
            } else {
                return Err("double v must be string or number".into());
            };
            Ok(Value::Float(f))
        }
        "string" => {
            let s = obj
                .get("v")
                .and_then(|v| v.as_str())
                .ok_or("string needs v")?;
            Ok(Value::String(Arc::new(s.to_string())))
        }
        "bool" => {
            let b = obj
                .get("v")
                .and_then(|v| v.as_bool())
                .ok_or("bool needs v")?;
            Ok(Value::Bool(b))
        }
        "null" => Ok(Value::Null),
        // G3: a type value binding. The "v" is the canonical type name.
        "type" => {
            let s = obj
                .get("v")
                .and_then(|v| v.as_str())
                .ok_or("type needs string v")?;
            Ok(Value::Type(Arc::from(s)))
        }
        "bytes" => {
            let s = obj
                .get("v")
                .and_then(|v| v.as_str())
                .ok_or("bytes needs hex v")?;
            let bytes = hex_decode(s)?;
            Ok(Value::Bytes(Arc::new(bytes)))
        }
        "list" => {
            let arr = obj
                .get("v")
                .and_then(|v| v.as_array())
                .ok_or("list needs v array")?;
            let items: Result<Vec<Value>, String> = arr.iter().map(typed_to_value).collect();
            Ok(Value::List(Arc::new(items?)))
        }
        "map" => {
            let arr = obj
                .get("v")
                .and_then(|v| v.as_array())
                .ok_or("map needs v array")?;
            let mut hm: HashMap<Key, Value> = HashMap::new();
            for pair in arr {
                let p = pair.as_array().ok_or("map entry must be [k,v]")?;
                if p.len() != 2 {
                    return Err("map entry must have 2 elements".into());
                }
                let key = typed_to_key(&p[0])?;
                let val = typed_to_value(&p[1])?;
                hm.insert(key, val);
            }
            Ok(Value::Map(Map { map: Arc::new(hm) }))
        }
        #[cfg(feature = "chrono")]
        "duration" => {
            let s = obj
                .get("v")
                .and_then(|v| v.as_str())
                .ok_or("duration needs v")?;
            // Stored form is "<secs>.<nanos>"; reconstruct chrono::Duration with a
            // CHECKED builder. split_secs_nanos does NO range check, and chrono's
            // Duration::seconds() + `+` PANIC on a value beyond the representable
            // TimeDelta range (a boundary wire string like
            // "9223372036854775.900000000") -- a panic would TRAP the wasm reactor
            // (ENGINE_PANIC / RELAY-CEL-PANIC) instead of the clean bad-binding
            // error the bindings loop maps a typed_to_value Err to (RELAY-CEL-006),
            // contradicting the no-panic contract the duration-arithmetic path
            // holds. nanos is bounded to +/-999_999_999 by split_secs_nanos so
            // nanoseconds(nanos) cannot panic; only secs construction and the sum
            // can overflow, and both are checked here.
            let (secs, nanos) = split_secs_nanos(s)?;
            let base = chrono::Duration::try_seconds(secs)
                .ok_or("duration seconds out of representable range")?;
            let dur = base
                .checked_add(&chrono::Duration::nanoseconds(nanos))
                .ok_or("duration out of representable range")?;
            Ok(Value::Duration(dur))
        }
        #[cfg(feature = "chrono")]
        "timestamp" => {
            let s = obj
                .get("v")
                .and_then(|v| v.as_str())
                .ok_or("timestamp needs v")?;
            chrono::DateTime::parse_from_rfc3339(s)
                .map(Value::Timestamp)
                .map_err(|e| format!("bad timestamp '{s}': {e}"))
        }
        other => Err(format!("unsupported binding type '{other}'")),
    }
}

#[cfg(feature = "chrono")]
fn split_secs_nanos(s: &str) -> Result<(i64, i64), String> {
    let (sec_str, nano_str) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, "0"),
    };
    let secs: i64 = sec_str.parse().map_err(|_| format!("bad duration secs '{s}'"))?;
    // pad/truncate the fractional part to 9 digits
    let mut nano_digits = nano_str.to_string();
    while nano_digits.len() < 9 {
        nano_digits.push('0');
    }
    nano_digits.truncate(9);
    let mut nanos: i64 = nano_digits.parse().map_err(|_| format!("bad duration nanos '{s}'"))?;
    // Apply the sign from the WHOLE string, not just `secs < 0`: a duration in
    // (-1s, 0s) serializes as "-0.<nanos>", whose secs field parses to 0 (the
    // sign lives only on the leading '-'), so a `secs < 0` test would miss it and
    // decode a negative sub-second duration as positive.
    if s.starts_with('-') {
        nanos = -nanos;
    }
    Ok((secs, nanos))
}

fn typed_to_key(j: &J) -> Result<Key, String> {
    let v = typed_to_value(j)?;
    match v {
        Value::Int(i) => Ok(Key::Int(i)),
        Value::UInt(u) => Ok(Key::Uint(u)),
        Value::String(s) => Ok(Key::String(s)),
        Value::Bool(b) => Ok(Key::Bool(b)),
        _ => Err("invalid map key type".into()),
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let nib = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("bad hex char '{}'", c as char)),
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        out.push((nib(bytes[i])? << 4) | nib(bytes[i + 1])?);
        i += 2;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// WS-J: deterministic in-wasm fuel budget tests (TDD -- written RED first).
//
// These drive eval_impl directly (the same entrypoint the reactor `eval` export
// uses), so they exercise the real eval pipeline + the JSON request/response
// contract. They run on the NATIVE host target via `cargo test` (the cdylib
// also builds as a test binary), so no wasm host is needed to assert the engine
// semantics. The wasm build (build.sh) ships the same code path.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod fuel_tests {
    use super::*;

    /// Drive eval_impl with a raw request JSON string and parse the response.
    fn eval_json(req: &str) -> J {
        let out = eval_impl(req.as_bytes());
        serde_json::from_slice(&out).expect("response is valid JSON")
    }

    /// A pathological expression: a triple-nested `.map` comprehension. With a
    /// small fuel budget it must exhaust; with fuel absent it evaluates normally.
    /// 10*10*10 inner iterations, each re-entering resolve_val several times, far
    /// exceeds a budget of 8. This is the CEL expression body only; the request
    /// JSON (with the closing `"`/`}` and the optional fuel field) is built by
    /// `pathological_with_fuel`.
    const PATHOLOGICAL_EXPR: &str =
        "[0,1,2,3,4,5,6,7,8,9].map(x, [0,1,2,3,4,5,6,7,8,9].map(y, [0,1,2,3,4,5,6,7,8,9].map(z, x + y + z)))";

    fn pathological_with_fuel(fuel: Option<u64>) -> String {
        match fuel {
            Some(n) => {
                format!(r#"{{"expr":"{PATHOLOGICAL_EXPR}","fuel_budget":{n}}}"#)
            }
            None => format!(r#"{{"expr":"{PATHOLOGICAL_EXPR}"}}"#),
        }
    }

    #[test]
    fn fuel_exhaustion_returns_relay_cel_003_timeout() {
        let resp = eval_json(&pathological_with_fuel(Some(8)));
        assert_eq!(resp["ok"], J::Bool(false), "exhausted eval must fail: {resp}");
        assert_eq!(
            resp["code"], J::String(codes::TIMEOUT.to_string()),
            "fuel exhaustion must surface RELAY-CEL-003: {resp}"
        );
        assert_eq!(
            resp["subtype"], J::String(subtypes::TIMEOUT.to_string()),
            "fuel exhaustion must carry the TIMEOUT subtype: {resp}"
        );
    }

    #[test]
    fn fuel_absent_evaluates_unbounded() {
        let resp = eval_json(&pathological_with_fuel(None));
        assert_eq!(
            resp["ok"], J::Bool(true),
            "fuel-absent eval must succeed unbounded: {resp}"
        );
        assert!(resp.get("value").is_some(), "must carry a value: {resp}");
        assert!(
            resp.get("code").is_none(),
            "an unbounded success carries no error code: {resp}"
        );
    }

    #[test]
    fn fuel_disabled_sentinel_evaluates_unbounded() {
        // A fuel_budget of 0 is the disabled sentinel: no limit, like absent.
        let resp = eval_json(&pathological_with_fuel(Some(0)));
        assert_eq!(
            resp["ok"], J::Bool(true),
            "fuel_budget=0 (disabled sentinel) must be unbounded: {resp}"
        );
    }

    #[test]
    fn generous_budget_evaluates_to_a_value() {
        // The SAME expression with a generous budget returns a value -- proving
        // the cap is a fuel limit, not a hard rejection of the expression.
        let resp = eval_json(&pathological_with_fuel(Some(1_000_000)));
        assert_eq!(
            resp["ok"], J::Bool(true),
            "generous budget must let the expression finish: {resp}"
        );
        assert!(resp.get("value").is_some(), "must carry a value: {resp}");
    }

    #[test]
    fn fuel_accounting_is_deterministic() {
        // Two independent evals of the SAME expression with the SAME (exhausting)
        // budget must produce byte-identical output (the counter is deterministic,
        // never host/time/iteration-order dependent).
        let a = eval_impl(pathological_with_fuel(Some(8)).as_bytes());
        let b = eval_impl(pathological_with_fuel(Some(8)).as_bytes());
        assert_eq!(a, b, "same expr+budget twice -> identical output bytes");

        // And a successful bounded run is likewise byte-identical run-to-run.
        let c = eval_impl(pathological_with_fuel(Some(1_000_000)).as_bytes());
        let d = eval_impl(pathological_with_fuel(Some(1_000_000)).as_bytes());
        assert_eq!(c, d, "same expr+generous budget twice -> identical bytes");
    }

    #[test]
    fn fuel_off_is_byte_identical_to_no_fuel_field() {
        // VAL-002: the disabled path must be byte-identical to the pre-WS-J engine
        // -- omitting the field and setting the disabled sentinel both produce the
        // exact same response bytes as a plain request.
        let plain = eval_impl(br#"{"expr":"1 + 2 + 3"}"#);
        let absent = eval_impl(br#"{"expr":"1 + 2 + 3"}"#);
        let sentinel = eval_impl(br#"{"expr":"1 + 2 + 3","fuel_budget":0}"#);
        assert_eq!(plain, absent);
        assert_eq!(
            plain, sentinel,
            "fuel_budget=0 must not perturb the response bytes vs the plain request"
        );
    }

    #[test]
    fn udf_trace_attached_on_error_envelope() {
        // BATCHED FIX: a UDF that RUNS and records a trace, then the eval ERRORS.
        // The error envelope must STILL carry the drained udf_trace (partial UDF
        // forensics survive a failed eval). relay.tool_arg runs first (recording a
        // trace entry), then `size(<string>) + (1 / 0)` forces a runtime
        // division-by-zero EXEC error -- the tool_arg call is NOT short-circuited
        // (`+` evaluates both operands), so its trace is recorded before the error.
        let resp = eval_json(
            r#"{"expr":"size(relay.tool_arg({'args': {'k': 'v'}}, 'k')) + (1 / 0)"}"#,
        );
        assert_eq!(resp["ok"], J::Bool(false), "this eval must error: {resp}");
        assert!(
            resp.get("udf_trace").is_some(),
            "a failed eval that ran a UDF must STILL carry udf_trace: {resp}"
        );
        let trace = &resp["udf_trace"];
        assert!(
            trace.get("relay.tool_arg").is_some(),
            "the executed UDF must appear in the error-envelope trace: {resp}"
        );
    }

    #[test]
    fn no_udf_trace_field_on_error_when_no_udf_ran() {
        // An error that runs NO udf still omits the field (no empty object).
        let resp = eval_json(r#"{"expr":"1 / 0"}"#);
        assert_eq!(resp["ok"], J::Bool(false));
        assert!(
            resp.get("udf_trace").is_none(),
            "no UDF ran -> no udf_trace field on the error envelope: {resp}"
        );
    }
}
