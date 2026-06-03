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
// size, G12 idempotent conversions), and the structured error envelope. The
// HARD semantic gaps (G3 type-value model, G4 macros2, G6 cross-numeric
// equality) are deferred to the vendored fork -- see HARDENING.md.

use std::alloc::{alloc as sys_alloc, dealloc as sys_dealloc, Layout};
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
    /// Runtime execution error (overload missing, division by zero, etc.).
    pub const EXEC: &str = "RELAY-CEL-004";
    /// Malformed request envelope (bad JSON, missing expr, bad binding).
    pub const REQUEST: &str = "RELAY-CEL-006";
}

struct CelError {
    code: &'static str,
    message: String,
}

impl CelError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        CelError {
            code,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// eval pipeline
// ---------------------------------------------------------------------------

fn eval_impl(input: &[u8]) -> Vec<u8> {
    let result = (|| -> Result<J, CelError> {
        let req: J = serde_json::from_slice(input)
            .map_err(|e| CelError::new(codes::REQUEST, e.to_string()))?;
        let expr = req
            .get("expr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CelError::new(codes::REQUEST, "missing 'expr'"))?;

        let program = Program::compile(expr)
            .map_err(|e| CelError::new(codes::COMPILE, format!("compile: {e:?}")))?;

        // G1 FENCE: cel 0.13 PANICS (wasm trap) on struct/message construction
        // (objects.rs resolve: `Expr::Struct(_) => todo!()`, map StructField
        // `panic!("WAT?")`, `Expr::Unspecified => panic!()`). A panic in an
        // evidence-grade evaluator is a P0 DoS surface. Relay's profile excludes
        // proto/message construction entirely, so we reject it with a CLEAN
        // error BEFORE execute() can reach the panic.
        if let Some(reason) = find_profile_rejection(program.expression()) {
            return Err(CelError::new(codes::PROFILE, reason));
        }

        let mut context = relay_context();

        if let Some(bindings) = req.get("bindings").and_then(|v| v.as_object()) {
            for (name, typed) in bindings {
                let v = typed_to_value(typed).map_err(|e| {
                    CelError::new(codes::REQUEST, format!("binding '{name}': {e}"))
                })?;
                context.add_variable_from_value(name.clone(), v);
            }
        }

        let value = program
            .execute(&context)
            .map_err(|e| CelError::new(codes::EXEC, format!("exec: {e:?}")))?;
        Ok(value_to_typed(&value))
    })();

    let out = match result {
        Ok(v) => json!({"ok": true, "value": v}),
        Err(e) => json!({"ok": false, "error": e.message, "code": e.code}),
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

/// Walk the parsed AST. Return Some(reason) if it contains any node that the
/// Relay CEL profile rejects AND that cel 0.13 would panic on at execution
/// time. Currently: struct/message construction (`Foo{...}`,
/// `google.protobuf.BoolValue{...}`), struct-field entries embedded in
/// map/list literals, and Unspecified nodes.
fn find_profile_rejection(expr: &IdedExpr) -> Option<String> {
    match &expr.expr {
        Expr::Struct(s) => Some(format!(
            "Relay CEL profile disables message/struct construction '{}{{...}}': \
             proto/message values are not part of the Relay contract surface \
             (RELAY-CEL-PROFILE-STRUCT-DISABLED)",
            s.type_name
        )),
        Expr::Unspecified => Some(
            "Relay CEL profile: unspecified expression node \
             (RELAY-CEL-PROFILE-STRUCT-DISABLED)"
                .to_string(),
        ),
        Expr::Call(call) => {
            if let Some(target) = &call.target {
                if let Some(r) = find_profile_rejection(target) {
                    return Some(r);
                }
            }
            call.args.iter().find_map(find_profile_rejection)
        }
        Expr::Comprehension(c) => find_profile_rejection(&c.iter_range)
            .or_else(|| find_profile_rejection(&c.accu_init))
            .or_else(|| find_profile_rejection(&c.loop_cond))
            .or_else(|| find_profile_rejection(&c.loop_step))
            .or_else(|| find_profile_rejection(&c.result)),
        Expr::List(l) => l.elements.iter().find_map(find_profile_rejection),
        Expr::Map(m) => m.entries.iter().find_map(|e| entry_rejection(&e.expr)),
        Expr::Select(s) => find_profile_rejection(&s.operand),
        Expr::Ident(_) | Expr::Literal(_) => None,
    }
}

fn entry_rejection(entry: &EntryExpr) -> Option<String> {
    match entry {
        // A StructField entry inside a Map literal is exactly the construct that
        // makes cel 0.13 `panic!("WAT?")` (objects.rs Expr::Map). Fence it.
        EntryExpr::StructField(_) => Some(
            "Relay CEL profile disables struct-field construction \
             (RELAY-CEL-PROFILE-STRUCT-DISABLED)"
                .to_string(),
        ),
        EntryExpr::MapEntry(e) => {
            find_profile_rejection(&e.key).or_else(|| find_profile_rejection(&e.value))
        }
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

    ctx
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

/// G12 timestamp(): accept an already-`timestamp` value idempotently; otherwise
/// parse from an RFC3339 string.
#[cfg(feature = "chrono")]
fn relay_timestamp(arg: Value) -> Result<Value, cel::ExecutionError> {
    match arg {
        Value::Timestamp(t) => Ok(Value::Timestamp(t)),
        Value::String(s) => parse_timestamp_string(&s),
        other => Err(cel::ExecutionError::function_error(
            "timestamp",
            format!("cannot convert {other:?} to timestamp"),
        )),
    }
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

/// Parse an RFC3339 timestamp string into Value::Timestamp.
#[cfg(feature = "chrono")]
fn parse_timestamp_string(s: &str) -> Result<Value, cel::ExecutionError> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(Value::Timestamp)
        .map_err(|e| {
            cel::ExecutionError::function_error("timestamp", format!("invalid timestamp '{s}': {e}"))
        })
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
            let secs = d.num_seconds();
            let nanos = (*d - chrono::Duration::seconds(secs))
                .num_nanoseconds()
                .unwrap_or(0);
            json!({"t":"duration","v": format!("{secs}.{:09}", nanos.abs())})
        }
        #[cfg(feature = "chrono")]
        Value::Timestamp(t) => {
            // G14: CEL canonical timestamp string uses 'Z' for the UTC offset,
            // not '+00:00'. chrono's to_rfc3339() emits +00:00; rewrite to a
            // Z-suffixed UTC form to match cel-go's Format("...Z07:00").
            json!({"t":"timestamp","v": rfc3339_utc_z(t)})
        }
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
            // Stored form is "<secs>.<nanos>"; reconstruct chrono::Duration.
            let (secs, nanos) = split_secs_nanos(s)?;
            Ok(Value::Duration(
                chrono::Duration::seconds(secs) + chrono::Duration::nanoseconds(nanos),
            ))
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
    if secs < 0 {
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
