// celoracle: cel-spec textproto parser + cel-go reference oracle.
//
// For every SimpleTest in every *.textproto file under -corpus, emit one JSON
// record to stdout (JSON-lines):
//
//	{
//	  "file": "...", "section": "...", "name": "...", "expr": "...",
//	  "disable_check": bool, "disable_macros": bool,
//	  "bindings": {<name>: <typed-value>} | null,   // typed-canonical form
//	  "expected_kind": "value" | "error" | "any_errors" | "unknown" | "typed_value" | "unsupported",
//	  "expected_typed": <typed-value> | null,        // when expected_kind in {value, typed_value}
//	  "celgo_kind": "value" | "error",
//	  "celgo_typed": <typed-value> | null,
//	  "celgo_error": "<msg>" | null,
//	  "skip_reason": "<why this test is structurally unmeasurable>" | null
//	}
//
// The typed-canonical form matches /tmp/cel-wasm-spike/src/lib.rs value_to_typed:
//   int    {"t":"int","v":"<dec>"}      uint  {"t":"uint","v":"<dec>"}
//   double {"t":"double","v":"<canon>"} string{"t":"string","v":"..."}
//   bool   {"t":"bool","v":true|false}  null  {"t":"null"}
//   bytes  {"t":"bytes","v":"<hex>"}    list  {"t":"list","v":[...]}
//   map    {"t":"map","v":[[k,v],...]} (sorted)  type {"t":"type","v":"<name>"}
//   duration {"t":"duration","v":"<s.ns>"}  timestamp {"t":"timestamp","v":"<rfc3339>"}
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	celexpr "cel.dev/expr"
	celtest "cel.dev/expr/conformance/test"

	// Register the conformance TestAllTypes message descriptors so that
	// textproto Any-typed object_value fields (used by dynamic/parse/
	// type_deduction) resolve during prototext.Unmarshal.
	_ "cel.dev/expr/conformance/proto2"
	_ "cel.dev/expr/conformance/proto3"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"

	"google.golang.org/protobuf/encoding/prototext"
)

type record struct {
	File          string                 `json:"file"`
	Section       string                 `json:"section"`
	Name          string                 `json:"name"`
	Expr          string                 `json:"expr"`
	Container     string                 `json:"container"`
	DisableCheck  bool                   `json:"disable_check"`
	DisableMacros bool                   `json:"disable_macros"`
	Bindings      map[string]interface{} `json:"bindings"`
	ExpectedKind  string                 `json:"expected_kind"`
	ExpectedTyped interface{}            `json:"expected_typed"`
	CelgoKind     string                 `json:"celgo_kind"`
	CelgoTyped    interface{}            `json:"celgo_typed"`
	CelgoError    string                 `json:"celgo_error"`
	SkipReason    string                 `json:"skip_reason"`
}

func canonicalDouble(f float64) string {
	if math.IsNaN(f) {
		return "nan"
	}
	if math.IsInf(f, 1) {
		return "inf"
	}
	if math.IsInf(f, -1) {
		return "-inf"
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s = s + ".0"
	}
	return s
}

// refToTyped converts a cel-go ref.Val into the typed-canonical JSON structure.
// Returns (typed, ok). ok=false if the value is an error/unknown/unsupported.
func refToTyped(v ref.Val) (interface{}, bool) {
	if v == nil {
		return nil, false
	}
	switch vv := v.(type) {
	case types.Bool:
		return map[string]interface{}{"t": "bool", "v": bool(vv)}, true
	case types.Int:
		return map[string]interface{}{"t": "int", "v": strconv.FormatInt(int64(vv), 10)}, true
	case types.Uint:
		return map[string]interface{}{"t": "uint", "v": strconv.FormatUint(uint64(vv), 10)}, true
	case types.Double:
		return map[string]interface{}{"t": "double", "v": canonicalDouble(float64(vv))}, true
	case types.String:
		return map[string]interface{}{"t": "string", "v": string(vv)}, true
	case types.Bytes:
		var sb strings.Builder
		for _, b := range []byte(vv) {
			fmt.Fprintf(&sb, "%02x", b)
		}
		return map[string]interface{}{"t": "bytes", "v": sb.String()}, true
	case types.Null:
		return map[string]interface{}{"t": "null"}, true
	case types.Duration:
		// "[-]seconds.nanos" with the sign on the WHOLE value -- matching the crate
		// serializer (crate/src/lib.rs value_to_typed Duration arm). A Go
		// time.Duration is int64 nanoseconds, so the total is exact; deriving secs
		// by truncation (int64(d.Seconds())) and abs()-ing the nanos LOSES the sign
		// for a duration in the open interval (-1s, 0s) (e.g. -0.25s -> "0.25",
		// POSITIVE). Carry the sign from the total instead so the oracle agrees
		// with the (sign-correct) wasm for every duration, not just |d| >= 1s.
		// Byte-identical to the prior form for every duration OUTSIDE (-1s, 0s).
		d := vv.Duration
		totalNanos := d.Nanoseconds()
		neg := totalNanos < 0
		// Magnitude in uint64 to avoid the signed-negation overflow at
		// math.MinInt64 (the minimum time.Duration, -9223372036.854775808s):
		// `-math.MinInt64` overflows int64 and would leave the value negative.
		// uint64(-(n+1))+1 computes |n| exactly for every negative int64.
		var abs uint64
		if neg {
			abs = uint64(-(totalNanos + 1)) + 1
		} else {
			abs = uint64(totalNanos)
		}
		secs := abs / 1_000_000_000
		nanos := abs % 1_000_000_000
		sign := ""
		if neg {
			sign = "-"
		}
		return map[string]interface{}{"t": "duration", "v": fmt.Sprintf("%s%d.%09d", sign, secs, nanos)}, true
	case types.Timestamp:
		return map[string]interface{}{"t": "timestamp", "v": vv.Format("2006-01-02T15:04:05Z07:00")}, true
	case *types.Type:
		return map[string]interface{}{"t": "type", "v": vv.TypeName()}, true
	}

	// Lists and maps via traits.
	if lister, ok := v.(traits.Lister); ok {
		var items []interface{}
		it := lister.Iterator()
		for it.HasNext() == types.True {
			el := it.Next()
			t, ok := refToTyped(el)
			if !ok {
				return nil, false
			}
			items = append(items, t)
		}
		if items == nil {
			items = []interface{}{}
		}
		return map[string]interface{}{"t": "list", "v": items}, true
	}
	if mapper, ok := v.(traits.Mapper); ok {
		type kv struct {
			sortKey string
			pair    []interface{}
		}
		var entries []kv
		it := mapper.Iterator()
		for it.HasNext() == types.True {
			k := it.Next()
			val := mapper.Get(k)
			kt, ok1 := refToTyped(k)
			vt, ok2 := refToTyped(val)
			if !ok1 || !ok2 {
				return nil, false
			}
			entries = append(entries, kv{sortKey: mapKeySort(kt), pair: []interface{}{kt, vt}})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].sortKey < entries[j].sortKey })
		pairs := make([]interface{}, 0, len(entries))
		for _, e := range entries {
			pairs = append(pairs, e.pair)
		}
		return map[string]interface{}{"t": "map", "v": pairs}, true
	}

	// types.Err, types.Unknown, and anything else.
	return nil, false
}

// mapKeySort mirrors the wasm key_sort_string ordering so map entries are
// byte-comparable across engines.
func mapKeySort(kt interface{}) string {
	m, ok := kt.(map[string]interface{})
	if !ok {
		return "9:" + fmt.Sprintf("%v", kt)
	}
	t, _ := m["t"].(string)
	switch t {
	case "bool":
		return fmt.Sprintf("0:bool:%v", m["v"])
	case "int":
		// pad like wasm: i128 + 2^63, 20 digits
		s, _ := m["v"].(string)
		i, _ := strconv.ParseInt(s, 10, 64)
		shifted := uint64(i) + (uint64(1) << 63)
		return fmt.Sprintf("1:int:%020d", shifted)
	case "uint":
		s, _ := m["v"].(string)
		u, _ := strconv.ParseUint(s, 10, 64)
		return fmt.Sprintf("2:uint:%020d", u)
	case "string":
		s, _ := m["v"].(string)
		return "3:string:" + s
	}
	return "9:" + t
}

func protoValueToTyped(pv *celexpr.Value, adapter types.Adapter) (interface{}, bool, string) {
	if pv == nil || pv.GetKind() == nil {
		// An empty/zero Value message (oneof kind unset). ProtoAsValue panics
		// on this, so we mark it unsupported rather than guess a mapping.
		return nil, false, "empty proto Value (kind oneof unset)"
	}
	rv, err := cel.ProtoAsValue(adapter, pv)
	if err != nil {
		return nil, false, err.Error()
	}
	t, ok := refToTyped(rv)
	if !ok {
		return nil, false, "expected value not representable in typed form"
	}
	return t, true, ""
}

func main() {
	corpus := flag.String("corpus", "", "directory of *.textproto files")
	only := flag.String("only", "", "comma-separated list of file base names (without .textproto) to include")
	flag.Parse()
	if *corpus == "" {
		fmt.Fprintln(os.Stderr, "need -corpus")
		os.Exit(2)
	}

	includes := map[string]bool{}
	if *only != "" {
		for _, f := range strings.Split(*only, ",") {
			includes[strings.TrimSpace(f)] = true
		}
	}

	files, _ := filepath.Glob(filepath.Join(*corpus, "*.textproto"))
	sort.Strings(files)

	enc := json.NewEncoder(os.Stdout)

	// Shared adapter for proto->ref.Val conversion.
	baseEnv, err := cel.NewEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "env:", err)
		os.Exit(1)
	}
	adapter := types.DefaultTypeAdapter

	for _, fpath := range files {
		base := strings.TrimSuffix(filepath.Base(fpath), ".textproto")
		if len(includes) > 0 && !includes[base] {
			continue
		}
		data, err := os.ReadFile(fpath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", fpath, err)
			continue
		}
		var tf celtest.SimpleTestFile
		if err := prototext.Unmarshal(data, &tf); err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", fpath, err)
			continue
		}
		for _, sec := range tf.GetSection() {
			for _, t := range sec.GetTest() {
				rec := record{
					File:          base,
					Section:       sec.GetName(),
					Name:          t.GetName(),
					Expr:          t.GetExpr(),
					Container:     t.GetContainer(),
					DisableCheck:  t.GetDisableCheck(),
					DisableMacros: t.GetDisableMacros(),
				}

				// Bindings: ExprValue -> Value -> typed.
				if len(t.GetBindings()) > 0 {
					rec.Bindings = map[string]interface{}{}
					for name, ev := range t.GetBindings() {
						pv := ev.GetValue()
						if pv == nil {
							rec.SkipReason = "binding is not a concrete value (unknown/error binding)"
							continue
						}
						typed, ok, _ := protoValueToTyped(pv, adapter)
						if !ok {
							rec.SkipReason = "binding value not representable in typed form"
							continue
						}
						rec.Bindings[name] = typed
					}
				}

				// Expected matcher.
				switch m := t.GetResultMatcher().(type) {
				case *celtest.SimpleTest_Value:
					typed, ok, reason := protoValueToTyped(m.Value, adapter)
					if ok {
						rec.ExpectedKind = "value"
						rec.ExpectedTyped = typed
					} else {
						rec.ExpectedKind = "unsupported"
						rec.SkipReason = "expected value unsupported: " + reason
					}
				case *celtest.SimpleTest_TypedResult:
					pv := m.TypedResult.GetResult()
					typed, ok, reason := protoValueToTyped(pv, adapter)
					if ok {
						rec.ExpectedKind = "typed_value"
						rec.ExpectedTyped = typed
					} else {
						rec.ExpectedKind = "unsupported"
						rec.SkipReason = "typed_result unsupported: " + reason
					}
				case *celtest.SimpleTest_EvalError:
					rec.ExpectedKind = "error"
				case *celtest.SimpleTest_AnyEvalErrors:
					rec.ExpectedKind = "any_errors"
				case *celtest.SimpleTest_Unknown, *celtest.SimpleTest_AnyUnknowns:
					rec.ExpectedKind = "unknown"
					if rec.SkipReason == "" {
						rec.SkipReason = "unknown-result matcher not measured"
					}
				case nil:
					// Per spec: unspecified result defaults to bool true.
					rec.ExpectedKind = "value"
					rec.ExpectedTyped = map[string]interface{}{"t": "bool", "v": true}
				default:
					rec.ExpectedKind = "unsupported"
					rec.SkipReason = "unhandled result matcher"
				}

				// cel-go oracle evaluation.
				gokind, gotyped, goerr := evalCelGo(baseEnv, t)
				rec.CelgoKind = gokind
				rec.CelgoTyped = gotyped
				rec.CelgoError = goerr

				_ = enc.Encode(&rec)
			}
		}
	}
}

// evalCelGo runs the expression through cel-go, returning ("value", typed, "")
// or ("error", nil, msg). Standard macros + the in-scope CEL extensions
// (two-variable comprehensions/macros2, strings, math, lists, sets, encoders,
// bindings, optional types) are enabled so cel-go faithfully matches the
// textproto ground truth for the in-scope feature surface. The container is set
// when the test declares one, so namespace resolution works. We Compile
// (type-check) when possible and fall back to Parse for disable_check cases.
func evalCelGo(baseEnv *cel.Env, t *celtest.SimpleTest) (string, interface{}, string) {
	opts := []cel.EnvOption{
		cel.OptionalTypes(),
		ext.TwoVarComprehensions(),
		ext.Strings(),
		ext.Math(),
		ext.Lists(),
		ext.Sets(),
		ext.Encoders(),
		ext.Bindings(),
	}
	if c := t.GetContainer(); c != "" {
		opts = append(opts, cel.Container(c))
	}
	// Declare bindings as dyn variables so checked compile can resolve them
	// (including dotted/container-qualified names like x.y).
	for name := range t.GetBindings() {
		opts = append(opts, cel.Variable(name, cel.DynType))
	}
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return "error", nil, "env: " + err.Error()
	}

	var ast *cel.Ast
	if !t.GetDisableCheck() {
		a, iss := env.Compile(t.GetExpr())
		if iss == nil || iss.Err() == nil {
			ast = a
		}
	}
	if ast == nil {
		a, iss := env.Parse(t.GetExpr())
		if iss != nil && iss.Err() != nil {
			return "error", nil, "parse: " + iss.Err().Error()
		}
		ast = a
	}

	prg, err := env.Program(ast)
	if err != nil {
		return "error", nil, "program: " + err.Error()
	}

	activation := map[string]interface{}{}
	adapter := types.DefaultTypeAdapter
	for name, ev := range t.GetBindings() {
		pv := ev.GetValue()
		if pv == nil {
			continue
		}
		rv, cerr := cel.ProtoAsValue(adapter, pv)
		if cerr != nil {
			return "error", nil, "binding-convert: " + cerr.Error()
		}
		activation[name] = rv
	}

	out, _, err := prg.Eval(activation)
	if err != nil {
		return "error", nil, "eval: " + err.Error()
	}
	if types.IsError(out) {
		return "error", nil, "eval-error"
	}
	typed, ok := refToTyped(out)
	if !ok {
		return "error", nil, "result-not-typed"
	}
	return "value", typed, ""
}
