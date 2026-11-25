package cel

import (
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"testing"

	"github.com/google/cel-go/cel"
	"gotest.tools/assert"
)

// compileCases covers sources that would compile or evaluate differently if compiles left state
// behind in the shared environment. TestCompile runs them in order, so a case that declares
// something comes before one that must not see it.
var compileCases = []struct {
	name     string
	source   string
	wantType *cel.Type
	want     any    // result of the evaluation against compileCasesInput, if not nil
	wantErr  string // compile error
}{
	{name: "syntax error", source: `request.`,
		wantErr: "ERROR: <input>:1:9: Syntax error: no viable alternative at input '.'\n | request.\n | ........^"},
	{name: "predicate", source: `auth.identity.username == 'john'`, wantType: cel.BoolType, want: true},
	{name: "comprehension variable", source: `[1].exists(x, x > 0)`, wantType: cel.BoolType, want: true},
	{name: "comprehension variable doesn't stay declared", source: `x > 0`, wantType: cel.BoolType,
		wantErr: "ERROR: <input>:1:1: undeclared reference to 'x' (in container '')\n | x > 0\n | ^"},
	{name: "unknown function", source: `nope(auth)`,
		wantErr: "ERROR: <input>:1:5: undeclared reference to 'nope' (in container '')\n | nope(auth)\n | ....^"},
	{name: "no matching overload", source: `'a' + 1`,
		wantErr: "ERROR: <input>:1:5: found no matching overload for '_+_' applied to '(string, int)'\n | 'a' + 1\n | ....^"},
	{name: "wrong output type", source: `'a' + 'b'`, wantType: cel.BoolType,
		wantErr: "type error: got string, wanted bool output type"},
	{name: "position on a later line", source: "auth.identity.username ==\n  'a' &&\n  nope", wantType: cel.BoolType,
		wantErr: "ERROR: <input>:3:3: undeclared reference to 'nope' (in container '')\n |   nope\n | ..^"},
	{name: "string extension", source: `'Hello'.lowerAscii()`, want: "hello"},
	{name: "optional field", source: `request.?http.orValue('none')`, want: "none"},
	// Protobuf type names are resolved through the environment's type provider.
	{name: "protobuf message", source: `google.protobuf.Value{string_value: 'x'}`, want: "x"},
	{name: "protobuf enum", source: `google.protobuf.NullValue.NULL_VALUE`, want: int64(0)},
	{name: "type not declared as a value", source: `type(auth) == google.protobuf.Struct`,
		wantErr: "reference to undefined type: google.protobuf.Struct"},
	{name: "unknown protobuf message", source: `google.protobuf.Nope{}`,
		wantErr: "ERROR: <input>:1:21: undeclared reference to 'google.protobuf.Nope' (in container '')\n | google.protobuf.Nope{}\n | ....................^"},
}

const compileCasesInput = `{"auth":{"identity":{"username":"john"}}}`

// checkCompileCase compiles and evaluates one of compileCases and describes how the outcome differs
// from the expected one, if it does.
func checkCompileCase(i int) error {
	tc := compileCases[i]
	program, err := Compile(tc.source, tc.wantType)
	if tc.wantErr != "" || err != nil {
		if fmt.Sprint(err) != tc.wantErr {
			return fmt.Errorf("%s: compile error %q, want %q", tc.name, err, tc.wantErr)
		}
		return nil
	}
	if tc.want == nil {
		return nil
	}
	input, err := AuthJsonToCel(compileCasesInput)
	if err != nil {
		return err
	}
	got, _, err := program.Eval(input)
	if err != nil || !reflect.DeepEqual(got.Value(), tc.want) {
		return fmt.Errorf("%s: got %v (%v), want %v", tc.name, got, err, tc.want)
	}
	return nil
}

func TestCompile(t *testing.T) {
	for i, tc := range compileCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NilError(t, checkCompileCase(i))
		})
	}
}

// TestCompileConcurrently compiles from many goroutines, as reconciliation and request-time
// compiles (metric labels, logging fields) do, all from the same base environment.
func TestCompileConcurrently(t *testing.T) {
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			for n := range 10 * len(compileCases) {
				if err := checkCompileCase((g + n) % len(compileCases)); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}

// TestCompiledExpressionMemory compares what a compiled expression holds with what one compiled in
// its own environment holds.
func TestCompiledExpressionMemory(t *testing.T) {
	shared := heldPerExpression(t, func(source string) cel.Program {
		program, err := Compile(source, cel.BoolType)
		assert.NilError(t, err)
		return program
	})
	own := heldPerExpression(t, func(source string) cel.Program {
		env, err := newEnv()
		assert.NilError(t, err)
		checked, issues := env.Compile(source)
		assert.NilError(t, issues.Err())
		program, err := env.Program(checked)
		assert.NilError(t, err)
		return program
	})
	t.Logf("holds %d B, %d B in its own environment", shared, own)
	assert.Assert(t, shared*3 <= own, "holds %d B, %d B in its own environment", shared, own)
}

// heldPerExpression is the heap a compiled expression holds, averaged over distinct sources.
func heldPerExpression(t *testing.T, compile func(source string) cel.Program) int64 {
	t.Helper()
	// Builds what is shared across compiles outside the measurement.
	compile(`true`)

	programs := make([]cel.Program, 100)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range programs {
		programs[i] = compile(fmt.Sprintf("%d == %d", i, i))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(programs)
	return (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / int64(len(programs))
}

func BenchmarkCompile(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := NewPredicate(`request.http.method == 'GET' && auth.identity.username.startsWith('admin')`); err != nil {
			b.Fatal(err)
		}
	}
}
