package cel

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"runtime"
	"strings"
	"testing"

	"gotest.tools/assert"
)

var regexCorpus = []string{
	`^system:`,
	`^[a-zA-Z0-9][a-zA-Z0-9._:-]*$`,
	`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
	`^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$`,
	`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`,
	`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`,
	`^(team-a|team-b|team-c|platform|sre)$`,
	`(?i)^admin(istrator)?$`,
	`(?s)^.{1,1000}$`,
	`^\pL[\pL\pN _-]*$`,
	`^\pL{1,64}$`,
	`^[^/]+/[^/]+$`,
	`(?:ab){2,5}`,
	`(?:(?:ab){0,}){10}`,
	`(?:(?:a|b)+c?){3,}`,
	`(?:a?)*`,
	`(?:a?){0,}`,
	`héllo|wörld|日本`,
}

func TestRegexProgramSizeIsUpperBound(t *testing.T) {
	for _, pattern := range regexCorpus {
		t.Run(pattern, func(t *testing.T) {
			parsed, err := syntax.Parse(pattern, syntax.Perl)
			assert.NilError(t, err)

			prog, err := syntax.Compile(parsed.Simplify())
			assert.NilError(t, err)

			// The program also holds a fail and a match instruction that the estimate leaves out.
			actual := int64(len(prog.Inst)) - 2
			for _, inst := range prog.Inst {
				if inst.Op == syntax.InstRune && len(inst.Rune) > 1 {
					actual += int64(len(inst.Rune) / 4)
				}
			}
			assert.Assert(t, regexProgramSize(parsed) >= actual, "estimate %d, compiled %d", regexProgramSize(parsed), actual)
		})
	}
}

func TestPrecompileRegex(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    bool
	}{
		{`^system:`, true},
		{`a{128}`, true},
		{`a{129}`, false},
		{`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, true},
		{`^[a-z0-9]{1,63}$`, false},
		{`^\pL{1,64}$`, false},
		{`[`, false},
		{`a++`, false},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			assert.Equal(t, precompileRegex(tc.pattern) != nil, tc.want)
		})
	}
}

func TestMatchesCompilesConstantPatternOnce(t *testing.T) {
	authJSON := `{"auth":{"identity":{"username":"john"}}}`
	allocs := func(source string) float64 {
		predicate, err := NewPredicate(source)
		assert.NilError(t, err)
		return testing.AllocsPerRun(100, func() { _, _ = predicate.Matches(authJSON) })
	}
	baseline := allocs(`auth.identity.username == 'john'`)

	// Compiling even a small pattern takes dozens of allocations.
	small := allocs(`auth.identity.username.matches('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')`)
	assert.Assert(t, small <= baseline+2, "%v allocations, %v without matches()", small, baseline)

	overLimit := allocs(`auth.identity.username.matches('^[a-z0-9]{1,63}$')`)
	assert.Assert(t, overLimit > baseline+20, "%v allocations, %v without matches()", overLimit, baseline)
}

// TestPrecompiledRegexMemory checks what the costliest pattern shapes known to us hold at
// maxPrecompiledRegexSize. Go's onepass program for anchored patterns grows quadratically with
// alternation branches and their class ranges, so those shapes come first.
func TestPrecompiledRegexMemory(t *testing.T) {
	const maxHeld = 96 << 10

	// distinct joins k branches, each starting with its own rune or class of three runes. Runes are
	// spaced out, so neighbours don't merge into one class range.
	distinct := func(k int, class bool, branch string) string {
		alts := make([]string, k)
		for i := range alts {
			first := string(rune(0x1000 + 16*i))
			if class {
				first = "[" + first + string(rune(0x1000+16*i+2)) + string(rune(0x1000+16*i+4)) + "]"
			}
			alts[i] = first + branch
		}
		return strings.Join(alts, "|")
	}
	for _, tc := range []struct {
		name    string
		pattern func(k int) string
	}{
		{"anchored alternation of classes in a loop", func(k int) string { return "^(?:" + distinct(k, true, "[xy]?") + ")+$" }},
		{"anchored alternation in a loop", func(k int) string { return "^(?:" + distinct(k, false, "x?") + ")+$" }},
		{"anchored alternation", func(k int) string { return "^(?:" + distinct(k, false, "y") + ")$" }},
		{"bounded repeat", func(k int) string { return fmt.Sprintf(`^a{0,%d}$`, k) }},
		{"case-folded literal", func(k int) string { return "(?i)^" + strings.Repeat("ab", k) }},
		{"captures", func(k int) string { return fmt.Sprintf(`^(?:(a)){%d}$`, k) }},
		{"class ranges", func(k int) string { return "[" + strings.ReplaceAll(distinct(k, false, ""), "|", "") + "]" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pattern := tc.pattern
			// The largest pattern of this shape that is still precompiled.
			k := 1
			for ; k < 1000 && precompileRegex(pattern(k+1)) != nil; k++ {
			}
			assert.Assert(t, k < 1000, "shape never reaches maxPrecompiledRegexSize")
			largest := pattern(k)
			assert.Assert(t, precompileRegex(largest) != nil)

			parsed, err := syntax.Parse(largest, syntax.Perl)
			assert.NilError(t, err)
			held := heldBytes(largest)
			t.Logf("size %d, holds %d B", regexProgramSize(parsed), held)
			assert.Assert(t, held <= maxHeld, "%s holds %d B", largest, held)
		})
	}
}

// heldBytes is the heap a compiled pattern holds, averaged over many copies.
func heldBytes(pattern string) int64 {
	compiled := make([]*regexp.Regexp, 100)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range compiled {
		compiled[i] = regexp.MustCompile(pattern)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(compiled)
	return (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / int64(len(compiled))
}
