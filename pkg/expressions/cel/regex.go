package cel

import (
	"regexp"
	"regexp/syntax"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter"
)

// maxPrecompiledRegexSize bounds, in regexProgramSize units, the constant patterns compiled into a
// program. It admits common validation patterns such as UUIDs, IPv4 addresses, semver and
// allowlists. A pattern under it holds at most about 76 KB (TestPrecompiledRegexMemory), while any
// expression already holds about 55 KiB for its CEL environment.
const maxPrecompiledRegexSize = 128

// matchesRegexOptimization compiles small constant `matches()` patterns once, when the program is
// built, instead of on every evaluation. A pattern that is over maxPrecompiledRegexSize, doesn't
// compile or isn't constant keeps the standard overload, which compiles it and reports its errors on
// every evaluation.
//
// It's used instead of interpreter.MatchesRegexOptimization, which keeps patterns of any size, fails
// the program build on a broken pattern, and accepts any receiver whose Value() is a Go string.
// Optional and type values unwrap to strings there, so `dyn(request.headers.?user).matches('^adm')`
// would match where the standard overload returns an error.
var matchesRegexOptimization = &interpreter.RegexOptimization{
	Function:   "matches",
	RegexIndex: 1,
	Factory: func(call interpreter.InterpretableCall, pattern string) (interpreter.InterpretableCall, error) {
		re := precompileRegex(pattern)
		if re == nil {
			return call, nil
		}
		id, function := call.ID(), call.Function()
		return interpreter.NewCall(id, function, call.OverloadID(), call.Args(), func(values ...ref.Val) ref.Val {
			if in, ok := values[0].(types.String); ok {
				return types.Bool(re.MatchString(string(in)))
			}
			// The standard overload's errors: Timestamp and Duration receivers fail in their Receive
			// method, others in the dispatch.
			if values[0].Type().HasTrait(traits.ReceiverType) {
				return types.NewErrWithNodeID(id, "no such overload")
			}
			return types.NewErrWithNodeID(id, "no such overload: %s", function)
		}), nil
	},
}

// precompileRegex returns the compiled pattern, or nil if it's over maxPrecompiledRegexSize or
// doesn't compile.
func precompileRegex(pattern string) *regexp.Regexp {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil || regexProgramSize(parsed) > maxPrecompiledRegexSize {
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re
}

// regexProgramSize is an upper bound on the instruction count of the compiled program, from calcSize
// in Go's regexp/syntax/parse.go, plus half a unit per character-class range. Go compiles a class to
// a single instruction that holds all its ranges, so `\pL` and its 659 ranges would otherwise count
// as 1.
func regexProgramSize(re *syntax.Regexp) int64 {
	var size int64
	switch re.Op {
	case syntax.OpLiteral:
		size = int64(len(re.Rune))
	case syntax.OpCharClass:
		size = 1 + int64(len(re.Rune)/4)
	case syntax.OpCapture, syntax.OpStar:
		size = 2 + regexProgramSize(re.Sub[0])
	case syntax.OpPlus, syntax.OpQuest:
		size = 1 + regexProgramSize(re.Sub[0])
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			size += regexProgramSize(sub)
		}
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			size += regexProgramSize(sub)
		}
		if len(re.Sub) > 1 {
			size += int64(len(re.Sub)) - 1
		}
	case syntax.OpRepeat:
		sub := regexProgramSize(re.Sub[0])
		if re.Max == -1 {
			if re.Min == 0 {
				size = 2 + sub
			} else {
				size = 1 + int64(re.Min)*sub
			}
			break
		}
		size = int64(re.Max)*sub + int64(re.Max-re.Min)
	}
	return max(1, size)
}
