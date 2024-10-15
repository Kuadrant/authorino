package cel

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/golang/protobuf/jsonpb"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const RootBinding = "auth"

type Predicate struct {
	program cel.Program
	source  string
}

func NewPredicate(source string) (*Predicate, error) {
	program, err := Compile(source, true)
	if err != nil {
		return nil, err
	}
	return &Predicate{
		program: program,
		source:  source,
	}, nil
}

func (p *Predicate) Matches(json string) (bool, error) {
	input, err := AuthJsonToCel(json)
	if err != nil {
		return false, err
	}
	result, _, err := p.program.Eval(input)
	if err != nil {
		return false, err
	}
	return result.Value().(bool), nil
}

func Compile(expression string, predicate bool, opts ...cel.EnvOption) (cel.Program, error) {
	envOpts := append([]cel.EnvOption{cel.Declarations(
		decls.NewConst(RootBinding, decls.NewObjectType("google.protobuf.Struct"), nil))}, opts...)
	env, env_err := cel.NewEnv(envOpts...)
	if env_err != nil {
		return nil, env_err
	}

	ast, issues := env.Parse(expression)
	if issues.Err() != nil {
		return nil, issues.Err()
	}

	checked, issues := env.Check(ast)
	if issues.Err() != nil {
		return nil, issues.Err()
	}

	if predicate {
		if !reflect.DeepEqual(checked.OutputType(), cel.BoolType) && !reflect.DeepEqual(checked.OutputType(), cel.DynType) {
			return nil, fmt.Errorf("type error: got %v, wanted %v output type", checked.OutputType(), cel.BoolType)
		}
	}

	program, err := env.Program(checked)
	if err != nil {
		return nil, err
	}
	return program, nil
}

func ValueToJSON(val ref.Val) (string, error) {
	v, err := val.ConvertToNative(reflect.TypeOf(&structpb.Value{}))
	if err != nil {
		return "", err
	}
	marshaller := protojson.MarshalOptions{Multiline: false}
	bytes, err := marshaller.Marshal(v.(proto.Message))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// todo this should eventually be sourced as proper proto from the pipeline
func AuthJsonToCel(json string) (map[string]interface{}, error) {
	data := structpb.Struct{}
	if err := jsonpb.Unmarshal(strings.NewReader(json), &data); err != nil {
		return nil, err
	}
	value := data.GetFields()["auth"]
	input := map[string]interface{}{
		RootBinding: value,
	}
	return input, nil
}
