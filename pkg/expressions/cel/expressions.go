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

const RootMetadataBinding = "metadata"
const RootRequestBinding = "request"
const RootSourceBinding = "source"
const RootDestinationBinding = "destination"
const RootAuthBinding = "auth"

type Predicate struct {
	program cel.Program
	source  string
}

func NewPredicate(source string) (*Predicate, error) {
	program, err := Compile(source, cel.BoolType)
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

type Expression struct {
	program cel.Program
	source  string
}

type StringExpression struct {
	expression Expression
}

func NewExpression(source string) (*Expression, error) {
	program, err := Compile(source, nil)
	if err != nil {
		return nil, err
	}
	return &Expression{
		program: program,
		source:  source,
	}, nil
}

func NewStringExpression(source string) (*StringExpression, error) {
	program, err := Compile(source, cel.StringType)
	if err != nil {
		return nil, err
	}
	return &StringExpression{
		expression: Expression{
			program: program,
			source:  source,
		},
	}, nil
}

func (e *Expression) ResolveFor(json string) (interface{}, error) {
	result, _, err := e.Evaluate(json)
	if err != nil {
		return nil, err
	}

	if jsonVal, err := ValueToJSON(result); err != nil {
		return nil, err
	} else {
		return jsonVal, nil
	}
}

func (e *StringExpression) ResolveFor(json string) (interface{}, error) {
	return e.expression.EvaluateStringValue(json)
}

func (e *Expression) Evaluate(json string) (ref.Val, *cel.EvalDetails, error) {
	input, err := AuthJsonToCel(json)
	if err != nil {
		return nil, nil, err
	}

	return e.program.Eval(input)
}

func (e *Expression) EvaluateStringValue(json string) (string, error) {
	if result, _, err := e.Evaluate(json); err != nil {
		return "", err
	} else if !reflect.DeepEqual(result.Type(), cel.StringType) {
		toJSON, err := ValueToJSON(result)
		return toJSON, err
	} else {
		str, err := result.ConvertToNative(reflect.TypeOf(""))
		if err != nil {
			return "", err
		}
		return str.(string), nil
	}
}

func Compile(expression string, expectedType *cel.Type, opts ...cel.EnvOption) (cel.Program, error) {
	envOpts := append([]cel.EnvOption{cel.Declarations(
		decls.NewConst(RootMetadataBinding, decls.NewObjectType("google.protobuf.Struct"), nil),
		decls.NewConst(RootRequestBinding, decls.NewObjectType("google.protobuf.Struct"), nil),
		decls.NewConst(RootSourceBinding, decls.NewObjectType("google.protobuf.Struct"), nil),
		decls.NewConst(RootDestinationBinding, decls.NewObjectType("google.protobuf.Struct"), nil),
		decls.NewConst(RootAuthBinding, decls.NewObjectType("google.protobuf.Struct"), nil),
	)}, opts...)
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

	if expectedType != nil {
		if !reflect.DeepEqual(checked.OutputType(), expectedType) && !reflect.DeepEqual(checked.OutputType(), cel.DynType) {
			return nil, fmt.Errorf("type error: got %v, wanted %v output type", checked.OutputType(), expectedType)
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
	metadata := data.GetFields()[RootMetadataBinding]
	request := data.GetFields()[RootRequestBinding]
	source := data.GetFields()[RootSourceBinding]
	destination := data.GetFields()[RootDestinationBinding]
	auth := data.GetFields()[RootAuthBinding]

	input := map[string]interface{}{
		RootMetadataBinding:    metadata,
		RootRequestBinding:     request,
		RootSourceBinding:      source,
		RootDestinationBinding: destination,
		RootAuthBinding:        auth,
	}
	return input, nil
}
