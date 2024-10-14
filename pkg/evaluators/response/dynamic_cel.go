package response

import (
	"context"
	"reflect"
	"strings"

	"github.com/golang/protobuf/jsonpb"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kuadrant/authorino/pkg/auth"
	"google.golang.org/protobuf/types/known/structpb"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const rootBinding = "auth"

func NewDynamicCelResponse(expression string) (*DynamicCEL, error) {

	cel_exp := DynamicCEL{}

	env, err := cel.NewEnv(cel.Declarations(
		decls.NewConst(rootBinding, decls.NewObjectType("google.protobuf.Struct"), nil),
	))
	if err != nil {
		return nil, err
	}

	ast, issues := env.Parse(expression)
	if issues.Err() != nil {
		return nil, issues.Err()
	}

	checked, issues := env.Check(ast)
	if issues.Err() != nil {
		return nil, issues.Err()
	}

	program, err := env.Program(checked)
	if err != nil {
		return nil, err
	}

	cel_exp.program = program

	return &cel_exp, nil
}

type DynamicCEL struct {
	program cel.Program
}

func (c *DynamicCEL) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {

	auth_json := pipeline.GetAuthorizationJSON()
	data := structpb.Struct{}
	if err := jsonpb.Unmarshal(strings.NewReader(auth_json), &data); err != nil {
		return nil, err
	}

	value := data.GetFields()["auth"]
	result, _, err := c.program.Eval(map[string]interface{}{
		rootBinding: value,
	})
	if err != nil {
		return nil, err
	}

	if jsonVal, err := valueToJSON(result); err != nil {
		return nil, err
	} else {
		return jsonVal, nil
	}
}

func valueToJSON(val ref.Val) (string, error) {
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
