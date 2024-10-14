package response

import (
	"context"
	"strings"

	"github.com/golang/protobuf/jsonpb"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/expressions"
	"google.golang.org/protobuf/types/known/structpb"
)

const rootBinding = "auth"

func NewDynamicCelResponse(expression string) (*DynamicCEL, error) {

	cel_exp := DynamicCEL{}

	if program, err := expressions.CelCompile(expression, cel.Declarations(
		decls.NewConst(rootBinding, decls.NewObjectType("google.protobuf.Struct"), nil),
	)); err != nil {
		return nil, err
	} else {
		cel_exp.program = program
	}

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

	if jsonVal, err := expressions.CelValueToJSON(result); err != nil {
		return nil, err
	} else {
		return jsonVal, nil
	}
}
