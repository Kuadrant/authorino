package response

import (
	"context"

	interpreter "github.com/google/cel-go/cel"
	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/expressions/cel"
)

func NewDynamicCelResponse(expression string) (*DynamicCEL, error) {

	cel_exp := DynamicCEL{}

	if program, err := cel.Compile(expression, nil); err != nil {
		return nil, err
	} else {
		cel_exp.program = program
	}

	return &cel_exp, nil
}

type DynamicCEL struct {
	program interpreter.Program
}

func (c *DynamicCEL) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	input, err := cel.AuthJsonToCel(pipeline.GetAuthorizationJSON())
	if err != nil {
		return nil, err
	}
	result, _, err := c.program.Eval(input)
	if err != nil {
		return nil, err
	}

	if jsonVal, err := cel.ValueToJSON(result); err != nil {
		return nil, err
	} else {
		return jsonVal, nil
	}
}
