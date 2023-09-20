package authorization

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/jsonexp"
)

type JSONPatternMatching struct {
	Rules jsonexp.Expression
}

func (j *JSONPatternMatching) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	if j.Rules == nil {
		return true, nil
	}
	authorized, err := j.Rules.Matches(pipeline.GetAuthorizationJSON())
	if err != nil {
		return false, err
	}
	if !authorized {
		return false, fmt.Errorf(unauthorizedErrorMsg)
	}
	return true, nil
}
