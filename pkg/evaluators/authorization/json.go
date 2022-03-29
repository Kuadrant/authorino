package authorization

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/json"
)

type JSONPatternMatching struct {
	Rules []json.JSONPatternMatchingRule
}

func (jsonAuth *JSONPatternMatching) Call(pipeline auth.AuthPipeline, ctx context.Context) (bool, error) {
	authJSON := pipeline.GetAuthorizationJSON()

	for _, rule := range jsonAuth.Rules {
		if authorized, err := rule.EvaluateFor(authJSON); err != nil {
			return false, err
		} else if !authorized {
			return false, fmt.Errorf(unauthorizedErrorMsg)
		}
	}

	return true, nil
}
