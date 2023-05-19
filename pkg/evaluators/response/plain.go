package response

import (
	"context"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/json"
)

type Plain struct {
	json.JSONValue
}

func (p *Plain) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	authJSON := pipeline.GetAuthorizationJSON()
	return p.ResolveFor(authJSON), nil
}
