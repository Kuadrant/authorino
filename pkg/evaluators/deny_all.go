package evaluators

import (
	"context"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators/authorization"
)

func NewDenyAllAuthorization(ctx context.Context, name, policyName string) auth.AuthConfigEvaluator {
	if policyName == "" {
		policyName = name
	}
	opaDenyAll, _ := authorization.NewOPAAuthorization(policyName, "allow { false }", nil, false, 0, ctx)
	return &AuthorizationConfig{
		Name:     name,
		Priority: 0,
		OPA:      opaDenyAll,
	}
}
