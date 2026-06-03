package identity

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/expressions"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

type Plain struct {
	Value   expressions.Value
	Pattern string
}

func (p *Plain) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	if object, err := p.Value.ResolveFor(pipeline.GetAuthorizationJSON()); err != nil {
		return nil, err
	} else if object != nil {
		return object, nil
	}
	return nil, fmt.Errorf("could not retrieve identity object or null")
}

// impl: AuthCredentials

func (p *Plain) GetCredentialsFromAuthReq(*envoy_auth.AttributeContext_HttpRequest) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (p *Plain) GetIdentifier() string {
	return p.Pattern
}

func (p *Plain) GetPlacement() string {
	return p.Pattern
}
