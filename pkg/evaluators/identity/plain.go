package identity

import (
	"context"
	"fmt"
	"io"
	"net/http"

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

func (p *Plain) GetCredentialsFromReq(*envoy_auth.AttributeContext_HttpRequest) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (p *Plain) GetCredentialsKeySelector() string {
	return p.Pattern
}

func (p *Plain) GetCredentialsIn() string {
	return p.Pattern
}

func (p *Plain) BuildRequestWithCredentials(ctx context.Context, endpoint string, method string, credentialValue string, body io.Reader) (*http.Request, error) {
	return nil, fmt.Errorf("not implemented")
}
