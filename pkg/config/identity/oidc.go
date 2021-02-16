package identity

import (
	"context"

	"github.com/3scale-labs/authorino/pkg/config/common"

	oidc "github.com/coreos/go-oidc"
)

type OIDC struct {
	Name     string `yaml:"name"`
	Endpoint string `yaml:"endpoint"`
}

func (self *OIDC) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	// extract access token
	accessToken, err := authContext.AuthorizationToken()
	if err != nil {
		return nil, err
	}

	// verify jwt
	provider, err := self.NewProvider(ctx)
	if err != nil {
		return nil, err
	}
	oidcConfig := &oidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true}
	verifier := provider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	var claims interface{}
	err = idToken.Claims(&claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (self *OIDC) NewProvider(ctx context.Context) (*oidc.Provider, error) {
	provider, err := oidc.NewProvider(ctx, self.Endpoint)
	if err != nil {
		return nil, err
	}
	return provider, nil
}
