package identity

import (
	"context"

	"github.com/3scale/authorino/pkg/config/internal"

	oidc "github.com/coreos/go-oidc"
)

type OIDC struct {
	Name string `yaml:"name"`
	Endpoint string `yaml:"endpoint"`
}

func (self *OIDC) Call(ctx internal.AuthContext) (interface{}, error) {
	// extract access token
	accessToken, err := ctx.AuthorizationToken()
	if err != nil { return nil, err }

	// verify jwt
	provider, err := self.NewProvider(ctx)
	if err != nil { return nil, err }
	oidcConfig := &oidc.Config{ SkipClientIDCheck: true, SkipIssuerCheck: true }
	verifier := provider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(context.TODO(), accessToken)
	if err != nil { return nil, err }

	var claims interface{}
	err = idToken.Claims(&claims)
	if err != nil { return nil, err }

	return claims, nil
}

func (self *OIDC) NewProvider(ctx internal.AuthContext) (*oidc.Provider, error) {
	provider, err := oidc.NewProvider(context.TODO(), self.Endpoint)
	if err != nil { return nil, err }
	return provider, nil
}
