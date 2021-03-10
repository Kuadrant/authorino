package identity

import (
	"context"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/common/auth_credentials"

	goidc "github.com/coreos/go-oidc"
)

type oidcDetails struct {
	Name     string `yaml:"name"`
	Endpoint string `yaml:"endpoint"`
}
type OIDC struct {
	auth_credentials.AuthCredentials
	oidcDetails
}

func NewOIDCIdentity(name string, endpoint string, authCred auth_credentials.AuthCredentials) *OIDC {
	return &OIDC{
		authCred,
		oidcDetails{
			name,
			endpoint,
		},
	}
}

func (oidc *OIDC) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	// discover oidc config
	// TODO: Move to a 'prepare' step and cache it (like in pkg/config/authorization/opa.go)
	provider, err := oidc.NewProvider(ctx)
	if err != nil {
		return nil, err
	}

	// retrieve access token
	accessToken, err := oidc.GetCredentialsFromReq(authContext.GetRequest().GetAttributes().GetRequest().GetHttp())
	if err != nil {
		return nil, err
	}

	// verify jwt and extract claims
	var claims interface{}
	if _, err := oidc.decodeAndVerifyToken(provider, accessToken, ctx, &claims); err != nil {
		return nil, err
	} else {
		return claims, nil
	}
}

func (oidc *OIDC) NewProvider(ctx context.Context) (*goidc.Provider, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	if provider, err := goidc.NewProvider(ctx, oidc.Endpoint); err != nil {
		return nil, err
	} else {
		return provider, nil
	}
}

func (oidc *OIDC) verifyToken(provider *goidc.Provider, accessToken string, ctx context.Context) (*goidc.IDToken, error) {
	oidcConfig := &goidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true}

	if idToken, err := provider.Verifier(oidcConfig).Verify(ctx, accessToken); err != nil {
		return nil, err
	} else {
		return idToken, nil
	}
}

func (oidc *OIDC) decodeAndVerifyToken(provider *goidc.Provider, accessToken string, ctx context.Context, claims *interface{}) (*goidc.IDToken, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	// verify jwt
	idToken, err := oidc.verifyToken(provider, accessToken, ctx)
	if err != nil {
		return nil, err
	}

	// extract claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	return idToken, nil
}
