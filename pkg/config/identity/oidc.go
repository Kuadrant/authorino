package identity

import (
	"context"
	"net/url"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
	"github.com/kuadrant/authorino/pkg/common/log"

	goidc "github.com/coreos/go-oidc"
)

type OIDC struct {
	auth_credentials.AuthCredentials
	Endpoint string `yaml:"endpoint"`
	provider *goidc.Provider
}

func NewOIDC(endpoint string, creds auth_credentials.AuthCredentials, ctx context.Context) *OIDC {
	oidc := &OIDC{
		AuthCredentials: creds,
		Endpoint:        endpoint,
	}
	_ = oidc.getProvider(log.IntoContext(ctx, log.FromContext(ctx).WithName("oidc")))

	return oidc
}

func (oidc *OIDC) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	// retrieve access token
	accessToken, err := oidc.GetCredentialsFromReq(pipeline.GetRequest().GetAttributes().GetRequest().GetHttp())
	if err != nil {
		return nil, err
	}

	// verify jwt and extract claims
	var claims interface{}
	if _, err := oidc.decodeAndVerifyToken(accessToken, log.IntoContext(ctx, log.FromContext(ctx).WithName("oidc")), &claims); err != nil {
		return nil, err
	} else {
		return claims, nil
	}
}

func (oidc *OIDC) getProvider(ctx context.Context) *goidc.Provider {
	if oidc.provider == nil {
		endpoint := oidc.Endpoint
		if provider, err := goidc.NewProvider(context.TODO(), endpoint); err != nil {
			log.FromContext(ctx).Error(err, "failed to discovery openid connect configuration", "endpoint", endpoint)
		} else {
			oidc.provider = provider
		}
	}

	return oidc.provider
}

func (oidc *OIDC) decodeAndVerifyToken(accessToken string, ctx context.Context, claims *interface{}) (*goidc.IDToken, error) {
	if err := common.CheckContext(ctx); err != nil {
		return nil, err
	}

	// verify jwt
	idToken, err := oidc.verifyToken(accessToken, ctx)
	if err != nil {
		return nil, err
	}

	// extract claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	return idToken, nil
}

func (oidc *OIDC) verifyToken(accessToken string, ctx context.Context) (*goidc.IDToken, error) {
	tokenVerifierConfig := &goidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true}

	if idToken, err := oidc.getProvider(ctx).Verifier(tokenVerifierConfig).Verify(ctx, accessToken); err != nil {
		return nil, err
	} else {
		return idToken, nil
	}
}

func (oidc *OIDC) GetURL(name string, ctx context.Context) (*url.URL, error) {
	var providerClaims map[string]interface{}
	_ = oidc.getProvider(ctx).Claims(&providerClaims)

	if endpoint, err := url.Parse(providerClaims[name].(string)); err != nil {
		return nil, err
	} else {
		return endpoint, nil
	}
}
