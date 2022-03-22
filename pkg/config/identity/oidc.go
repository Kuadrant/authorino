package identity

import (
	"context"
	"fmt"
	"net/url"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/cron"

	goidc "github.com/coreos/go-oidc"
)

type OIDC struct {
	auth_credentials.AuthCredentials
	Endpoint  string `yaml:"endpoint"`
	provider  *goidc.Provider
	refresher cron.Worker
}

func NewOIDC(endpoint string, creds auth_credentials.AuthCredentials, ttl int, ctx context.Context) *OIDC {
	oidc := &OIDC{
		AuthCredentials: creds,
		Endpoint:        endpoint,
	}
	ctxWithLogger := log.IntoContext(ctx, log.FromContext(ctx).WithName("oidc"))
	_ = oidc.getProvider(ctxWithLogger, false)
	oidc.configureProviderRefresh(ttl, ctxWithLogger)
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

func (oidc *OIDC) getProvider(ctx context.Context, force bool) *goidc.Provider {
	if oidc.provider == nil || force {
		endpoint := oidc.Endpoint
		if provider, err := goidc.NewProvider(context.TODO(), endpoint); err != nil {
			log.FromContext(ctx).Error(err, "failed to discovery openid connect configuration", "endpoint", endpoint)
		} else {
			log.FromContext(ctx).V(1).Info("openid connect configuration updated", "endpoint", endpoint)
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
	provider := oidc.getProvider(ctx, false)

	if provider == nil {
		return nil, fmt.Errorf("missing openid connect configuration")
	}

	tokenVerifierConfig := &goidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true}
	if idToken, err := provider.Verifier(tokenVerifierConfig).Verify(ctx, accessToken); err != nil {
		return nil, err
	} else {
		return idToken, nil
	}
}

func (oidc *OIDC) GetURL(name string, ctx context.Context) (*url.URL, error) {
	var providerClaims map[string]interface{}
	_ = oidc.getProvider(ctx, false).Claims(&providerClaims)

	if endpoint, err := url.Parse(providerClaims[name].(string)); err != nil {
		return nil, err
	} else {
		return endpoint, nil
	}
}

func (oidc *OIDC) configureProviderRefresh(ttl int, ctx context.Context) {
	oidc.refresher, _ = cron.StartWorker(ctx, ttl, func() {
		oidc.getProvider(ctx, true)
	})
}

// Clean ensures the goroutine started by configureProviderRefresh is cleaned up
func (oidc *OIDC) Clean(ctx context.Context) error {
	if oidc.refresher == nil {
		return nil
	}
	return oidc.refresher.Stop()
}
