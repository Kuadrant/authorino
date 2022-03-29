package identity

import (
	gocontext "context"
	"fmt"
	"net/url"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/workers"

	goidc "github.com/coreos/go-oidc"
)

const (
	msg_oidcProviderConfigMissingError    = "missing openid connect configuration"
	msg_oidcProviderConfigRefreshSuccess  = "openid connect configuration updated"
	msg_oidcProviderConfigRefreshError    = "failed to discovery openid connect configuration"
	msg_oidcProviderConfigRefreshDisabled = "auto-refresh of openid connect configuration disabled"
)

type OIDC struct {
	auth.AuthCredentials
	Endpoint  string `yaml:"endpoint"`
	provider  *goidc.Provider
	refresher workers.Worker
}

func NewOIDC(endpoint string, creds auth.AuthCredentials, ttl int, ctx gocontext.Context) *OIDC {
	oidc := &OIDC{
		AuthCredentials: creds,
		Endpoint:        endpoint,
	}
	ctxWithLogger := log.IntoContext(ctx, log.FromContext(ctx).WithName("oidc"))
	_ = oidc.getProvider(ctxWithLogger, false)
	oidc.configureProviderRefresh(ttl, ctxWithLogger)
	return oidc
}

func (oidc *OIDC) Call(pipeline auth.AuthPipeline, ctx gocontext.Context) (interface{}, error) {
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

func (oidc *OIDC) getProvider(ctx gocontext.Context, force bool) *goidc.Provider {
	if oidc.provider == nil || force {
		endpoint := oidc.Endpoint
		if provider, err := goidc.NewProvider(gocontext.TODO(), endpoint); err != nil {
			log.FromContext(ctx).Error(err, msg_oidcProviderConfigRefreshError, "endpoint", endpoint)
		} else {
			log.FromContext(ctx).V(1).Info(msg_oidcProviderConfigRefreshSuccess, "endpoint", endpoint)
			oidc.provider = provider
		}
	}

	return oidc.provider
}

func (oidc *OIDC) decodeAndVerifyToken(accessToken string, ctx gocontext.Context, claims *interface{}) (*goidc.IDToken, error) {
	if err := context.CheckContext(ctx); err != nil {
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

func (oidc *OIDC) verifyToken(accessToken string, ctx gocontext.Context) (*goidc.IDToken, error) {
	provider := oidc.getProvider(ctx, false)

	if provider == nil {
		return nil, fmt.Errorf(msg_oidcProviderConfigMissingError)
	}

	tokenVerifierConfig := &goidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true}
	if idToken, err := provider.Verifier(tokenVerifierConfig).Verify(ctx, accessToken); err != nil {
		return nil, err
	} else {
		return idToken, nil
	}
}

func (oidc *OIDC) GetURL(name string, ctx gocontext.Context) (*url.URL, error) {
	var providerClaims map[string]interface{}
	_ = oidc.getProvider(ctx, false).Claims(&providerClaims)

	if endpoint, err := url.Parse(providerClaims[name].(string)); err != nil {
		return nil, err
	} else {
		return endpoint, nil
	}
}

func (oidc *OIDC) configureProviderRefresh(ttl int, ctx gocontext.Context) {
	var err error

	oidc.refresher, err = workers.StartWorker(ctx, ttl, func() {
		oidc.getProvider(ctx, true)
	})

	if err != nil {
		log.FromContext(ctx).V(1).Info(msg_oidcProviderConfigRefreshDisabled, "reason", err)
	}
}

// Clean ensures the goroutine started by configureProviderRefresh is cleaned up
func (oidc *OIDC) Clean(ctx gocontext.Context) error {
	if oidc.refresher == nil {
		return nil
	}
	return oidc.refresher.Stop()
}
