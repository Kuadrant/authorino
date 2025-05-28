package identity

import (
	gocontext "context"
	"errors"
	"net/url"
	"sync"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/workers"

	oidc "github.com/coreos/go-oidc/v3/oidc"
)

const (
	msg_oidcProviderVerifierConfigMissingError    = "missing openid connect configuration"
	msg_oidcProviderVerifierConfigRefreshSuccess  = "openid connect configuration updated"
	msg_oidcProviderVerifierConfigRefreshError    = "failed to discovery openid connect configuration"
	msg_oidcProviderVerifierConfigRefreshDisabled = "auto-refresh of openid connect configuration disabled"
	msg_jwksVerifierFailedToCreate                = "failed to create JWKS verifier"
	msg_jwtVerifierDoesNotStoreOpenIdConfig       = "rule does not store openid configuration"
)

var tokenVerifierConfig = &oidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true}

type JWTAuthentication struct {
	auth.AuthCredentials

	verifier JWTVerifier
}

func NewJWTAuthentication(ctx gocontext.Context, verifier JWTVerifier, creds auth.AuthCredentials) *JWTAuthentication {
	return &JWTAuthentication{
		AuthCredentials: creds,
		verifier:        verifier,
	}
}

func (j *JWTAuthentication) Call(pipeline auth.AuthPipeline, ctx gocontext.Context) (interface{}, error) {
	ctxWithLogger := log.IntoContext(ctx, log.FromContext(ctx).WithName("jwt"))
	if err := context.CheckContext(ctxWithLogger); err != nil {
		return nil, err
	}

	// get the raw token from the request
	rawIDToken, err := j.GetCredentialsFromReq(pipeline.GetRequest().GetAttributes().GetRequest().GetHttp())
	if err != nil {
		return nil, err
	}

	// verify jwt
	idToken, err := j.verifier.Verify(ctxWithLogger, rawIDToken)
	if err != nil {
		return nil, err
	}

	// extract claims
	var claims interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// impl:auth.AuthConfigCleaner
func (j *JWTAuthentication) Clean(ctx gocontext.Context) error {
	if j.verifier == nil {
		return nil
	}
	cleaner, ok := j.verifier.(auth.AuthConfigCleaner)
	if !ok {
		return nil
	}
	return cleaner.Clean(ctx)
}

// impl:OpenIdConfigStore
func (j *JWTAuthentication) GetOpenIdUrl(ctx gocontext.Context, claim string) (*url.URL, error) {
	if j.verifier != nil {
		if openIdVerifier, ok := j.verifier.(auth.OpenIdConfigStore); ok {
			return openIdVerifier.GetOpenIdUrl(ctx, claim)
		}
	}
	return nil, errors.New(msg_jwtVerifierDoesNotStoreOpenIdConfig)
}

type JWTVerifier interface {
	Verify(ctx gocontext.Context, rawIDToken string) (*oidc.IDToken, error)
}

type oidcProviderVerifier struct {
	issuerUrl string

	mu        sync.RWMutex
	provider  *oidc.Provider
	refresher workers.Worker
}

func NewOIDCProviderVerifier(ctx gocontext.Context, issuerUrl string, ttl int) JWTVerifier {
	v := &oidcProviderVerifier{
		issuerUrl: issuerUrl,
	}
	ctxWithLogger := log.IntoContext(ctx, log.FromContext(ctx).WithName("jwt"))
	v.getOpenIdProvider(ctxWithLogger, false)
	v.setupOpenIdProviderRefresh(ctxWithLogger, ttl)
	return v
}

func (v *oidcProviderVerifier) Verify(ctx gocontext.Context, rawIDToken string) (*oidc.IDToken, error) {
	provider := v.getOpenIdProvider(ctx, false)
	if provider == nil {
		return nil, errors.New(msg_oidcProviderVerifierConfigMissingError)
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	idToken, err := provider.Verifier(tokenVerifierConfig).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	return idToken, nil
}

func (v *oidcProviderVerifier) GetOpenIdUrl(ctx gocontext.Context, claim string) (*url.URL, error) {
	provider := v.getOpenIdProvider(ctx, false)
	if provider == nil {
		return nil, errors.New(msg_oidcProviderVerifierConfigMissingError)
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	var claims map[string]interface{}
	provider.Claims(&claims)

	url, err := url.Parse(claims[claim].(string))
	if err != nil {
		return nil, err
	}
	return url, nil
}

// Clean ensures the goroutine started by setupOpenIdProviderRefresh is cleaned up
// impl: auth.AuthConfigCleaner
func (v *oidcProviderVerifier) Clean(ctx gocontext.Context) error {
	if v.refresher == nil {
		return nil
	}
	return v.refresher.Stop()
}

func (v *oidcProviderVerifier) getOpenIdProvider(ctx gocontext.Context, force bool) *oidc.Provider {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.provider == nil || force {
		if provider, err := oidc.NewProvider(gocontext.Background(), v.issuerUrl); err != nil {
			log.FromContext(ctx).Error(err, msg_oidcProviderVerifierConfigRefreshError, "issuerUrl", v.issuerUrl)
		} else {
			log.FromContext(ctx).V(1).Info(msg_oidcProviderVerifierConfigRefreshSuccess, "issuerUrl", v.issuerUrl)
			v.provider = provider
		}
	}

	return v.provider
}

func (v *oidcProviderVerifier) setupOpenIdProviderRefresh(ctx gocontext.Context, ttl int) {
	var err error

	v.refresher, err = workers.StartWorker(ctx, ttl, func() {
		v.getOpenIdProvider(ctx, true)
	})

	if err != nil {
		log.FromContext(ctx).V(1).Info(msg_oidcProviderVerifierConfigRefreshDisabled, "reason", err)
	}
}

type jwksVerifier struct {
	jwks oidc.KeySet
}

func NewJwksVerifier(ctx gocontext.Context, jwksUrl string) JWTVerifier {
	return &jwksVerifier{
		jwks: oidc.NewRemoteKeySet(ctx, jwksUrl),
	}
}

func (v *jwksVerifier) Verify(ctx gocontext.Context, rawIDToken string) (*oidc.IDToken, error) {
	verifier := oidc.NewVerifier("", v.jwks, tokenVerifierConfig)
	if verifier == nil {
		return nil, errors.New(msg_jwksVerifierFailedToCreate)
	}
	return verifier.Verify(ctx, rawIDToken)
}

// impl: auth.AuthConfigCleaner
func (v *jwksVerifier) Clean(_ gocontext.Context) error {
	return nil
}
