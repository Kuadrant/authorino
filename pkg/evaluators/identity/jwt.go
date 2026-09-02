package identity

import (
	gocontext "context"
	"errors"
	"net/url"
	"sync"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	httputil "github.com/kuadrant/authorino/pkg/http"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/workers"

	"github.com/coreos/go-oidc/v3/oidc"
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

func NewJWTAuthentication(verifier JWTVerifier, creds auth.AuthCredentials) *JWTAuthentication {
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
	rawIDToken, err := j.GetCredentialsFromAuthReq(pipeline.GetRequest().GetAttributes().GetRequest().GetHttp())
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

// impl:auth.AuthConfigStarter
func (j *JWTAuthentication) Start(ctx gocontext.Context) error {
	if j.verifier == nil {
		return nil
	}
	starter, ok := j.verifier.(auth.AuthConfigStarter)
	if !ok {
		return nil
	}
	return starter.Start(ctx)
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
	ttl       int
	timeout   *int

	mu        sync.RWMutex
	provider  *oidc.Provider
	refresher workers.Worker
}

// NewOIDCProviderVerifier discovers the openid connect configuration straight away, so a broken
// issuer still surfaces while the authconfig is being translated, but leaves the periodic refresh
// to Start(), which the reconciler only calls once the config is indexed.
func NewOIDCProviderVerifier(ctx gocontext.Context, issuerUrl string, ttl int, timeout *int) JWTVerifier {
	v := &oidcProviderVerifier{
		issuerUrl: issuerUrl,
		ttl:       ttl,
		timeout:   timeout,
	}
	ctxWithLogger := log.IntoContext(ctx, log.FromContext(ctx).WithName("jwt"))
	v.getOpenIdProvider(ctxWithLogger, false)
	return v
}

// impl: auth.AuthConfigStarter
func (v *oidcProviderVerifier) Start(ctx gocontext.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// the check and the assignment have to happen under the same lock: released in between, two
	// callers could both find no refresher and both start one, leaking whichever loses the race
	if v.refresher != nil {
		return nil
	}

	v.setupOpenIdProviderRefresh(log.IntoContext(ctx, log.FromContext(ctx).WithName("jwt")), v.ttl)
	return nil
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
	if err := provider.Claims(&claims); err != nil {
		return nil, err
	}

	url, err := url.Parse(claims[claim].(string))
	if err != nil {
		return nil, err
	}
	return url, nil
}

// Clean ensures the goroutine started by setupOpenIdProviderRefresh is cleaned up
// impl: auth.AuthConfigCleaner
func (v *oidcProviderVerifier) Clean(ctx gocontext.Context) error {
	v.mu.Lock()
	refresher := v.refresher
	v.refresher = nil
	v.mu.Unlock()

	if refresher == nil {
		return nil
	}
	return refresher.Stop()
}

// GetProvider returns the current OIDC provider in a thread-safe manner
func (v *oidcProviderVerifier) GetProvider() *oidc.Provider {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.provider
}

func (v *oidcProviderVerifier) getOpenIdProvider(ctx gocontext.Context, force bool) *oidc.Provider {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.provider == nil || force {
		// Create HTTP client with timeout and trace propagation.
		// Use Background context for request lifecycle (to avoid cancellation from reconciliation),
		// but propagate trace context from caller's ctx for observability.
		httpClient := httputil.NewClientWithTracing(ctx, v.timeout)
		discoveryCtx := oidc.ClientContext(gocontext.Background(), httpClient)

		if provider, err := oidc.NewProvider(discoveryCtx, v.issuerUrl); err != nil {
			log.FromContext(ctx).Error(err, msg_oidcProviderVerifierConfigRefreshError, "issuerUrl", v.issuerUrl)
		} else {
			log.FromContext(ctx).V(1).Info(msg_oidcProviderVerifierConfigRefreshSuccess, "issuerUrl", v.issuerUrl)
			v.provider = provider
		}
	}

	return v.provider
}

// setupOpenIdProviderRefresh assigns v.refresher and must be called with v.mu held.
//
// The worker callback takes v.mu itself, so this relies on StartWorker only arming a ticker and
// never invoking the callback synchronously. Do not make it fire immediately without moving this
// call out of the critical section first.
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

func NewJwksVerifier(ctx gocontext.Context, jwksUrl string, timeout *int) JWTVerifier {
	// Create HTTP client with timeout and trace propagation.
	// Use Background context for request lifecycle (to avoid cancellation from reconciliation),
	// but propagate trace context from caller's ctx for observability.
	httpClient := httputil.NewClientWithTracing(ctx, timeout)
	jwkCtx := oidc.ClientContext(gocontext.Background(), httpClient)

	return &jwksVerifier{
		jwks: oidc.NewRemoteKeySet(jwkCtx, jwksUrl),
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

// RefresherRunning reports whether the background refresher of the underlying verifier is running.
// Exposed so the reconciler tests can assert on the lifecycle of a config held in the index.
func (j *JWTAuthentication) RefresherRunning() bool {
	verifier, ok := j.verifier.(*oidcProviderVerifier)
	if !ok {
		return false
	}
	verifier.mu.RLock()
	defer verifier.mu.RUnlock()
	return verifier.refresher != nil
}
