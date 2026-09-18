package identity

import (
	gocontext "context"
	"errors"
	"net/url"
	"slices"
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
	msg_jwtVerifierDoesNotStoreOpenIdConfig       = "rule does not store openid configuration"
	msg_jwtAudienceMissing                        = "jwt: token has no audience (aud) claim"
	msg_jwtAudienceNotAccepted                    = "jwt: token audience not accepted"
)

// oidcConfig returns the go-oidc verifier config shared by both JWT verifier flavors.
// SkipClientIDCheck is always on: go-oidc can only match the aud claim against a single client
// ID, so the configured audiences are enforced by JWTAuthentication after verification instead.
// The issuer check is enabled only when an expected issuer is configured —
// an empty issuer means "do not verify the iss claim" (the default, backwards compatible),
// a non-empty issuer means "reject any token whose iss does not equal it".
func oidcConfig(issuer string) *oidc.Config {
	return &oidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: issuer == ""}
}

type JWTAuthentication struct {
	auth.AuthCredentials

	verifier  JWTVerifier
	audiences []string
}

// NewJWTAuthentication builds the evaluator around a verifier. When audiences is non-empty, a
// verified token must also carry at least one of them in its aud claim; an empty list means
// "do not verify the aud claim" (the default, backwards compatible).
func NewJWTAuthentication(verifier JWTVerifier, creds auth.AuthCredentials, audiences []string) *JWTAuthentication {
	return &JWTAuthentication{
		AuthCredentials: creds,
		verifier:        verifier,
		audiences:       slices.Clone(audiences),
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

	// verify audience
	if err := j.checkAudience(idToken); err != nil {
		return nil, err
	}

	// extract claims
	var claims interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// checkAudience rejects a verified token whose aud claim does not include any of the configured
// audiences. go-oidc normalises the claim to a slice whether the token encodes it as a string or
// as an array, so both JSON shapes are covered by the same intersection check; it also turns an
// empty or null aud into [""], and an empty audience never matches. The errors are static: they
// reach the client through the deny response reason, so they neither echo the token's audiences
// (caller-controlled input) nor disclose the configured list.
func (j *JWTAuthentication) checkAudience(idToken *oidc.IDToken) error {
	if len(j.audiences) == 0 {
		return nil
	}
	present := false
	for _, aud := range idToken.Audience {
		if aud == "" {
			continue
		}
		if slices.Contains(j.audiences, aud) {
			return nil
		}
		present = true
	}
	if !present {
		return errors.New(msg_jwtAudienceMissing)
	}
	return errors.New(msg_jwtAudienceNotAccepted)
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
	issuerUrl        string
	issuer           string
	config           *oidc.Config
	timeout          *int
	maxResponseBytes int64

	mu        sync.RWMutex
	provider  *oidc.Provider
	refresher workers.Worker
}

func NewOIDCProviderVerifier(ctx gocontext.Context, issuerUrl string, issuer string, ttl int, timeout *int, maxResponseBytes ...int64) JWTVerifier {
	var maxBytes int64
	if len(maxResponseBytes) > 0 {
		maxBytes = maxResponseBytes[0]
	}
	v := &oidcProviderVerifier{
		issuerUrl:        issuerUrl,
		issuer:           issuer,
		config:           oidcConfig(issuer),
		timeout:          timeout,
		maxResponseBytes: maxBytes,
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

	// No lock is held across Verify on purpose: getOpenIdProvider already returned a stable
	// provider snapshot under its own lock, the go-oidc Provider is immutable, and v.config is
	// set once at construction. Holding a read lock across the crypto checks and lazy JWKS fetch
	// would needlessly block the background refresher's write lock in getOpenIdProvider.
	idToken, err := provider.Verifier(v.config).Verify(ctx, rawIDToken)
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
	if v.refresher == nil {
		return nil
	}
	return v.refresher.Stop()
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
		// Create HTTP client with timeout, trace propagation, and optional response body size limit.
		// Use Background context for request lifecycle (to avoid cancellation from reconciliation),
		// but propagate trace context from caller's ctx for observability.
		httpClient := httputil.NewClient(httputil.WithTimeout(v.timeout), httputil.WithTracing(ctx), httputil.WithMaxResponseBytes(v.maxResponseBytes))
		discoveryCtx := oidc.ClientContext(gocontext.Background(), httpClient)

		// When an expected issuer is configured that differs from the discovery URL, pin it so
		// discovery and JWKS are still fetched from issuerUrl while the verifier enforces the
		// token's iss against the configured issuer. This supports setups where the OpenID
		// Connect discovery endpoint is reached at a different URL than the issuer stamped into
		// tokens (e.g. cluster-internal discovery vs external issuer).
		if v.issuer != "" && v.issuer != v.issuerUrl {
			discoveryCtx = oidc.InsecureIssuerURLContext(discoveryCtx, v.issuer)
		}

		if provider, err := oidc.NewProvider(discoveryCtx, v.issuerUrl); err != nil {
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
	verifier *oidc.IDTokenVerifier
}

func NewJwksVerifier(ctx gocontext.Context, jwksUrl string, issuer string, timeout *int, maxResponseBytes ...int64) JWTVerifier {
	// Create HTTP client with timeout, trace propagation, and optional response body size limit.
	// Use Background context for request lifecycle (to avoid cancellation from reconciliation),
	// but propagate trace context from caller's ctx for observability.
	var maxBytes int64
	if len(maxResponseBytes) > 0 {
		maxBytes = maxResponseBytes[0]
	}
	httpClient := httputil.NewClient(httputil.WithTimeout(timeout), httputil.WithTracing(ctx), httputil.WithMaxResponseBytes(maxBytes))
	jwkCtx := oidc.ClientContext(gocontext.Background(), httpClient)

	// The remote key set self-refreshes on key rotation, and issuer and config are fixed for the
	// lifetime of the verifier, so it can be built once here and reused for every request.
	return &jwksVerifier{
		verifier: oidc.NewVerifier(issuer, oidc.NewRemoteKeySet(jwkCtx, jwksUrl), oidcConfig(issuer)),
	}
}

func (v *jwksVerifier) Verify(ctx gocontext.Context, rawIDToken string) (*oidc.IDToken, error) {
	return v.verifier.Verify(ctx, rawIDToken)
}

// impl: auth.AuthConfigCleaner
func (v *jwksVerifier) Clean(_ gocontext.Context) error {
	return nil
}
