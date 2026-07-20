package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	gohttptest "net/http/httptest"
	"testing"
	"time"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/httptest"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

const (
	issuerTestServerHost = "127.0.0.1:9007"
	trustedIssuer        = "http://" + issuerTestServerHost
	foreignIssuer        = "http://foreign-issuer.example.com"
	externalIssuer       = "https://external-issuer.example.com"
	signingKeyId         = "shared-signing-key"
)

// newSharedSigningKey returns an RSA key plus the JWKS document advertising its
// public part, modelling an identity provider whose signing key is shared across
// more than one issuer (multi-tenant IdPs, or Authorino wristbands issued by two
// AuthConfigs backed by the same signing-key Secret).
func newSharedSigningKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key.Public(),
		KeyID:     signingKeyId,
		Algorithm: "RS256",
		Use:       "sig",
	}}}
	encoded, err := json.Marshal(jwks)
	assert.NilError(t, err)

	return key, string(encoded)
}

// signToken mints an unexpired RS256 token for the given issuer, signed with key.
func signToken(t *testing.T, key *rsa.PrivateKey, issuer string) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer,
		"sub": "user",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = signingKeyId

	raw, err := token.SignedString(key)
	assert.NilError(t, err)
	return raw
}

// newIdPMock serves the OIDC discovery document and JWKS of the trusted issuer.
func newIdPMock(jwks string) *gohttptest.Server {
	return newIdPMockWithIssuer(trustedIssuer, jwks)
}

// newIdPMockWithIssuer serves discovery at issuerTestServerHost but advertises advertisedIssuer,
// modelling a cluster-internal discovery URL with a different (e.g. external) issuer in tokens.
// JWKS is always served from the discovery host so keys remain fetchable.
func newIdPMockWithIssuer(advertisedIssuer, jwks string) *gohttptest.Server {
	return httptest.NewHttpServerMock(issuerTestServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": httptest.NewHttpServerMockResponseFuncJSON(
			fmt.Sprintf(`{"issuer":%q,"jwks_uri":"%v/certs"}`, advertisedIssuer, trustedIssuer),
		),
		"/certs": httptest.NewHttpServerMockResponseFuncJSON(jwks),
	})
}

func callWithToken(t *testing.T, verifier JWTVerifier, rawToken string) (any, error) {
	t.Helper()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(verifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().
		GetCredentialsFromAuthReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).
		Return(rawToken, nil)

	return evaluator.Call(pipelineMock, context.TODO())
}

// issuerUrl path, issuer set: a token signed by a key in the configured provider's JWKS
// but whose `iss` names a different issuer must NOT authenticate.
func TestOIDCProviderVerifier_IssuerSet_RejectsForeignIssuer(t *testing.T) {
	key, jwks := newSharedSigningKey(t)
	authServer := newIdPMock(jwks)
	defer authServer.Close()

	verifier := NewOIDCProviderVerifier(context.TODO(), trustedIssuer, trustedIssuer, 0, nil)

	obj, err := callWithToken(t, verifier, signToken(t, key, foreignIssuer))

	assert.Check(t, obj == nil, "token from a foreign issuer was accepted as a valid identity")
	assert.ErrorContains(t, err, "issued by a different provider")
}

// issuerUrl path, issuer unset (the default): legacy behavior is preserved — the foreign-issuer
// token is still accepted, and callers may enforce `iss` via an authorization rule. Pins the
// opt-in nature of the field.
func TestOIDCProviderVerifier_IssuerUnset_AcceptsForeignIssuer(t *testing.T) {
	key, jwks := newSharedSigningKey(t)
	authServer := newIdPMock(jwks)
	defer authServer.Close()

	verifier := NewOIDCProviderVerifier(context.TODO(), trustedIssuer, "", 0, nil)

	obj, err := callWithToken(t, verifier, signToken(t, key, foreignIssuer))

	assert.NilError(t, err)
	assert.Equal(t, obj.(map[string]any)["iss"].(string), foreignIssuer)
}

// issuerUrl path, issuer set: the happy path (matching `iss`) still authenticates.
func TestOIDCProviderVerifier_IssuerSet_AcceptsMatchingIssuer(t *testing.T) {
	key, jwks := newSharedSigningKey(t)
	authServer := newIdPMock(jwks)
	defer authServer.Close()

	verifier := NewOIDCProviderVerifier(context.TODO(), trustedIssuer, trustedIssuer, 0, nil)

	obj, err := callWithToken(t, verifier, signToken(t, key, trustedIssuer))

	assert.NilError(t, err)
	assert.Equal(t, obj.(map[string]any)["iss"].(string), trustedIssuer)
}

// issuerUrl path, issuer differs from issuerUrl (cluster-internal discovery / external issuer):
// discovery and JWKS are fetched from issuerUrl while `iss` is enforced against the external
// issuer — accepting the legitimate external-issuer token and rejecting a wrong-issuer one.
func TestOIDCProviderVerifier_IssuerDiffersFromIssuerUrl_EnforcesConfiguredIssuer(t *testing.T) {
	key, jwks := newSharedSigningKey(t)
	authServer := newIdPMockWithIssuer(externalIssuer, jwks) // served at trustedIssuer, advertises externalIssuer
	defer authServer.Close()

	verifier := NewOIDCProviderVerifier(context.TODO(), trustedIssuer, externalIssuer, 0, nil)

	obj, err := callWithToken(t, verifier, signToken(t, key, externalIssuer))
	assert.NilError(t, err)
	assert.Equal(t, obj.(map[string]any)["iss"].(string), externalIssuer)

	obj, err = callWithToken(t, verifier, signToken(t, key, foreignIssuer))
	assert.Check(t, obj == nil, "wrong-issuer token accepted in the internal/external split configuration")
	assert.ErrorContains(t, err, "issued by a different provider")
}

// jwksUrl path, issuer set: `iss` is enforced
func TestJWKSVerifier_IssuerSet_EnforcesIssuer(t *testing.T) {
	key, jwks := newSharedSigningKey(t)
	authServer := newIdPMock(jwks)
	defer authServer.Close()

	verifier := NewJwksVerifier(context.TODO(), trustedIssuer+"/certs", trustedIssuer, nil)

	obj, err := callWithToken(t, verifier, signToken(t, key, trustedIssuer))
	assert.NilError(t, err)
	assert.Equal(t, obj.(map[string]any)["iss"].(string), trustedIssuer)

	obj, err = callWithToken(t, verifier, signToken(t, key, foreignIssuer))
	assert.Check(t, obj == nil, "foreign-issuer token accepted on the jwksUrl path with issuer set")
	assert.ErrorContains(t, err, "issued by a different provider")
}

// jwksUrl path, issuer unset: legacy behavior — any signature-valid token is accepted
// regardless of `iss`.
func TestJWKSVerifier_IssuerUnset_IgnoresIssuer(t *testing.T) {
	key, jwks := newSharedSigningKey(t)
	authServer := newIdPMock(jwks)
	defer authServer.Close()

	verifier := NewJwksVerifier(context.TODO(), trustedIssuer+"/certs", "", nil)

	obj, err := callWithToken(t, verifier, signToken(t, key, foreignIssuer))

	assert.NilError(t, err)
	assert.Equal(t, obj.(map[string]any)["iss"].(string), foreignIssuer)
}
