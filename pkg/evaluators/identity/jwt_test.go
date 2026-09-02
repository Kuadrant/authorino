package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	gohttptest "net/http/httptest"
	"sync"
	"testing"
	"time"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	mock_identity "github.com/kuadrant/authorino/pkg/evaluators/identity/mocks"
	"github.com/kuadrant/authorino/pkg/httptest"
	mock_workers "github.com/kuadrant/authorino/pkg/workers/mocks"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

const oidcServerHost = "127.0.0.1:9006"

var jwtAuthenticationRequestMock = &envoy_auth.CheckRequest{
	Attributes: &envoy_auth.AttributeContext{
		Request: &envoy_auth.AttributeContext_Request{
			Http: &envoy_auth.AttributeContext_HttpRequest{
				Headers: map[string]string{
					"authorization": "Bearer token",
				},
			},
		},
	},
}

func oidcServerMockResponse(count int) httptest.HttpServerMockResponse {
	return httptest.HttpServerMockResponse{
		Status:  200,
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    fmt.Sprintf(`{ "issuer": "http://%v", "authorization_endpoint": "http://%v/auth?count=%v" }`, oidcServerHost, oidcServerHost, count),
	}
}

func TestJWTAuthenticationCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := mock_identity.NewMockJWTVerifier(ctrl)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	const issuer = "http://keycloak:8080/auth/realms/kuadrant"
	const rawToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5cm0tSWpweGRfd3dzVmZPR1FUWWE2NHVmdEVlOHY3VG5sQzFMLUl4ZUlJIn0.eyJleHAiOjIxNDU4NjU3NzMsImlhdCI6MTY1OTA4ODE3MywianRpIjoiZDI0ODliMWEtYjY0Yi00MzRhLWJhNmItMmQ4OGIyY2I1ZWE3IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjgwODAvYXV0aC9yZWFsbXMva3VhZHJhbnQiLCJhdWQiOlsicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiMWEwYjZjNmUtNDdmNy00ZjI1LWEyNjYtYzg3MzZhOTkxODQ0IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZGVtbyIsInNlc3Npb25fc3RhdGUiOiIxMTdkMTc1Ni1mM2RlLTRjM2MtOWEwZS0zYjU5Mzc2YmI0ZTgiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwibWVtYmVyIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwidmlldy1yZWFsbSIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwicmVhbG0tYWRtaW4iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjExN2QxNzU2LWYzZGUtNGMzYy05YTBlLTNiNTkzNzZiYjRlOCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IlBldGVyIFdobyIsInByZWZlcnJlZF91c2VybmFtZSI6InBldGVyIiwiZ2l2ZW5fbmFtZSI6IlBldGVyIiwiZmFtaWx5X25hbWUiOiJXaG8iLCJlbWFpbCI6InBldGVyQGt1YWRyYW50LmlvIn0.Yy2aWR6_u0NBLx8x--OToYipfQ1f1KcC8zedsKDiymcbBiAaxrBQmaV2JC1PQVEgyxwmyMk0Rao2MdKGWk6pXB9mTUF5FX-pS8mkPIMUt1UVGJgzq7WR9KfRqdZSzRtFQHoDmTeA1-msayMYTAD8xtUH4JYRNbIXjY2cEtn8LjuLpQVR3DR4_ARMrEYXiDBS3rmmFKHdipqU7ozwJ_gtpZv8vfeiO3mUPyQLJKQ-nKpe_Z5z7tm_Ewh5MN2oBfn_0pcdANB3pe2RclGAm-YHlyNDTnAZL2Y1gdCmwzwigk7AJcgWtPqnRzvEQ9zRBxQRai5W5aNKYTxuKIG8k9N05w"

	v := oidc.NewVerifier(issuer, nil, &oidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true, SkipExpiryCheck: true, InsecureSkipSignatureCheck: true})
	token, _ := v.Verify(context.TODO(), rawToken)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return(rawToken, nil)
	jwtVerifier.EXPECT().Verify(gomock.Any(), rawToken).Return(token, nil)
	obj, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Equal(t, obj.(map[string]any)["iss"].(string), issuer)
	assert.NilError(t, err)
}

func TestOIDCProviderVerifierUnknownHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), "http://unreachable-server", "", 0, nil)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.Error(t, err, "missing openid connect configuration")
}

func TestOIDCProviderVerifierNotFound(t *testing.T) {
	authServer := httptest.NewHttpServerMock(oidcServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": func() httptest.HttpServerMockResponse { return httptest.HttpServerMockResponse{Status: 404} },
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), "", 0, nil)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.Error(t, err, "missing openid connect configuration")
}

func TestOIDCProviderVerifierInternalError(t *testing.T) {
	authServer := httptest.NewHttpServerMock(oidcServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": func() httptest.HttpServerMockResponse { return httptest.HttpServerMockResponse{Status: 500} },
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), "", 0, nil)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.Error(t, err, "missing openid connect configuration")
}

func TestOIDCProviderVerifierRefresh(t *testing.T) {
	var mu sync.Mutex
	count := 0
	authServer := httptest.NewHttpServerMock(oidcServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": func() httptest.HttpServerMockResponse {
			mu.Lock()
			count += 1
			currentCount := count
			mu.Unlock()
			return oidcServerMockResponse(currentCount)
		},
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), "", 3, nil) // refresh every 3 seconds
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)
	defer func(evaluator *JWTAuthentication, ctx context.Context) {
		_ = evaluator.Clean(ctx)
	}(evaluator, context.Background())

	verifier, _ := jwtVerifier.(*oidcProviderVerifier)
	assert.Check(t, verifier.refresher != nil)

	time.Sleep(4 * time.Second)
	mu.Lock()
	currentCount := count
	mu.Unlock()
	assert.Equal(t, 2, currentCount)
	verifier, _ = jwtVerifier.(*oidcProviderVerifier)
	provider := verifier.GetProvider()
	assert.Equal(t, fmt.Sprintf("http://%v/auth?count=2", oidcServerHost), provider.Endpoint().AuthURL)
}

func TestOIDCProviderVerifierRefreshDisabled(t *testing.T) {
	count := 0
	authServer := httptest.NewHttpServerMock(oidcServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": func() httptest.HttpServerMockResponse {
			count += 1
			return oidcServerMockResponse(count)
		},
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), "", 0, nil) // refresh disabled
	defer func(verifier *oidcProviderVerifier, ctx context.Context) {
		_ = verifier.Clean(ctx)
	}(jwtVerifier.(*oidcProviderVerifier), context.Background())

	time.Sleep(2 * time.Second)
	assert.Equal(t, 1, count)
	verifier, _ := jwtVerifier.(*oidcProviderVerifier)
	assert.Equal(t, fmt.Sprintf("http://%v/auth?count=1", oidcServerHost), verifier.provider.Endpoint().AuthURL)
}

func TestOIDCProviderVerifierRefreshClean(t *testing.T) {
	count := 0
	authServer := httptest.NewHttpServerMock(oidcServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": func() httptest.HttpServerMockResponse {
			count += 1
			return oidcServerMockResponse(count)
		},
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := &oidcProviderVerifier{issuerUrl: fmt.Sprintf("http://%v", oidcServerHost)}
	refresher := mock_workers.NewMockWorker(ctrl)
	jwtVerifier.refresher = refresher
	refresher.EXPECT().Stop()
	err := jwtVerifier.Clean(context.Background())
	assert.NilError(t, err)
}

func TestJWKSVerifierTokenExpired(t *testing.T) {
	authServer := httptest.NewHttpServerMock(oidcServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/certs": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{
				Status:  200,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    `{"keys":[{"kid":"nRygyU6fNLNMYEeCr4zXePyVEQFR85BXKZwt8pvlNYo","kty":"RSA","alg":"RS256","use":"sig","n":"wHMzFkVkYixA218jTCBSWJYwV1qsHq1lfNWG47CdLFWT6O-CZ2aGmb1vefOKpxvPzrP-RWQywllHpoktEoAmw6uy6d_A2TfdOdGvIGLgKLdm-4VXRFc5qlm6ipuXj8cCvo4Ff8UXxUewZrgvLMlf1Dq5GlfcfUOB6wAPfePmg2r5MlPEgC5ps8XF2hFweI6HjUM_EPUaxP3wkmv9cgU5TfTnbtStNLtdlrHDQDzx9x0GgQW1ttzLJ6O0E0Z6m1ghUnf1PPNCB9uQx6Z0xAmPEOAMmg4bbfn3550penZ6YvJqjZzu6EdHyhh6hyuNOUAihuKL2zXjfYnuS7dO0JAgzw","e":"AQAB","x5c":["MIICnzCCAYcCBgGXF016gDANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhrdWFkcmFudDAeFw0yNTA1MjgxNDI5MDNaFw0zNTA1MjgxNDMwNDNaMBMxETAPBgNVBAMMCGt1YWRyYW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHMzFkVkYixA218jTCBSWJYwV1qsHq1lfNWG47CdLFWT6O+CZ2aGmb1vefOKpxvPzrP+RWQywllHpoktEoAmw6uy6d/A2TfdOdGvIGLgKLdm+4VXRFc5qlm6ipuXj8cCvo4Ff8UXxUewZrgvLMlf1Dq5GlfcfUOB6wAPfePmg2r5MlPEgC5ps8XF2hFweI6HjUM/EPUaxP3wkmv9cgU5TfTnbtStNLtdlrHDQDzx9x0GgQW1ttzLJ6O0E0Z6m1ghUnf1PPNCB9uQx6Z0xAmPEOAMmg4bbfn3550penZ6YvJqjZzu6EdHyhh6hyuNOUAihuKL2zXjfYnuS7dO0JAgzwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCFdkqG9Hm8nfFzAzyCWh5DrjE54e9Qj9/dosRkyV++Scaf8UfY7MC1y5n/aC29vP1SRPwkPRMXTFj0lEL+edQ9Y2IyyhIyH/V45pYFfeW7lJngED6wCCqWgObDEiX83S+GTTQIVxoEppW2hWTdWeSNOaCV5TJ70fGOhXgLeeY73/VmOnNkt5x3dSwS5Uk/b78BUCh+ZVjuwcXxzF2u9VTQyP/Qrpy7xsROYptzB8NabinieREe0XBPY4hesyWbVKYyliIhWwvjr9JVjfjr2zQTqz82625ZlK/hnxJQVdpMXaCm5A5bCIxuhDse+eaNbIAdHdKBXZDujG2URmHB5Fqk"],"x5t":"as4omm562civnCct6fmfOMzX1zc","x5t#S256":"EY_x32hxjmBic5riPdoGDOFSN8CqZOYUaaB6KnCU-co"}]}`,
			}
		},
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewJwksVerifier(context.TODO(), fmt.Sprintf("http://%v/certs", oidcServerHost), "", nil)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	const rawToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJuUnlneVU2Zk5MTk1ZRWVDcjR6WGVQeVZFUUZSODVCWEtad3Q4cHZsTllvIn0.eyJleHAiOjE3NDg1MTIyMTYsImlhdCI6MTc0ODUxMTkxNiwianRpIjoiODJhOGViYTctYTAzYi00YzM5LTkxYjEtOTU1OTNiODgxMTFmIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjgwODAvcmVhbG1zL2t1YWRyYW50IiwiYXVkIjpbInJlYWxtLW1hbmFnZW1lbnQiLCJhY2NvdW50Il0sInN1YiI6ImY2ZjZlYTlhLTU3YmMtNGJjYS1hYTFiLTk2ODdkNzIyMDgxNyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImRlbW8iLCJzZXNzaW9uX3N0YXRlIjoiOGJjMTBlNjMtNDhkYy00ZWJhLTllMTgtZDlkMWQyZWU4NTRiIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwibWVtYmVyIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwidmlldy1yZWFsbSIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwicmVhbG0tYWRtaW4iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiI4YmMxMGU2My00OGRjLTRlYmEtOWUxOC1kOWQxZDJlZTg1NGIiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiam9obiIsImdpdmVuX25hbWUiOiJKb2huIiwiZmFtaWx5X25hbWUiOiJEb2UiLCJlbWFpbCI6ImpvaG5Aa3VhZHJhbnQuaW8ifQ.vMlILMmxjadto_CHahbNdSQwhVIJil2pnCwA5dKEZlrYeLnTo1zrptVsGFzyvTSwiB6d0SozoGBqVRU7L6amFcd9KBxk-4dfDhMcKn6NfqBzuYs6NR20i7wknOsUgtdn5O7DmHYjKkNs1Kr55JG6htCLlHRXa4O6wun6qWC3Gp03aLS5n7a0vxPlnPDNszy-QXT4iXeED5n7eJ1s0CVZrD6pZ4fmYWaDWW8PUj25hOBukR6bRwKGN0qioGGYQtgVq491AsvG3cp083nlGfVj9hAEWDtwvuuokmCHCWPTbsppT1CNUcYXODl4QK95VUi7NK66NAbjVc9uD69awei-1A"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return(rawToken, nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.ErrorContains(t, err, "oidc: token is expired")
}

func TestJWKSVerifierMalformedJWT(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewJwksVerifier(context.TODO(), fmt.Sprintf("http://%v/certs", oidcServerHost), "", nil)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.ErrorContains(t, err, "oidc: malformed jwt")
}

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
