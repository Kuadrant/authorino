package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	mock_identity "github.com/kuadrant/authorino/pkg/evaluators/identity/mocks"
	"github.com/kuadrant/authorino/pkg/httptest"
	mock_workers "github.com/kuadrant/authorino/pkg/workers/mocks"

	oidc "github.com/coreos/go-oidc/v3/oidc"
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
	authCredMock.EXPECT().GetCredentialsFromReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return(rawToken, nil)
	jwtVerifier.EXPECT().Verify(gomock.Any(), rawToken).Return(token, nil)
	obj, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Equal(t, obj.(map[string]any)["iss"].(string), issuer)
	assert.NilError(t, err)
}

func TestOIDCProviderVerifierUnknownHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), "http://unreachable-server", 0)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
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

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), 0)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
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

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), 0)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.Error(t, err, "missing openid connect configuration")
}

func TestOIDCProviderVerifierRefresh(t *testing.T) {
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

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), 3) // refresh every 3 seconds
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)
	defer evaluator.Clean(context.Background())

	verifier, _ := jwtVerifier.(*oidcProviderVerifier)
	assert.Check(t, verifier.refresher != nil)

	time.Sleep(4 * time.Second)
	assert.Equal(t, 2, count)
	verifier, _ = jwtVerifier.(*oidcProviderVerifier)
	assert.Equal(t, fmt.Sprintf("http://%v/auth?count=2", oidcServerHost), verifier.provider.Endpoint().AuthURL)
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

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), 0) // refresh disabled
	defer jwtVerifier.(*oidcProviderVerifier).Clean(context.Background())

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

	jwtVerifier := NewJwksVerifier(context.TODO(), fmt.Sprintf("http://%v/certs", oidcServerHost))
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	const rawToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJuUnlneVU2Zk5MTk1ZRWVDcjR6WGVQeVZFUUZSODVCWEtad3Q4cHZsTllvIn0.eyJleHAiOjE3NDg1MTIyMTYsImlhdCI6MTc0ODUxMTkxNiwianRpIjoiODJhOGViYTctYTAzYi00YzM5LTkxYjEtOTU1OTNiODgxMTFmIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjgwODAvcmVhbG1zL2t1YWRyYW50IiwiYXVkIjpbInJlYWxtLW1hbmFnZW1lbnQiLCJhY2NvdW50Il0sInN1YiI6ImY2ZjZlYTlhLTU3YmMtNGJjYS1hYTFiLTk2ODdkNzIyMDgxNyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImRlbW8iLCJzZXNzaW9uX3N0YXRlIjoiOGJjMTBlNjMtNDhkYy00ZWJhLTllMTgtZDlkMWQyZWU4NTRiIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwibWVtYmVyIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwidmlldy1yZWFsbSIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwicmVhbG0tYWRtaW4iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiI4YmMxMGU2My00OGRjLTRlYmEtOWUxOC1kOWQxZDJlZTg1NGIiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiam9obiIsImdpdmVuX25hbWUiOiJKb2huIiwiZmFtaWx5X25hbWUiOiJEb2UiLCJlbWFpbCI6ImpvaG5Aa3VhZHJhbnQuaW8ifQ.vMlILMmxjadto_CHahbNdSQwhVIJil2pnCwA5dKEZlrYeLnTo1zrptVsGFzyvTSwiB6d0SozoGBqVRU7L6amFcd9KBxk-4dfDhMcKn6NfqBzuYs6NR20i7wknOsUgtdn5O7DmHYjKkNs1Kr55JG6htCLlHRXa4O6wun6qWC3Gp03aLS5n7a0vxPlnPDNszy-QXT4iXeED5n7eJ1s0CVZrD6pZ4fmYWaDWW8PUj25hOBukR6bRwKGN0qioGGYQtgVq491AsvG3cp083nlGfVj9hAEWDtwvuuokmCHCWPTbsppT1CNUcYXODl4QK95VUi7NK66NAbjVc9uD69awei-1A"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return(rawToken, nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.ErrorContains(t, err, "oidc: token is expired")
}

func TestJWKSVerifierMalformedJWT(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewJwksVerifier(context.TODO(), fmt.Sprintf("http://%v/certs", oidcServerHost))
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.ErrorContains(t, err, "oidc: malformed jwt")
}
