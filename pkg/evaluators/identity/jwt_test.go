package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/httptest"
	mock_workers "github.com/kuadrant/authorino/pkg/workers/mocks"

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

func TestOidcVerifyTokenServerUnknownHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), "http://unreachable-server", 0)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(context.TODO(), jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.Error(t, err, "missing openid connect configuration")
}

func TestOidcVerifyTokenServerNotFound(t *testing.T) {
	authServer := httptest.NewHttpServerMock(oidcServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": func() httptest.HttpServerMockResponse { return httptest.HttpServerMockResponse{Status: 404} },
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), 0)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(context.TODO(), jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.Error(t, err, "missing openid connect configuration")
}

func TestOidcVerifyTokenServerInternalError(t *testing.T) {
	authServer := httptest.NewHttpServerMock(oidcServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": func() httptest.HttpServerMockResponse { return httptest.HttpServerMockResponse{Status: 500} },
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), 0)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(context.TODO(), jwtVerifier, authCredMock)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetRequest().Return(jwtAuthenticationRequestMock)
	authCredMock.EXPECT().GetCredentialsFromReq(jwtAuthenticationRequestMock.GetAttributes().GetRequest().GetHttp()).Return("token", nil)
	token, err := evaluator.Call(pipelineMock, context.TODO())

	assert.Check(t, token == nil)
	assert.Error(t, err, "missing openid connect configuration")
}

func TestOidcProviderRefreshDisabled(t *testing.T) {
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

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), 0)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(context.TODO(), jwtVerifier, authCredMock)
	defer evaluator.Clean(context.Background())

	time.Sleep(2 * time.Second)
	assert.Equal(t, 1, count)
	verifier, _ := jwtVerifier.(*oidcProviderVerifier)
	assert.Equal(t, fmt.Sprintf("http://%v/auth?count=1", oidcServerHost), verifier.provider.Endpoint().AuthURL)
}

func TestOidcProviderRefresh(t *testing.T) {
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

	jwtVerifier := NewOIDCProviderVerifier(context.TODO(), fmt.Sprintf("http://%v", oidcServerHost), 3)
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(context.TODO(), jwtVerifier, authCredMock)
	defer evaluator.Clean(context.Background())

	verifier, _ := jwtVerifier.(*oidcProviderVerifier)
	assert.Check(t, verifier.refresher != nil)

	time.Sleep(4 * time.Second)
	assert.Equal(t, 2, count)
	verifier, _ = jwtVerifier.(*oidcProviderVerifier)
	assert.Equal(t, fmt.Sprintf("http://%v/auth?count=2", oidcServerHost), verifier.provider.Endpoint().AuthURL)
}

func TestOidcProviderRefreshClean(t *testing.T) {
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
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewJWTAuthentication(context.TODO(), jwtVerifier, authCredMock)

	refresher := mock_workers.NewMockWorker(ctrl)
	jwtVerifier.refresher = refresher
	refresher.EXPECT().Stop()
	err := evaluator.Clean(context.Background())
	assert.NilError(t, err)
}
