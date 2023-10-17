package identity

import (
	"context"
	"fmt"
	"testing"
	"time"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/httptest"
	mock_workers "github.com/kuadrant/authorino/pkg/workers/mocks"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

const oidcServerHost = "127.0.0.1:9006"

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

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)

	evaluator := NewOIDC("http://unreachable-server", authCredMock, 0, context.TODO())
	token, err := evaluator.verifyToken("token", context.TODO())

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

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)

	evaluator := NewOIDC(fmt.Sprintf("http://%v", oidcServerHost), authCredMock, 0, context.TODO())
	token, err := evaluator.verifyToken("token", context.TODO())

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

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)

	evaluator := NewOIDC(fmt.Sprintf("http://%v", oidcServerHost), authCredMock, 0, context.TODO())
	token, err := evaluator.verifyToken("token", context.TODO())

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

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)

	evaluator := NewOIDC(fmt.Sprintf("http://%v", oidcServerHost), authCredMock, 0, context.TODO())
	defer evaluator.Clean(context.Background())
	time.Sleep(2 * time.Second)

	assert.Equal(t, 1, count)
	assert.Equal(t, fmt.Sprintf("http://%v/auth?count=1", oidcServerHost), evaluator.provider.Endpoint().AuthURL)
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

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)

	evaluator := NewOIDC(fmt.Sprintf("http://%v", oidcServerHost), authCredMock, 3, context.TODO())
	defer evaluator.Clean(context.Background())

	assert.Check(t, evaluator.refresher != nil)

	time.Sleep(4 * time.Second)
	assert.Equal(t, 2, count)
	assert.Equal(t, fmt.Sprintf("http://%v/auth?count=2", oidcServerHost), evaluator.provider.Endpoint().AuthURL)
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

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	evaluator := NewOIDC(fmt.Sprintf("http://%v", oidcServerHost), authCredMock, 0, context.TODO())
	refresher := mock_workers.NewMockWorker(ctrl)
	evaluator.refresher = refresher
	refresher.EXPECT().Stop()
	err := evaluator.Clean(context.Background())
	assert.NilError(t, err)
}
