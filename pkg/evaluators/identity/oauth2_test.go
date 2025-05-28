package identity

import (
	"context"
	"fmt"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/httptest"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

const oauthServerHost = "127.0.0.1:9004"

func TestOAuth2Call(t *testing.T) {
	authServer := httptest.NewHttpServerMock(oauthServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/introspect-active": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: `{ "active": true }`}
		},
		"/introspect-inactive": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: `{ "active": false }`}
		},
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(gomock.Any()).Return("oauth-opaque-token", nil).AnyTimes()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetHttp().Return(nil).AnyTimes()

	ctx := context.Background()

	{
		oauthEvaluator := NewOAuth2Identity(fmt.Sprintf("http://%v/introspect-active", oauthServerHost), "access_token", "client-id", "client-secret", authCredMock)
		obj, err := oauthEvaluator.Call(pipelineMock, ctx)
		assert.NilError(t, err)
		claims := obj.(map[string]interface{})
		assert.Assert(t, claims["active"])
	}

	{
		oauthEvaluator := NewOAuth2Identity(fmt.Sprintf("http://%v/introspect-inactive", oauthServerHost), "access_token", "client-id", "client-secret", authCredMock)
		_, err := oauthEvaluator.Call(pipelineMock, ctx)
		assert.Error(t, err, "token is not active")
	}
}

func TestDefaultTokenTypeHint(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)

	{
		oauthEvaluator := NewOAuth2Identity("http://server.example.com", "", "client-id", "client-secret", authCredMock)
		assert.Equal(t, "access_token", oauthEvaluator.TokenTypeHint)
	}

	{
		oauthEvaluator := NewOAuth2Identity("http://server.example.com", "refresh_token", "client-id", "client-secret", authCredMock)
		assert.Equal(t, "refresh_token", oauthEvaluator.TokenTypeHint)
	}
}
