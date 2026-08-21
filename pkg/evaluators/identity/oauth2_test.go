package identity

import (
	"context"
	"fmt"
	"strings"
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
		// RFC 6749 error response returned e.g. on invalid client credentials: valid JSON, non-200, no "active".
		"/introspect-error": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 401, Body: `{"error":"invalid_request","error_description":"Authentication failed."}`}
		},
		// 200 response that omits the "active" field.
		"/introspect-missing-active": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: `{ "sub": "1234" }`}
		},
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(gomock.Any()).Return("oauth-opaque-token", nil).AnyTimes()

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

	// A non-200 introspection response (e.g. invalid client credentials) must return a clean
	// error instead of panicking on the missing "active" field. See issue #651.
	{
		oauthEvaluator := NewOAuth2Identity(fmt.Sprintf("http://%v/introspect-error", oauthServerHost), "access_token", "client-id", "wrong-secret", authCredMock)
		obj, err := oauthEvaluator.Call(pipelineMock, ctx)
		assert.Assert(t, obj == nil)
		assert.ErrorContains(t, err, "token introspection request failed")
	}

	// A 200 response that omits "active" must also return a clean error rather than panicking.
	{
		oauthEvaluator := NewOAuth2Identity(fmt.Sprintf("http://%v/introspect-missing-active", oauthServerHost), "access_token", "client-id", "client-secret", authCredMock)
		obj, err := oauthEvaluator.Call(pipelineMock, ctx)
		assert.Assert(t, obj == nil)
		assert.ErrorContains(t, err, "missing or non-boolean")
	}
}

func TestOAuth2MaxResponseBytes(t *testing.T) {
	largeClaims := `{ "active": true, "sub": "user123", "extra": "` + strings.Repeat("x", 1000) + `" }`

	authServer := httptest.NewHttpServerMock(oauthServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/introspect-large": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: largeClaims}
		},
	})
	defer authServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromAuthReq(gomock.Any()).Return("oauth-opaque-token", nil).AnyTimes()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetHttp().Return(nil).AnyTimes()

	ctx := context.Background()

	t.Run("within limit", func(t *testing.T) {
		oauthEvaluator := NewOAuth2Identity(fmt.Sprintf("http://%v/introspect-large", oauthServerHost), "access_token", "client-id", "client-secret", authCredMock)
		oauthEvaluator.MaxResponseBytes = int64(len(largeClaims) + 100)
		obj, err := oauthEvaluator.Call(pipelineMock, ctx)
		assert.NilError(t, err)
		claims := obj.(map[string]interface{})
		assert.Assert(t, claims["active"])
	})

	t.Run("exceeds limit causes decode error", func(t *testing.T) {
		oauthEvaluator := NewOAuth2Identity(fmt.Sprintf("http://%v/introspect-large", oauthServerHost), "access_token", "client-id", "client-secret", authCredMock)
		oauthEvaluator.MaxResponseBytes = 50
		_, err := oauthEvaluator.Call(pipelineMock, ctx)
		assert.Assert(t, err != nil)
	})

	t.Run("zero means no limit", func(t *testing.T) {
		oauthEvaluator := NewOAuth2Identity(fmt.Sprintf("http://%v/introspect-large", oauthServerHost), "access_token", "client-id", "client-secret", authCredMock)
		oauthEvaluator.MaxResponseBytes = 0
		obj, err := oauthEvaluator.Call(pipelineMock, ctx)
		assert.NilError(t, err)
		claims := obj.(map[string]interface{})
		assert.Assert(t, claims["active"])
	})
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
