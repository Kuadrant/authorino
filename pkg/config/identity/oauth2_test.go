package identity

import (
	"context"
	"fmt"
	"testing"

	. "github.com/kuadrant/authorino/pkg/common/auth_credentials/mocks"
	. "github.com/kuadrant/authorino/pkg/common/mocks"

	. "github.com/golang/mock/gomock"

	"gotest.tools/assert"
)

const oauthServerHost = "127.0.0.1:9004"

func TestOAuth2Call(t *testing.T) {
	authServer := NewHttpServerMock(oauthServerHost, map[string]HttpServerMockResponses{
		"/introspect-active":   {Status: 200, Body: `{ "active": true }`},
		"/introspect-inactive": {Status: 200, Body: `{ "active": false }`},
	})
	defer authServer.Close()

	ctrl := NewController(t)
	defer ctrl.Finish()

	authCredMock := NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(Any()).Return("oauth-opaque-token", nil).AnyTimes()

	pipelineMock := NewMockAuthPipeline(ctrl)
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
		obj, err := oauthEvaluator.Call(pipelineMock, ctx)
		assert.NilError(t, err)
		claims := obj.(map[string]interface{})
		assert.Assert(t, claims["active"] == false)
	}
}

func TestDefaultTokenTypeHint(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	authCredMock := NewMockAuthCredentials(ctrl)

	{
		oauthEvaluator := NewOAuth2Identity("http://server.example.com", "", "client-id", "client-secret", authCredMock)
		assert.Equal(t, "access_token", oauthEvaluator.TokenTypeHint)
	}

	{
		oauthEvaluator := NewOAuth2Identity("http://server.example.com", "refresh_token", "client-id", "client-secret", authCredMock)
		assert.Equal(t, "refresh_token", oauthEvaluator.TokenTypeHint)
	}
}
