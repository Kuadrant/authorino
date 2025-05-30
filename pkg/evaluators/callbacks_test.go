package evaluators

import (
	"context"
	"fmt"
	"testing"

	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/evaluators/metadata"
	"github.com/kuadrant/authorino/pkg/httptest"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

const testCallbackServerHost string = "127.0.0.1:9010"

func TestCallbacks(t *testing.T) {
	var called bool
	extHttpCallbackServer := httptest.NewHttpServerMock(testCallbackServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/callback": func() httptest.HttpServerMockResponse {
			called = true
			return httptest.NewHttpServerMockResponseFuncPlain("OK")()
		},
	})
	defer extHttpCallbackServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	callbackConfig := CallbackConfig{
		Name: "test",
		HTTP: &metadata.GenericHttp{
			Endpoint:        fmt.Sprintf("http://%s/callback", testCallbackServerHost),
			Method:          "GET",
			AuthCredentials: auth.NewAuthCredential("", "authorization_header"),
		},
	}

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{}`)

	assert.Check(t, !called)
	obj, err := callbackConfig.Call(pipelineMock, context.TODO())
	assert.NilError(t, err)
	assert.Equal(t, fmt.Sprintf("%s", obj), "OK")
	assert.Check(t, called)
}
