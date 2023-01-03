package evaluators

import (
	"context"
	"fmt"
	"testing"

	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/evaluators/metadata"
	"github.com/kuadrant/authorino/pkg/httptest"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

const testNotifyServerHost string = "127.0.0.1:9010"

func TestNotify(t *testing.T) {
	var notified bool
	extHttpNotifyServer := httptest.NewHttpServerMock(testNotifyServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/notify": func() httptest.HttpServerMockResponse {
			notified = true
			return httptest.NewHttpServerMockResponseFuncPlain("OK")()
		},
	})
	defer extHttpNotifyServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	notifyConfig := NotifyConfig{
		Name: "test",
		HTTP: &metadata.GenericHttp{
			Endpoint:        fmt.Sprintf("http://%s/notify", testNotifyServerHost),
			Method:          "GET",
			AuthCredentials: auth.NewAuthCredential("", "authorization_header"),
		},
	}

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{}`)

	assert.Check(t, !notified)
	obj, err := notifyConfig.Call(pipelineMock, context.TODO())
	assert.NilError(t, err)
	assert.Equal(t, fmt.Sprintf("%s", obj), "OK")
	assert.Check(t, notified)
}
