package response

import (
	"context"
	"fmt"
	"github.com/kuadrant/authorino/pkg/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"gotest.tools/assert"

	"github.com/golang/mock/gomock"
)

func TestPlainCallWithStaticValue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ev := Plain{}
	ev.Value = &json.JSONValue{
		Static: "value1",
	}

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john"}}}`)

	obj, err := ev.Call(pipelineMock, context.TODO())

	assert.Equal(t, `value1`, fmt.Sprintf("%v", obj))
	assert.NilError(t, err)
}

func TestPlainCallWithPattern(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ev := Plain{}
	ev.Value = &json.JSONValue{
		Pattern: "auth.identity.username",
	}

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john"}}}`)

	obj, err := ev.Call(pipelineMock, context.TODO())

	assert.Equal(t, `john`, fmt.Sprintf("%v", obj))
	assert.NilError(t, err)
}
