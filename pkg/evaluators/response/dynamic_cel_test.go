package response

import (
	"context"
	"encoding/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"gotest.tools/assert"

	"github.com/golang/mock/gomock"
)

func TestDynamicCELCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	celResponseEvaluator, _ := NewDynamicCelResponse(`{"prop1": "value1", "prop2": auth.identity.username}`)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john","evil": false}}}`)

	response, err := celResponseEvaluator.Call(pipelineMock, context.TODO())
	assert.NilError(t, err)

	// We need to parse this response: https://protobuf.dev/reference/go/faq/#unstable-json
	result := struct {
		Prop1 string `json:"prop1"`
		Prop2 string `json:"prop2"`
	}{}
	assert.NilError(t, json.Unmarshal([]byte(response.(string)), &result))

	assert.Equal(t, result.Prop1, "value1")
	assert.Equal(t, result.Prop2, "john")
}
