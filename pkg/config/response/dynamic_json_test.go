package response

import (
	"context"
	"encoding/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/common"
	"gotest.tools/assert"

	"github.com/golang/mock/gomock"
)

func TestDynamicJSONCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jsonProperties := []common.JSONProperty{
		{Name: "prop1", Value: common.JSONValue{Static: "value1"}},
		{Name: "prop2", Value: common.JSONValue{Pattern: "auth.identity.username"}},
	}

	jsonResponseEvaluator := NewDynamicJSONResponse(jsonProperties)

	type authData struct {
		Auth struct {
			Identity struct {
				Username string `json:"username"`
			} `json:"identity"`
		} `json:"auth"`
	}

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john"}}}`)

	response, err := jsonResponseEvaluator.Call(pipelineMock, context.TODO())
	responseJSON, _ := json.Marshal(response)

	assert.Equal(t, `{"prop1":"value1","prop2":"john"}`, string(responseJSON))
	assert.NilError(t, err)
}
