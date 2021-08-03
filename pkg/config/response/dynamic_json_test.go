package response

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kuadrant/authorino/pkg/common"
	mock_common "github.com/kuadrant/authorino/pkg/common/mocks"
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

	var data authData
	_ = json.Unmarshal([]byte(`{"auth":{"identity":{"username":"john"}}}`), &data)

	pipelineMock := mock_common.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetPostAuthorizationData().Return(data)

	response, err := jsonResponseEvaluator.Call(pipelineMock, context.TODO())
	responseJSON, _ := json.Marshal(response)

	assert.Equal(t, `{"prop1":"value1","prop2":"john"}`, string(responseJSON))
	assert.NilError(t, err)
}
