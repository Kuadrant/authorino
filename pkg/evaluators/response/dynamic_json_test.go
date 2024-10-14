package response

import (
	"context"
	gojson "encoding/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/json"
	"gotest.tools/assert"

	"github.com/golang/mock/gomock"
)

func TestDynamicJSONCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	jsonProperties := []json.JSONProperty{
		{Name: "prop1", Value: json.JSONValue{Static: "value1"}},
		{Name: "prop2", Value: json.JSONValue{Pattern: "auth.identity.username"}},
		{Name: "prop2", Value: json.JSONValue{Pattern: "auth.identity.username"}},
		{Name: "prop2", Value: json.JSONValue{Pattern: "auth.identity.username"}},
		{Name: "prop2", Value: json.JSONValue{Pattern: "auth.identity.username"}},
		{Name: "prop2", Value: json.JSONValue{Pattern: "auth.identity.username"}},
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
	responseJSON, _ := gojson.Marshal(response)

	assert.Equal(t, `{"prop1":"value1","prop2":"john"}`, string(responseJSON))
	assert.NilError(t, err)
}
