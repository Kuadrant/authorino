package identity

import (
	"encoding/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	j "github.com/kuadrant/authorino/pkg/json"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

func TestPlainCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"body":"{\"username\":\"john\"}"}}}}`)

	plain := &Plain{Value: &j.JSONValue{Pattern: "context.request.http.body.@fromstr"}, Pattern: "context.request.http.body.@fromstr"}
	id, err := plain.Call(pipelineMock, nil)
	assert.NilError(t, err)
	j, _ := json.Marshal(id)
	assert.Equal(t, string(j), `{"username":"john"}`)
}

func TestPlainCallWithUresolvableObject(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{}`)

	plain := &Plain{Value: &j.JSONValue{Pattern: "context.request.http.body.@fromstr"}, Pattern: "context.request.http.body.@fromstr"}
	id, err := plain.Call(pipelineMock, nil)
	assert.ErrorContains(t, err, "could not retrieve identity object")
	assert.Check(t, id == nil)
}

func TestPlainCallWithInvalidPatttern(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"body":"{\"username\":\"john\"}"}}}}`)

	plain := &Plain{Value: &j.JSONValue{Pattern: "not a valid json path"}, Pattern: "not a valid json path"}
	id, err := plain.Call(pipelineMock, nil)
	assert.ErrorContains(t, err, "could not retrieve identity object")
	assert.Check(t, id == nil)
}

func TestPlainGetIdentifier(t *testing.T) {
	plain := &Plain{Value: &j.JSONValue{Pattern: "context.request.http.body.@fromstr"}, Pattern: "context.request.http.body.@fromstr"}
	assert.Equal(t, plain.GetIdentifier(), "context.request.http.body.@fromstr")
}

func TestPlainGetPlacement(t *testing.T) {
	plain := &Plain{Value: &j.JSONValue{Pattern: "context.request.http.body.@fromstr"}, Pattern: "context.request.http.body.@fromstr"}
	assert.Equal(t, plain.GetPlacement(), "context.request.http.body.@fromstr")
}

func TestPlainGetCredentialsFromAuthReq(t *testing.T) {
	plain := &Plain{}
	s, err := plain.GetCredentialsFromAuthReq(nil)
	assert.Equal(t, s, "")
	assert.ErrorContains(t, err, "not implemented")
}
