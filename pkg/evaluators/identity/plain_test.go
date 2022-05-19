package identity

import (
	"context"
	"encoding/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

func TestPlainCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"body":"{\"username\":\"john\"}"}}}}`)

	plain := &Plain{Pattern: "context.request.http.body.@fromstr"}
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

	plain := &Plain{Pattern: "context.request.http.body.@fromstr"}
	id, err := plain.Call(pipelineMock, nil)
	assert.ErrorContains(t, err, "Could not retrieve identity object")
	assert.Check(t, id == nil)
}

func TestPlainCallWithInvalidPatttern(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"body":"{\"username\":\"john\"}"}}}}`)

	plain := &Plain{Pattern: "not a valid json path"}
	id, err := plain.Call(pipelineMock, nil)
	assert.ErrorContains(t, err, "Could not retrieve identity object")
	assert.Check(t, id == nil)
}

func TestPlainGetCredentailsKeySelector(t *testing.T) {
	plain := &Plain{Pattern: "context.request.http.body.@fromstr"}
	assert.Equal(t, plain.GetCredentialsKeySelector(), "context.request.http.body.@fromstr")
}

func TestPlainGetCredentailsIn(t *testing.T) {
	plain := &Plain{Pattern: "context.request.http.body.@fromstr"}
	assert.Equal(t, plain.GetCredentialsIn(), "context.request.http.body.@fromstr")
}

func TestPlainGetCredentialsFromReq(t *testing.T) {
	plain := &Plain{}
	s, err := plain.GetCredentialsFromReq(nil)
	assert.Equal(t, s, "")
	assert.ErrorContains(t, err, "not implemented")
}

func TestPlainBuildRequestWithCredentials(t *testing.T) {
	plain := &Plain{}
	r, err := plain.BuildRequestWithCredentials(context.TODO(), "", "", "", nil)
	assert.Check(t, r == nil)
	assert.ErrorContains(t, err, "not implemented")
}
