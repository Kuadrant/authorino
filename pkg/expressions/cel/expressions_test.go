package cel

import (
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"gotest.tools/assert"

	"github.com/golang/mock/gomock"
)

func TestPredicate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	predicate, err := NewPredicate(`context`)
	assert.ErrorContains(t, err, "wanted bool output type")

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)

	predicate, err = NewPredicate(`false == true`)
	assert.NilError(t, err)

	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john","evil": false}}}`)
	response, err := predicate.Matches(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, response, false)

	predicate, err = NewPredicate(`auth.identity.evil == false`)
	assert.NilError(t, err)

	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john","evil": false}}}`)
	response, err = predicate.Matches(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, response, true)

	predicate, err = NewPredicate(`context.request.http.method == "GET"`)
	assert.NilError(t, err)

	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http": {"method": "GET"}}}}`)
	response, err = predicate.Matches(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, response, true)
}
