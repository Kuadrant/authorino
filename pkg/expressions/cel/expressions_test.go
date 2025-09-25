package cel

import (
	"testing"

	"gotest.tools/assert"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"

	"go.uber.org/mock/gomock"
)

func TestPredicate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	_, err := NewPredicate(`auth`)
	assert.ErrorContains(t, err, "wanted bool output type")

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)

	predicate, err := NewPredicate(`false == true`)
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

	predicate, err = NewPredicate(`request.http.method == "GET"`)
	assert.NilError(t, err)

	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"request":{"http": {"method": "GET"}}}`)
	response, err = predicate.Matches(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, response, true)

	predicate, err = NewPredicate(`"GET".lowerAscii() == "get"`)
	assert.NilError(t, err)
	response, err = predicate.Matches("{}")
	assert.NilError(t, err)
	assert.Equal(t, response, true)
}

func TestExpression(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john","evil": false}}}`)

	expression, err := NewExpression(`auth.identity.evil == false`)
	assert.NilError(t, err)

	v, err := expression.ResolveFor(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, v, true)

	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"auth":{"identity":{"username":"john","evil": false}}}`)
	expression, err = NewExpression(`auth.?nonexistent.orValue("none")`)
	assert.NilError(t, err)

	v, err = expression.ResolveFor(pipelineMock.GetAuthorizationJSON())
	assert.NilError(t, err)
	assert.Equal(t, v, "none")
}
