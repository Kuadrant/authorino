package cel

import (
	"testing"

	"github.com/golang/mock/gomock"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"gotest.tools/assert"

	authorinojson "github.com/kuadrant/authorino/pkg/json"
)

func TestPredicate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	predicate, err := NewPredicate(`auth`)
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

func TestTimestamp(t *testing.T) {
	expression, _ := NewExpression(`request.time`)

	val, err := expression.ResolveFor(`{"request":{"time":{"seconds":1732721739,"nanos":123456}}}`)
	s, _ := authorinojson.StringifyJSON(val)
	assert.NilError(t, err)
	assert.Equal(t, s, "2024-11-27T15:35:39.000123456Z")

	val, err = expression.ResolveFor(`{"request":{"time":"2024-11-27T15:35:39Z"}}`)
	s, _ = authorinojson.StringifyJSON(val)
	assert.NilError(t, err)
	assert.Equal(t, s, "2024-11-27T15:35:39Z")

	val, err = expression.ResolveFor(`{"request":{"time":{"custom":"11 Nov 2024 03:35:39pm UTC"}}}`)
	s, _ = authorinojson.StringifyJSON(val)
	assert.NilError(t, err)
	assert.Equal(t, s, `{"custom":"11 Nov 2024 03:35:39pm UTC"}`)
}
