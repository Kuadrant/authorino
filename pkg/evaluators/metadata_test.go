package evaluators

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/evaluators/metadata"
	"github.com/kuadrant/authorino/pkg/httptest"
	"github.com/kuadrant/authorino/pkg/json"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

const testMetadataServerHost string = "127.0.0.1:9008"

func TestMetadataCaching(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": httptest.NewHttpServerMockResponseFuncJSON(`{"foo":"bar"}`),
	})
	defer extHttpMetadataServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)

	var metadataConfig MetadataConfig
	var metadataObject interface{}
	var metadataObjectJSON map[string]interface{}
	var err error

	evaluator := &metadata.GenericHttp{
		Endpoint:        fmt.Sprintf("http://%s/metadata", testMetadataServerHost),
		Method:          "GET",
		AuthCredentials: auth.NewAuthCredential("", "authorization_header"),
	}

	// Without caching of metadata
	metadataConfig = MetadataConfig{
		Name:        "test",
		GenericHTTP: evaluator,
	}

	pipelineMock.EXPECT().GetAuthorizationJSON().Times(2).Return(`{}`) // both times by the Generic HTTP metadata evaluator

	metadataObject, err = metadataConfig.Call(pipelineMock, context.TODO())
	metadataObjectJSON = metadataObject.(map[string]interface{})
	assert.Equal(t, metadataObjectJSON["foo"], "bar")
	assert.NilError(t, err)

	metadataObject, err = metadataConfig.Call(pipelineMock, context.TODO())
	metadataObjectJSON = metadataObject.(map[string]interface{})
	assert.Equal(t, metadataObjectJSON["foo"], "bar")
	assert.NilError(t, err)

	// With caching of metadata
	cache := NewEvaluatorCache(&json.JSONValue{Static: "x"}, 2) // 2 seconds ttl
	metadataConfig.Cache = cache
	defer metadataConfig.Clean(context.TODO())

	pipelineMock.EXPECT().GetAuthorizationJSON().Times(3).Return(`{}`) // twice at the upper level to resolve the cache key; another time by the Generic HTTP metadata evaluator

	metadataObject, err = metadataConfig.Call(pipelineMock, context.TODO())
	metadataObjectJSON = metadataObject.(map[string]interface{})
	assert.Equal(t, metadataObjectJSON["foo"], "bar")
	assert.NilError(t, err)

	metadataObject, err = metadataConfig.Call(pipelineMock, context.TODO())
	metadataObjectJSON = metadataObject.(map[string]interface{})
	assert.Equal(t, metadataObjectJSON["foo"], "bar")
	assert.NilError(t, err)

	time.Sleep(5 * time.Second)

	pipelineMock.EXPECT().GetAuthorizationJSON().Times(2).Return(`{}`) // once at the upper level to resolve the cache key; another time by the Generic HTTP metadata evaluator

	metadataObject, err = metadataConfig.Call(pipelineMock, context.TODO())
	metadataObjectJSON = metadataObject.(map[string]interface{})
	assert.Equal(t, metadataObjectJSON["foo"], "bar")
	assert.NilError(t, err)
}
