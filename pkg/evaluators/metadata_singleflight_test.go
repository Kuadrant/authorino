package evaluators

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/evaluators/metadata"
	"github.com/kuadrant/authorino/pkg/httptest"
	"github.com/kuadrant/authorino/pkg/json"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

const singleflightTestHost = "127.0.0.1:9018"

func TestMetadataSingleflight_ConcurrentMissesCoalesce(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewHttpServerMock(singleflightTestHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": func() httptest.HttpServerMockResponse {
			callCount.Add(1)
			return httptest.HttpServerMockResponse{
				Status:  200,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    `{"valid":true}`,
			}
		},
	})
	defer server.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	evaluator := &metadata.GenericHttp{
		Endpoint:        fmt.Sprintf("http://%s/metadata", singleflightTestHost),
		Method:          "GET",
		AuthCredentials: auth.NewAuthCredential("", "authorization_header"),
	}

	cache := NewEvaluatorCache(&json.JSONValue{Static: "test-key"}, 60)

	config := MetadataConfig{
		Name:        "test-metadata",
		Cache:       cache,
		GenericHTTP: evaluator,
	}
	defer config.Clean(context.Background())

	const concurrency = 50
	var wg sync.WaitGroup
	wg.Add(concurrency)
	errors := make([]error, concurrency)
	results := make([]interface{}, concurrency)

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().AnyTimes().Return(`{}`)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx], errors[idx] = config.Call(pipelineMock, context.Background())
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		assert.NilError(t, err, "goroutine %d returned error", i)
	}

	for i, res := range results {
		assert.Assert(t, res != nil, "goroutine %d returned nil result", i)
	}

	actual := callCount.Load()
	assert.Assert(t, actual == 1, "expected 1 HTTP call, got %d (singleflight did not coalesce)", actual)
}

func TestMetadataSingleflight_DifferentKeysDoNotCoalesce(t *testing.T) {
	var callCount atomic.Int32

	const testHost2 = "127.0.0.1:9019"
	server := httptest.NewHttpServerMock(testHost2, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": func() httptest.HttpServerMockResponse {
			callCount.Add(1)
			return httptest.HttpServerMockResponse{
				Status:  200,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    `{"valid":true}`,
			}
		},
	})
	defer server.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	evaluator := &metadata.GenericHttp{
		Endpoint:        fmt.Sprintf("http://%s/metadata", testHost2),
		Method:          "GET",
		AuthCredentials: auth.NewAuthCredential("", "authorization_header"),
	}

	cacheA := NewEvaluatorCache(&json.JSONValue{Static: "key-A"}, 60)
	cacheB := NewEvaluatorCache(&json.JSONValue{Static: "key-B"}, 60)

	configA := MetadataConfig{
		Name:        "test-metadata",
		Cache:       cacheA,
		GenericHTTP: evaluator,
	}
	configB := MetadataConfig{
		Name:        "test-metadata",
		Cache:       cacheB,
		GenericHTTP: evaluator,
	}
	defer configA.Clean(context.Background())
	defer configB.Clean(context.Background())

	pipelineMockA := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMockA.EXPECT().GetAuthorizationJSON().AnyTimes().Return(`{}`)
	pipelineMockB := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMockB.EXPECT().GetAuthorizationJSON().AnyTimes().Return(`{}`)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		configA.Call(pipelineMockA, context.Background())
	}()
	go func() {
		defer wg.Done()
		configB.Call(pipelineMockB, context.Background())
	}()

	wg.Wait()

	actual := callCount.Load()
	assert.Assert(t, actual == 2, "expected 2 HTTP calls (one per distinct cache), got %d", actual)
}

func TestMetadataSingleflight_CachePopulatedAfterCoalescedCall(t *testing.T) {
	var callCount atomic.Int32

	const testHost3 = "127.0.0.1:9020"
	server := httptest.NewHttpServerMock(testHost3, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": func() httptest.HttpServerMockResponse {
			callCount.Add(1)
			return httptest.HttpServerMockResponse{
				Status:  200,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    `{"cached":"value"}`,
			}
		},
	})
	defer server.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	evaluator := &metadata.GenericHttp{
		Endpoint:        fmt.Sprintf("http://%s/metadata", testHost3),
		Method:          "GET",
		AuthCredentials: auth.NewAuthCredential("", "authorization_header"),
	}

	cache := NewEvaluatorCache(&json.JSONValue{Static: "populate-key"}, 60)

	config := MetadataConfig{
		Name:        "test-metadata-populate",
		Cache:       cache,
		GenericHTTP: evaluator,
	}
	defer config.Clean(context.Background())

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().AnyTimes().Return(`{}`)

	_, err := config.Call(pipelineMock, context.Background())
	assert.NilError(t, err)
	assert.Assert(t, callCount.Load() == 1, "first call should invoke evaluator")

	_, err = config.Call(pipelineMock, context.Background())
	assert.NilError(t, err)
	assert.Assert(t, callCount.Load() == 1, "second call should hit cache, not invoke evaluator again")
}
