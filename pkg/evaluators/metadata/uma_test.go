package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/httptest"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

type UMATest struct{}

const (
	umaServerHost = "127.0.0.1:9003"
)

var (
	umaIssuer          = fmt.Sprintf("http://%v/uma", umaServerHost)
	umaWellKnownConfig = fmt.Sprintf(`{
		"issuer": "%v",
		"token_endpoint": "%v/pat",
		"resource_registration_endpoint": "%v/resource_set"
	}`, umaIssuer, umaIssuer, umaIssuer)
)

func TestNewUMAMetadata(t *testing.T) {
	httpServer := httptest.NewHttpServerMock(umaServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/uma/.well-known/uma2-configuration": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: umaWellKnownConfig}
		},
	})
	defer httpServer.Close()

	uma, err := NewUMAMetadata(umaIssuer, "client-id", "client-secret")

	assert.NilError(t, err)
	assert.Equal(t, umaIssuer, uma.provider.issuer)
}

func TestUMAMetadataFailToDecodeConfig(t *testing.T) {
	httpServer := httptest.NewHttpServerMock(umaServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/uma/.well-known/uma2-configuration": func() httptest.HttpServerMockResponse { return httptest.HttpServerMockResponse{Status: 500} },
	})
	defer httpServer.Close()

	uma, err := NewUMAMetadata(umaIssuer, "client-id", "client-secret")

	assert.ErrorContains(t, err, "failed to decode uma provider discovery object")
	assert.Check(t, uma == nil)
}

func TestUMACall(t *testing.T) {
	jsonResponse := func(body string) httptest.HttpServerMockResponseFunc {
		return func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Headers: map[string]string{"Context-Type": "application/json"}, Body: body}
		}
	}

	resourceData := `{"_id":"44f93c94-a8d0-4b33-8188-8173e86844d2","name":"some-resource","uris":["/someresource"]}`
	httpServer := httptest.NewHttpServerMock(umaServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/uma/.well-known/uma2-configuration":                    jsonResponse(umaWellKnownConfig),
		"/uma/pat":                                               jsonResponse(`{"some-pat-claim": "some-value"}`),
		"/uma/resource_set?uri=/someresource":                    jsonResponse(`["44f93c94-a8d0-4b33-8188-8173e86844d2"]`),
		"/uma/resource_set/44f93c94-a8d0-4b33-8188-8173e86844d2": jsonResponse(resourceData),
	})
	defer httpServer.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	request := &envoy_auth.AttributeContext_HttpRequest{Path: "/someresource"}
	pipelineMock.EXPECT().GetHttp().Return(request)

	uma, _ := NewUMAMetadata(umaIssuer, "client-id", "client-secret")

	obj, err := uma.Call(pipelineMock, context.TODO())

	data, _ := json.Marshal(obj)
	assert.Equal(t, "["+resourceData+"]", string(data))
	assert.NilError(t, err)
}
