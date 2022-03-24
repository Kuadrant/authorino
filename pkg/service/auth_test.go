package service

import (
	"testing"

	"golang.org/x/net/context"
	"gotest.tools/assert"

	"github.com/kuadrant/authorino/pkg/cache"
	mock_cache "github.com/kuadrant/authorino/pkg/cache/mocks"
	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/config"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/golang/mock/gomock"
	"k8s.io/apimachinery/pkg/runtime"
)

func getHeader(headers []*envoy_core.HeaderValueOption, key string) string {
	for _, header := range headers {
		entry := header.Header
		if entry.GetKey() == key {
			return entry.GetValue()
		}
	}
	return ""
}

func TestSuccessResponse(t *testing.T) {
	service := AuthService{
		Cache: cache.NewCache(),
	}

	var resp *envoy_auth.OkHttpResponse
	resp = service.successResponse(common.AuthResult{}, nil).GetOkResponse()
	assert.Equal(t, len(resp.GetHeaders()), 0)

	headers := []map[string]string{{"X-Custom-Header": "some-value"}}
	resp = service.successResponse(common.AuthResult{Headers: headers}, nil).GetOkResponse()
	assert.Equal(t, getHeader(resp.GetHeaders(), "X-Custom-Header"), "some-value")
}

func TestDeniedResponse(t *testing.T) {
	service := AuthService{
		Cache: cache.NewCache(),
	}

	var resp *envoy_auth.DeniedHttpResponse
	var extraHeaders []map[string]string

	resp = service.deniedResponse(common.AuthResult{Code: rpc.FAILED_PRECONDITION, Message: "Invalid request"}).GetDeniedResponse()
	assert.Equal(t, resp.Status.Code, envoy_type.StatusCode_BadRequest)
	assert.Equal(t, getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Invalid request")

	resp = service.deniedResponse(common.AuthResult{Code: rpc.NOT_FOUND, Message: "Service not found"}).GetDeniedResponse()
	assert.Equal(t, resp.Status.Code, envoy_type.StatusCode_NotFound)
	assert.Equal(t, getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Service not found")

	extraHeaders = []map[string]string{{"WWW-Authenticate": "Bearer"}}
	resp = service.deniedResponse(common.AuthResult{Code: rpc.UNAUTHENTICATED, Message: "Unauthenticated", Headers: extraHeaders}).GetDeniedResponse()
	assert.Equal(t, resp.Status.Code, envoy_type.StatusCode_Unauthorized)
	assert.Equal(t, getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Unauthenticated")
	assert.Equal(t, getHeader(resp.GetHeaders(), "WWW-Authenticate"), "Bearer")

	resp = service.deniedResponse(common.AuthResult{Code: rpc.PERMISSION_DENIED, Message: "Unauthorized"}).GetDeniedResponse()
	assert.Equal(t, resp.Status.Code, envoy_type.StatusCode_Forbidden)
	assert.Equal(t, getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Unauthorized")

	extraHeaders = []map[string]string{{"Location": "http://my-app.io/login"}}
	resp = service.deniedResponse(common.AuthResult{Code: rpc.UNAUTHENTICATED, Status: envoy_type.StatusCode_Found, Message: "Please login", Headers: extraHeaders}).GetDeniedResponse()
	assert.Equal(t, resp.Status.Code, envoy_type.StatusCode_Found)
	assert.Equal(t, getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Please login")
	assert.Equal(t, getHeader(resp.GetHeaders(), "Location"), "http://my-app.io/login")
	assert.Equal(t, len(resp.GetHeaders()), 2)
}

func TestAuthConfigLookup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	c := mock_cache.NewMockCache(ctrl)
	service := AuthService{Cache: c}
	authConfig := &config.APIConfig{}

	var resp *envoy_auth.CheckResponse
	var err error

	c.EXPECT().Get("host.com").Return(nil)
	resp, err = service.Check(context.TODO(), &envoy_auth.CheckRequest{Attributes: &envoy_auth.AttributeContext{
		Request: &envoy_auth.AttributeContext_Request{Http: &envoy_auth.AttributeContext_HttpRequest{Host: "host.com"}},
	}})
	assert.Equal(t, int32(resp.GetDeniedResponse().Status.Code), int32(404))
	assert.NilError(t, err)

	c.EXPECT().Get("host.com").Return(authConfig)
	resp, err = service.Check(context.TODO(), &envoy_auth.CheckRequest{Attributes: &envoy_auth.AttributeContext{
		Request: &envoy_auth.AttributeContext_Request{Http: &envoy_auth.AttributeContext_HttpRequest{Host: "host.com"}},
	}})
	assert.Equal(t, int32(resp.GetDeniedResponse().Status.Code), int32(401))
	assert.NilError(t, err)

	c.EXPECT().Get("host-overwrite").Return(nil)
	resp, err = service.Check(context.TODO(), &envoy_auth.CheckRequest{Attributes: &envoy_auth.AttributeContext{
		Request:           &envoy_auth.AttributeContext_Request{Http: &envoy_auth.AttributeContext_HttpRequest{Host: "actual-host.com"}},
		ContextExtensions: map[string]string{"host": "host-overwrite"},
	}})
	assert.Equal(t, int32(resp.GetDeniedResponse().Status.Code), int32(404))
	assert.NilError(t, err)

	c.EXPECT().Get("host-overwrite").Return(authConfig)
	resp, err = service.Check(context.TODO(), &envoy_auth.CheckRequest{Attributes: &envoy_auth.AttributeContext{
		Request:           &envoy_auth.AttributeContext_Request{Http: &envoy_auth.AttributeContext_HttpRequest{Host: "actual-host.com"}},
		ContextExtensions: map[string]string{"host": "host-overwrite"},
	}})
	assert.Equal(t, int32(resp.GetDeniedResponse().Status.Code), int32(401))
	assert.NilError(t, err)
}

func TestBuildDynamicEnvoyMetadata(t *testing.T) {
	data := map[string]interface{}{
		"foo": runtime.RawExtension{
			Raw: []byte(`"value"`),
		},
	}

	_, err := buildEnvoyDynamicMetadata(data)

	assert.NilError(t, err)
}
