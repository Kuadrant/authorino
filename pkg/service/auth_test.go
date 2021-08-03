package service

import (
	"testing"

	"gotest.tools/assert"

	"github.com/kuadrant/authorino/pkg/cache"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
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

	resp = service.successResponse(AuthResult{}).GetOkResponse()
	assert.Equal(t, 0, len(resp.GetHeaders()))

	headers := []map[string]string{{"X-Custom-Header": "some-value"}}
	resp = service.successResponse(AuthResult{Headers: headers}).GetOkResponse()
	assert.Equal(t, "some-value", getHeader(resp.GetHeaders(), "X-Custom-Header"))
}

func TestDeniedResponse(t *testing.T) {
	service := AuthService{
		Cache: cache.NewCache(),
	}

	var resp *envoy_auth.DeniedHttpResponse

	resp = service.deniedResponse(AuthResult{Code: rpc.FAILED_PRECONDITION, Message: "Invalid request"}).GetDeniedResponse()
	assert.Equal(t, envoy_type.StatusCode_BadRequest, resp.Status.Code)
	assert.Equal(t, "Invalid request", getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER))

	resp = service.deniedResponse(AuthResult{Code: rpc.NOT_FOUND, Message: "Service not found"}).GetDeniedResponse()
	assert.Equal(t, envoy_type.StatusCode_NotFound, resp.Status.Code)
	assert.Equal(t, "Service not found", getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER))

	extraHeaders := []map[string]string{{"WWW-Authenticate": "Bearer"}}
	resp = service.deniedResponse(AuthResult{Code: rpc.UNAUTHENTICATED, Message: "Unauthenticated", Headers: extraHeaders}).GetDeniedResponse()
	assert.Equal(t, envoy_type.StatusCode_Unauthorized, resp.Status.Code)
	assert.Equal(t, "Unauthenticated", getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER))
	assert.Equal(t, "Bearer", getHeader(resp.GetHeaders(), "WWW-Authenticate"))

	resp = service.deniedResponse(AuthResult{Code: rpc.PERMISSION_DENIED, Message: "Unauthorized"}).GetDeniedResponse()
	assert.Equal(t, envoy_type.StatusCode_Forbidden, resp.Status.Code)
	assert.Equal(t, "Unauthorized", getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER))
}
