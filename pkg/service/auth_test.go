package service

import (
	"testing"

	"gotest.tools/assert"

	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/common"

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
