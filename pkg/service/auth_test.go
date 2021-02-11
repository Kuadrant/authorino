package service

import (
	"testing"

	"gotest.tools/assert"

	"github.com/3scale-labs/authorino/pkg/cache"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/gogo/googleapis/google/rpc"
)

func TestDeniedResponse(t *testing.T) {
	c := cache.NewCache()
	service := AuthService{
		Cache: &c,
	}

	var resp *auth.DeniedHttpResponse

	findAuthReason := func(headers []*envoy_core.HeaderValueOption) string {
		for i := range headers {
			header := headers[i].Header
			if header.GetKey() == "x-ext-auth-reason" {
				return header.GetValue()
			}
		}
		return ""
	}

	resp = service.deniedResponse(rpc.FAILED_PRECONDITION, "Invalid request").GetDeniedResponse()
	assert.Equal(t, envoy_type.StatusCode_BadRequest, resp.Status.Code)
	assert.Equal(t, "Invalid request", findAuthReason(resp.GetHeaders()))

	resp = service.deniedResponse(rpc.NOT_FOUND, "Service not found").GetDeniedResponse()
	assert.Equal(t, envoy_type.StatusCode_NotFound, resp.Status.Code)
	assert.Equal(t, "Service not found", findAuthReason(resp.GetHeaders()))

	resp = service.deniedResponse(rpc.PERMISSION_DENIED, "Unauthorized").GetDeniedResponse()
	assert.Equal(t, envoy_type.StatusCode_Forbidden, resp.Status.Code)
	assert.Equal(t, "Unauthorized", findAuthReason(resp.GetHeaders()))
}
