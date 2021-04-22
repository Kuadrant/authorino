package service

import (
	"encoding/json"

	"golang.org/x/net/context"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/kuadrant/authorino/pkg/cache"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
)

const (
	X_EXT_AUTH_REASON_HEADER = "X-Ext-Auth-Reason"

	RESPONSE_MESSAGE_INVALID_REQUEST   = "Invalid request"
	RESPONSE_MESSAGE_SERVICE_NOT_FOUND = "Service not found"
)

var (
	authServiceLog = ctrl.Log.WithName("Authorino").WithName("AuthService")

	statusCodeMapping = map[rpc.Code]envoy_type.StatusCode{
		rpc.FAILED_PRECONDITION: envoy_type.StatusCode_BadRequest,
		rpc.NOT_FOUND:           envoy_type.StatusCode_NotFound,
		rpc.UNAUTHENTICATED:     envoy_type.StatusCode_Unauthorized,
		rpc.PERMISSION_DENIED:   envoy_type.StatusCode_Forbidden,
	}
)

// AuthService is the server API for the authorization service.
type AuthService struct {
	Cache *cache.Cache
}

// Check performs authorization check based on the attributes associated with the incoming request,
// and returns status `OK` or not `OK`.
func (self *AuthService) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	reqJSON, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return self.deniedResponse(AuthResult{Code: rpc.FAILED_PRECONDITION, Message: RESPONSE_MESSAGE_INVALID_REQUEST}), nil
	}
	authServiceLog.Info("Check()", "reqJSON", string(reqJSON))

	// service config
	host := req.Attributes.Request.Http.Host
	// TODO: Get this from the cache.
	config := self.Cache.List()

	apiConfig, apiConfigOK := config[host]
	if !apiConfigOK {
		return self.deniedResponse(AuthResult{Code: rpc.NOT_FOUND, Message: RESPONSE_MESSAGE_SERVICE_NOT_FOUND}), nil
	}

	pipeline := NewAuthPipeline(ctx, req, apiConfig)

	if result := pipeline.Evaluate(); result.Success() {
		return self.successResponse(result.Headers), nil
	} else {
		return self.deniedResponse(result), nil
	}
}

func (self *AuthService) successResponse(headers []map[string]string) *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{
				Headers: buildResponseHeaders(headers),
			},
		},
	}
}

func (self *AuthService) deniedResponse(authResult AuthResult) *envoy_auth.CheckResponse {
	code := authResult.Code
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(code),
		},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: statusCodeMapping[code],
				},
				Headers: buildResponseHeadersWithReason(authResult.Message, authResult.Headers),
			},
		},
	}
}

func buildResponseHeaders(headers []map[string]string) []*envoy_core.HeaderValueOption {
	responseHeaders := make([]*envoy_core.HeaderValueOption, 0)

	for _, headerMap := range headers {
		for key, value := range headerMap {
			responseHeaders = append(responseHeaders, &envoy_core.HeaderValueOption{
				Header: &envoy_core.HeaderValue{
					Key:   key,
					Value: value,
				},
			})
		}
	}

	return responseHeaders
}

func buildResponseHeadersWithReason(authReason string, extraHeaders []map[string]string) []*envoy_core.HeaderValueOption {
	var headers []map[string]string

	if extraHeaders != nil {
		headers = extraHeaders
	} else {
		headers = make([]map[string]string, 0)
	}

	headers = append(headers, map[string]string{X_EXT_AUTH_REASON_HEADER: authReason})

	return buildResponseHeaders(headers)
}
