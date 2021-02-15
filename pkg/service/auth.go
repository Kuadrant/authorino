package service

import (
	"encoding/json"

	"golang.org/x/net/context"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/3scale-labs/authorino/pkg/cache"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
)

var (
	authServiceLog = ctrl.Log.WithName("Authorino").WithName("AuthService")

	statusCodeMapping = map[rpc.Code]envoy_type.StatusCode{
		rpc.FAILED_PRECONDITION: envoy_type.StatusCode_BadRequest,
		rpc.NOT_FOUND:           envoy_type.StatusCode_NotFound,
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
		return self.deniedResponse(rpc.FAILED_PRECONDITION, "Invalid request"), nil
	}
	authServiceLog.Info("Check()", "reqJSON", string(reqJSON))

	// service config
	host := req.Attributes.Request.Http.Host
	// TODO: Get this from the cache.
	config := self.Cache.List()

	apiConfig, apiConfigOK := config[host]
	if !apiConfigOK || !apiConfig.Enabled {
		return self.deniedResponse(rpc.NOT_FOUND, "Service not found"), nil
	}

	authContext := NewAuthContext(ctx, req, apiConfig)

	err = authContext.Evaluate()
	if err != nil {
		return self.deniedResponse(rpc.PERMISSION_DENIED, err.Error()), nil
	}

	return self.successResponse(), nil
}

func (self *AuthService) successResponse() *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{},
		},
	}
}

func (self *AuthService) deniedResponse(code rpc.Code, message string) *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(code),
		},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: statusCodeMapping[code],
				},
				Headers: []*envoy_core.HeaderValueOption{
					{
						Header: &envoy_core.HeaderValue{
							Key:   "x-ext-auth-reason",
							Value: message,
						},
					},
				},
			},
		},
	}
}
