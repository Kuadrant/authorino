package service

import (
	"encoding/json"
	"log"

	"github.com/3scale-labs/authorino/pkg/cache"
	"golang.org/x/net/context"

	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/gogo/googleapis/google/rpc"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
)

// AuthService is the server API for the authorization service.
type AuthService struct {
	Cache *cache.Cache
}

// Check performs authorization check based on the attributes associated with the incoming request,
// and returns status `OK` or not `OK`.
func (self *AuthService) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	reqJSON, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return self.deniedResponse(rpc.FAILED_PRECONDITION, "Invalid request"), nil
	}
	log.Println("[AuthService] Check()\n", string(reqJSON))

	// service config
	host := req.Attributes.Request.Http.Host
	// TODO: Get this from the cache.
	config := self.Cache.List()

	apiConfig, apiConfigOK := config[host]
	if !apiConfigOK || !apiConfig.Enabled {
		return self.deniedResponse(rpc.NOT_FOUND, "Service not found"), nil
	}

	authContext := AuthContext{
		ParentContext: &ctx,
		Request:       req,
		API:           &apiConfig,
	}

	err = authContext.Evaluate()
	if err != nil {
		return self.deniedResponse(rpc.PERMISSION_DENIED, err.Error()), nil
	}

	return self.successResponse(), nil
}

func (self *AuthService) successResponse() *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{},
		},
	}
}

func (self *AuthService) deniedResponse(code rpc.Code, message string) *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(code),
		},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Unauthorized,
				},
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "x-ext-auth-reason",
							Value: "forbidden",
						},
					},
				},
				Body: message,
			},
		},
	}
}
