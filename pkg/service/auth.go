package service

import (
	"strings"

	"golang.org/x/net/context"

	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/config"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	X_EXT_AUTH_REASON_HEADER = "X-Ext-Auth-Reason"

	RESPONSE_MESSAGE_INVALID_REQUEST   = "Invalid request"
	RESPONSE_MESSAGE_SERVICE_NOT_FOUND = "Service not found"
)

var (
	statusCodeMapping = map[rpc.Code]envoy_type.StatusCode{
		rpc.FAILED_PRECONDITION: envoy_type.StatusCode_BadRequest,
		rpc.NOT_FOUND:           envoy_type.StatusCode_NotFound,
		rpc.UNAUTHENTICATED:     envoy_type.StatusCode_Unauthorized,
		rpc.PERMISSION_DENIED:   envoy_type.StatusCode_Forbidden,
	}
)

// AuthService is the server API for the authorization service.
type AuthService struct {
	Cache cache.Cache
}

// Check performs authorization check based on the attributes associated with the incoming request,
// and returns status `OK` or not `OK`.
func (a *AuthService) Check(parentContext context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	requestLogger := log.WithName("service").WithName("auth").WithValues("request id", req.Attributes.Request.Http.GetId())
	ctx := log.IntoContext(parentContext, requestLogger)

	a.logAuthRequest(req, ctx)

	requestData := req.Attributes.Request.Http

	// service config
	host := requestData.Host
	var apiConfig *config.APIConfig
	apiConfig = a.Cache.Get(host)
	// If the host is not found, but contains a port, remove the port part and retry.
	if apiConfig == nil && strings.Contains(host, ":") {
		splitHost := strings.Split(host, ":")
		apiConfig = a.Cache.Get(splitHost[0])
	}
	// If we couldn't find the APIConfig in the config, we return and deny.
	if apiConfig == nil {
		result := common.AuthResult{Code: rpc.NOT_FOUND, Message: RESPONSE_MESSAGE_SERVICE_NOT_FOUND}
		a.logAuthResult(result, ctx)
		return a.deniedResponse(result), nil
	}

	pipeline := NewAuthPipeline(log.IntoContext(ctx, requestLogger), req, *apiConfig)
	result := pipeline.Evaluate()

	a.logAuthResult(result, ctx)

	if result.Success() {
		return a.successResponse(result, ctx), nil
	} else {
		return a.deniedResponse(result), nil
	}
}

func (a *AuthService) successResponse(authResult common.AuthResult, ctx context.Context) *envoy_auth.CheckResponse {
	dynamicMetadata, err := structpb.NewStruct(authResult.Metadata)
	if err != nil {
		log.FromContext(ctx).V(1).Error(err, "failed to create dynamic metadata", "object", authResult.Metadata)
	}
	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{
				Headers: buildResponseHeaders(authResult.Headers),
			},
		},
		DynamicMetadata: dynamicMetadata,
	}
}

func (a *AuthService) deniedResponse(authResult common.AuthResult) *envoy_auth.CheckResponse {
	code := authResult.Code

	httpCode := authResult.Status
	if httpCode == 0 {
		httpCode = statusCodeMapping[code]
	}

	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(code),
		},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: httpCode,
				},
				Headers: buildResponseHeadersWithReason(authResult.Message, authResult.Headers),
			},
		},
	}
}

func (a *AuthService) logAuthRequest(req *envoy_auth.CheckRequest, ctx context.Context) {
	logger := log.FromContext(ctx)
	reqAttrs := req.Attributes
	httpAttrs := reqAttrs.Request.Http

	reducedReq := &struct {
		Source      *envoy_auth.AttributeContext_Peer `json:"source,omitempty"`
		Destination *envoy_auth.AttributeContext_Peer `json:"destination,omitempty"`
		Request     interface{}                       `json:"request,omitempty"`
	}{
		Source:      reqAttrs.Source,
		Destination: reqAttrs.Destination,
		Request: struct {
			Http interface{} `json:"http,omitempty"`
		}{
			Http: struct {
				Id     string `json:"id,omitempty"`
				Method string `json:"method,omitempty"`
				Path   string `json:"path,omitempty"`
				Host   string `json:"host,omitempty"`
				Scheme string `json:"scheme,omitempty"`
			}{
				Id:     httpAttrs.Id,
				Method: httpAttrs.Method,
				Path:   strings.Split(httpAttrs.Path, "?")[0],
				Host:   httpAttrs.Host,
				Scheme: httpAttrs.Scheme,
			},
		},
	}
	logger.Info("incoming authorization request", "object", reducedReq) // info

	if logger.V(1).Enabled() {
		logger.V(1).Info("incoming authorization request", "object", &reqAttrs) // debug
	}
}

func (a *AuthService) logAuthResult(result common.AuthResult, ctx context.Context) {
	logger := log.FromContext(ctx)
	success := result.Success()
	baseLogData := []interface{}{"authorized", success, "response", result.Code.String()}

	logData := baseLogData
	if !success {
		reducedResult := common.AuthResult{
			Code:    result.Code,
			Status:  result.Status,
			Message: result.Message,
		}
		logData = append(logData, "object", reducedResult)
	}
	logger.Info("outgoing authorization response", logData...) // info

	if logger.V(1).Enabled() {
		if !success {
			baseLogData = append(baseLogData, "object", result)
		}
		logger.V(1).Info("outgoing authorization response", baseLogData...) // debug
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
