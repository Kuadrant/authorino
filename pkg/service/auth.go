package service

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	gocontext "golang.org/x/net/context"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/cache"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/metrics"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	HTTPAuthorizationBasePath = "/check"

	X_EXT_AUTH_REASON_HEADER = "X-Ext-Auth-Reason"

	RESPONSE_MESSAGE_INVALID_REQUEST   = "Invalid request"
	RESPONSE_MESSAGE_SERVICE_NOT_FOUND = "Service not found"

	X_LOOKUP_KEY_NAME = "host"
)

var (
	statusCodeMapping = map[rpc.Code]envoy_type.StatusCode{
		rpc.OK:                  envoy_type.StatusCode_OK,
		rpc.FAILED_PRECONDITION: envoy_type.StatusCode_BadRequest,
		rpc.NOT_FOUND:           envoy_type.StatusCode_NotFound,
		rpc.UNAUTHENTICATED:     envoy_type.StatusCode_Unauthorized,
		rpc.PERMISSION_DENIED:   envoy_type.StatusCode_Forbidden,
	}

	authServerResponseStatusMetric = metrics.NewCounterMetric("auth_server_response_status", "Response status of authconfigs sent by the auth server.", "status")
	httpServerHandledTotal         = metrics.NewCounterMetric("http_server_handled_total", "Total number of calls completed on the raw HTTP authorization server, regardless of success or failure.", "status")
	httpServerDuration             = metrics.NewDurationMetric("http_server_handling_seconds", "Response latency (seconds) of raw HTTP authorization request that had been application-level handled by the server.")
)

func init() {
	metrics.Register(
		authServerResponseStatusMetric,
		httpServerHandledTotal,
		httpServerDuration,
	)
}

// AuthService is the server API for the authorization service.
type AuthService struct {
	Cache   cache.Cache
	Timeout time.Duration
}

// ServeHTTP invokes authorization check for a simple GET/POST HTTP authorization request
// Content-Type header must be 'application/json'
// The body can be any JSON object; in case the input is a Kubernetes AdmissionReview resource,
// the response is compatible with the Dynamic Admission API
func (a *AuthService) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	ctx := context.New(context.WithTimeout(a.Timeout))
	requestId := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(req))))
	logger := log.WithName("service").WithName("auth").WithValues("request id", requestId)

	switch req.Method {
	case "GET", "POST":
	default:
		closeWithStatus(envoy_type.StatusCode_NotFound, resp, ctx, nil)
		return
	}

	path := strings.TrimSuffix(req.URL.Path, "/")

	if path != HTTPAuthorizationBasePath {
		closeWithStatus(envoy_type.StatusCode_NotFound, resp, ctx, nil)
		return
	}

	if req.Header.Get("Content-Type") != "application/json" {
		closeWithStatus(envoy_type.StatusCode_BadRequest, resp, ctx, nil)
		return
	}

	var payload []byte
	var err error

	if err := context.CheckContext(ctx); err != nil {
		closeWithStatus(envoy_type.StatusCode_ServiceUnavailable, resp, ctx, nil)
		return
	}

	if payload, err = ioutil.ReadAll(req.Body); err != nil {
		closeWithStatus(envoy_type.StatusCode_BadRequest, resp, ctx, nil)
		return
	}

	metrics.ReportTimedMetric(httpServerDuration, func() {
		checkRequest := &envoy_auth.CheckRequest{
			Attributes: &envoy_auth.AttributeContext{
				Request: &envoy_auth.AttributeContext_Request{
					Http: &envoy_auth.AttributeContext_HttpRequest{
						Id:   requestId,
						Host: req.Host,
						Body: string(payload),
					},
				},
			},
		}

		if err := context.CheckContext(ctx); err != nil {
			closeWithStatus(envoy_type.StatusCode_ServiceUnavailable, resp, ctx, nil)
			return
		}

		checkResponse, _ := a.Check(ctx, checkRequest)
		code := rpc.Code(checkResponse.GetStatus().Code)

		var respStatusCode envoy_type.StatusCode
		var respBody []byte

		if admissionReviewRequest := admissionReviewFromPayload(payload); admissionReviewRequest != nil {
			// it's an admission review request
			respStatusCode = envoy_type.StatusCode_OK
			admissionResponse := &v1.AdmissionResponse{}
			admissionResponse.Allowed = code == rpc.OK
			if !admissionResponse.Allowed {
				admissionResponse.Result = &metav1.Status{
					Code: int32(statusCodeMapping[code]),
				}
				for _, h := range checkResponse.GetDeniedResponse().GetHeaders() {
					if h.Header.GetKey() == X_EXT_AUTH_REASON_HEADER {
						admissionResponse.Result.Message = h.Header.GetValue()
						break
					}
				}
			}
			admissionReviewResponse := &v1.AdmissionReview{}
			admissionReviewResponse.SetGroupVersionKind(admissionReviewRequest.GroupVersionKind())
			admissionReviewResponse.Response = admissionResponse
			admissionReviewResponse.Response.UID = admissionReviewRequest.Request.UID
			respBody, err = json.Marshal(admissionReviewResponse)
			if err != nil {
				logger.Error(err, "failed to encode http authorization response")
			}
			resp.Header().Set("Content-Type", "application/json")
		} else {
			// not an admission review request
			respStatusCode = statusCodeMapping[code]
			var headers []*envoy_core.HeaderValueOption
			if code == rpc.OK {
				headers = checkResponse.GetOkResponse().GetHeaders()
			} else {
				headers = checkResponse.GetDeniedResponse().GetHeaders()
				respBody = []byte(checkResponse.GetDeniedResponse().GetBody())
			}
			for _, h := range headers {
				resp.Header().Set(h.Header.GetKey(), h.Header.GetValue())
			}
		}

		closeWithStatus(respStatusCode, resp, ctx, func() {
			_, _ = resp.Write(respBody)
		})
	})
}

// Check performs authorization check based on the attributes associated with the incoming request,
// and returns status `OK` or not `OK`.
func (a *AuthService) Check(parentContext gocontext.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	requestLogger := log.WithName("service").WithName("auth").WithValues("request id", req.Attributes.Request.Http.GetId())
	ctx := log.IntoContext(context.New(context.WithParent(parentContext), context.WithTimeout(a.Timeout)), requestLogger)

	a.logAuthRequest(req, ctx)

	requestData := req.Attributes.Request.Http

	// service config
	var host string
	if h, overridden := req.Attributes.ContextExtensions[X_LOOKUP_KEY_NAME]; overridden {
		host = h
	} else {
		host = requestData.Host
	}

	authConfig := a.Cache.Get(host)
	// If the host is not found, but contains a port, remove the port part and retry.
	if authConfig == nil && strings.Contains(host, ":") {
		splitHost := strings.Split(host, ":")
		authConfig = a.Cache.Get(splitHost[0])
	}

	// If we couldn't find the AuthConfig in the config, we return and deny.
	if authConfig == nil {
		result := auth.AuthResult{Code: rpc.NOT_FOUND, Message: RESPONSE_MESSAGE_SERVICE_NOT_FOUND}
		a.logAuthResult(result, ctx)
		return a.deniedResponse(result), nil
	}

	if err := context.CheckContext(ctx); err != nil {
		result := auth.AuthResult{Code: rpc.UNAVAILABLE}
		a.logAuthResult(result, ctx)
		context.Cancel(ctx)
		return a.deniedResponse(result), nil
	}

	pipeline := NewAuthPipeline(log.IntoContext(ctx, requestLogger), req, *authConfig)
	result := pipeline.Evaluate()

	a.logAuthResult(result, ctx)

	if result.Success() {
		return a.successResponse(result, ctx), nil
	} else {
		return a.deniedResponse(result), nil
	}
}

func (a *AuthService) successResponse(authResult auth.AuthResult, ctx gocontext.Context) *envoy_auth.CheckResponse {
	dynamicMetadata, err := buildEnvoyDynamicMetadata(authResult.Metadata)
	if err != nil {
		log.FromContext(ctx).V(1).Error(err, "failed to create dynamic metadata", "object", authResult.Metadata)
	}

	code := rpc.OK
	reportStatusMetric(code)

	return &envoy_auth.CheckResponse{
		Status: &rpcstatus.Status{
			Code: int32(code),
		},
		HttpResponse: &envoy_auth.CheckResponse_OkResponse{
			OkResponse: &envoy_auth.OkHttpResponse{
				Headers: buildResponseHeaders(authResult.Headers),
			},
		},
		DynamicMetadata: dynamicMetadata,
	}
}

func (a *AuthService) deniedResponse(authResult auth.AuthResult) *envoy_auth.CheckResponse {
	code := authResult.Code
	reportStatusMetric(code)

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
				Body:    authResult.Body,
			},
		},
	}
}

func (a *AuthService) logAuthRequest(req *envoy_auth.CheckRequest, ctx gocontext.Context) {
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

func (a *AuthService) logAuthResult(result auth.AuthResult, ctx gocontext.Context) {
	logger := log.FromContext(ctx)
	success := result.Success()
	baseLogData := []interface{}{"authorized", success, "response", result.Code.String()}

	logData := baseLogData
	if !success {
		reducedResult := auth.AuthResult{
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

func buildEnvoyDynamicMetadata(data map[string]interface{}) (*structpb.Struct, error) {
	var d map[string]interface{}

	// handles unknown types among the values in the map
	if b, err := json.Marshal(data); err != nil {
		return nil, err
	} else {
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
	}

	return structpb.NewStruct(d)
}

func reportStatusMetric(rpcStatusCode rpc.Code) {
	metrics.ReportMetricWithStatus(authServerResponseStatusMetric, rpc.Code_name[int32(rpcStatusCode)])
}

func admissionReviewFromPayload(payload []byte) *v1.AdmissionReview {
	r := v1.AdmissionReview{}
	err := json.Unmarshal(payload, &r)
	if err == nil &&
		r.TypeMeta.Kind == "AdmissionReview" &&
		r.TypeMeta.APIVersion == "admission.k8s.io/v1" &&
		r.Request != nil {
		return &r
	}
	return nil
}

// Writes the response status code to the raw HTTP external authorization and cancels the context
func closeWithStatus(respStatusCode envoy_type.StatusCode, response http.ResponseWriter, ctx gocontext.Context, closingFunc func()) {
	metrics.ReportMetric(httpServerHandledTotal, respStatusCode.String())
	if respStatusCode != envoy_type.StatusCode_OK { // avoids 'http: superfluous response.WriteHeader call'
		response.WriteHeader(int(respStatusCode))
	}
	if closingFunc != nil {
		closingFunc()
	}
	context.Cancel(ctx)
}
