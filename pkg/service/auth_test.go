package service

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	gohttptest "net/http/httptest"

	"golang.org/x/net/context"
	"gotest.tools/assert"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/evaluators/authorization"
	"github.com/kuadrant/authorino/pkg/evaluators/identity"
	"github.com/kuadrant/authorino/pkg/evaluators/response"
	"github.com/kuadrant/authorino/pkg/index"
	mock_index "github.com/kuadrant/authorino/pkg/index/mocks"
	"github.com/kuadrant/authorino/pkg/json"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/golang/mock/gomock"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	defaultMaxHttpRequestBytes = 8192
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
		Index: index.NewIndex(),
	}

	var resp *envoy_auth.OkHttpResponse
	resp = service.successResponse(auth.AuthResult{}, nil).GetOkResponse()
	assert.Equal(t, len(resp.GetHeaders()), 0)

	headers := []map[string]string{{"X-Custom-Header": "some-value"}}
	resp = service.successResponse(auth.AuthResult{Headers: headers}, nil).GetOkResponse()
	assert.Equal(t, getHeader(resp.GetHeaders(), "X-Custom-Header"), "some-value")
}

func TestDeniedResponse(t *testing.T) {
	service := AuthService{
		Index: index.NewIndex(),
	}

	var resp *envoy_auth.DeniedHttpResponse
	var extraHeaders []map[string]string

	resp = service.deniedResponse(auth.AuthResult{Code: rpc.FAILED_PRECONDITION, Message: "Invalid request"}).GetDeniedResponse()
	assert.Equal(t, resp.Status.Code, envoy_type.StatusCode_BadRequest)
	assert.Equal(t, getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Invalid request")

	resp = service.deniedResponse(auth.AuthResult{Code: rpc.NOT_FOUND, Message: "Service not found"}).GetDeniedResponse()
	assert.Equal(t, resp.Status.Code, envoy_type.StatusCode_NotFound)
	assert.Equal(t, getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Service not found")

	extraHeaders = []map[string]string{{"WWW-Authenticate": "Bearer"}}
	resp = service.deniedResponse(auth.AuthResult{Code: rpc.UNAUTHENTICATED, Message: "Unauthenticated", Headers: extraHeaders}).GetDeniedResponse()
	assert.Equal(t, resp.Status.Code, envoy_type.StatusCode_Unauthorized)
	assert.Equal(t, getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Unauthenticated")
	assert.Equal(t, getHeader(resp.GetHeaders(), "WWW-Authenticate"), "Bearer")

	resp = service.deniedResponse(auth.AuthResult{Code: rpc.PERMISSION_DENIED, Message: "Unauthorized"}).GetDeniedResponse()
	assert.Equal(t, resp.Status.Code, envoy_type.StatusCode_Forbidden)
	assert.Equal(t, getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Unauthorized")

	extraHeaders = []map[string]string{{"Location": "http://my-app.io/login"}}
	resp = service.deniedResponse(auth.AuthResult{Code: rpc.UNAUTHENTICATED, Status: envoy_type.StatusCode_Found, Message: "Please login", Headers: extraHeaders}).GetDeniedResponse()
	assert.Equal(t, resp.Status.Code, envoy_type.StatusCode_Found)
	assert.Equal(t, getHeader(resp.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Please login")
	assert.Equal(t, getHeader(resp.GetHeaders(), "Location"), "http://my-app.io/login")
	assert.Equal(t, len(resp.GetHeaders()), 2)
}

func TestAuthConfigLookup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	i := mock_index.NewMockIndex(ctrl)
	service := AuthService{Index: i}
	authConfig := &evaluators.AuthConfig{}

	var resp *envoy_auth.CheckResponse
	var err error

	i.EXPECT().Get("host.com").Return(nil)
	resp, err = service.Check(context.TODO(), &envoy_auth.CheckRequest{Attributes: &envoy_auth.AttributeContext{
		Request: &envoy_auth.AttributeContext_Request{Http: &envoy_auth.AttributeContext_HttpRequest{Host: "host.com"}},
	}})
	assert.Equal(t, int32(resp.GetDeniedResponse().Status.Code), int32(404))
	assert.NilError(t, err)

	i.EXPECT().Get("host.com").Return(authConfig)
	resp, err = service.Check(context.TODO(), &envoy_auth.CheckRequest{Attributes: &envoy_auth.AttributeContext{
		Request: &envoy_auth.AttributeContext_Request{Http: &envoy_auth.AttributeContext_HttpRequest{Host: "host.com"}},
	}})
	assert.Equal(t, int32(resp.GetDeniedResponse().Status.Code), int32(401))
	assert.NilError(t, err)

	i.EXPECT().Get("host-overwrite").Return(nil)
	resp, err = service.Check(context.TODO(), &envoy_auth.CheckRequest{Attributes: &envoy_auth.AttributeContext{
		Request:           &envoy_auth.AttributeContext_Request{Http: &envoy_auth.AttributeContext_HttpRequest{Host: "actual-host.com"}},
		ContextExtensions: map[string]string{"host": "host-overwrite"},
	}})
	assert.Equal(t, int32(resp.GetDeniedResponse().Status.Code), int32(404))
	assert.NilError(t, err)

	i.EXPECT().Get("host-overwrite").Return(authConfig)
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

func TestInvalidCheckRequest(t *testing.T) {
	authService := AuthService{Index: index.NewIndex()}
	resp, err := authService.Check(context.TODO(), &envoy_auth.CheckRequest{})
	assert.NilError(t, err)
	assert.Equal(t, resp.Status.Code, int32(rpc.INVALID_ARGUMENT))
	denied := resp.GetDeniedResponse()
	assert.Equal(t, denied.Status.Code, envoy_type.StatusCode_BadRequest)
	assert.Equal(t, getHeader(denied.GetHeaders(), X_EXT_AUTH_REASON_HEADER), "Invalid request")
}

func TestAuthServiceRawHTTPAuthorization_Post(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)
	indexMock.EXPECT().Get("myapp.io").Return(mockAnonymousAccessAuthConfig())
	authService := &AuthService{Index: indexMock, MaxHttpRequestBodySize: defaultMaxHttpRequestBytes}
	request, _ := http.NewRequest("POST", "http://myapp.io/check", bytes.NewReader([]byte(`{}`)))
	request.Header = map[string][]string{"Content-Type": {"application/json"}}
	response := gohttptest.NewRecorder()
	authService.ServeHTTP(response, request)
	assert.Equal(t, response.Code, 200)
}

func TestAuthServiceRawHTTPAuthorization_Get(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)
	indexMock.EXPECT().Get("myapp.io").Return(mockAnonymousAccessAuthConfig())
	authService := &AuthService{Index: indexMock, MaxHttpRequestBodySize: defaultMaxHttpRequestBytes}
	request, _ := http.NewRequest("GET", "http://myapp.io/check", bytes.NewReader([]byte(`{}`)))
	request.Header = map[string][]string{"Content-Type": {"application/json"}}
	response := gohttptest.NewRecorder()
	authService.ServeHTTP(response, request)
	assert.Equal(t, response.Code, 200)
}

func TestAuthServiceRawHTTPAuthorization_UnsupportedMethod(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)
	authService := &AuthService{Index: indexMock, MaxHttpRequestBodySize: defaultMaxHttpRequestBytes}
	request, _ := http.NewRequest("PUT", "http://myapp.io/check", bytes.NewReader([]byte(`{}`)))
	request.Header = map[string][]string{"Content-Type": {"application/json"}}
	response := gohttptest.NewRecorder()
	authService.ServeHTTP(response, request)
	assert.Equal(t, response.Code, 404)
}

func TestAuthServiceRawHTTPAuthorization_InvalidPath(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)
	authService := &AuthService{Index: indexMock, MaxHttpRequestBodySize: defaultMaxHttpRequestBytes}
	request, _ := http.NewRequest("PUT", "http://myapp.io/foo", bytes.NewReader([]byte(`{}`)))
	request.Header = map[string][]string{"Content-Type": {"application/json"}}
	response := gohttptest.NewRecorder()
	authService.ServeHTTP(response, request)
	assert.Equal(t, response.Code, 404)
}

func TestAuthServiceRawHTTPAuthorization_WithQueryString(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)
	indexMock.EXPECT().Get("myapp.io").Return(mockAnonymousAccessAuthConfig())
	authService := &AuthService{Index: indexMock, MaxHttpRequestBodySize: defaultMaxHttpRequestBytes}
	request, _ := http.NewRequest("POST", "http://myapp.io/check?foo=bar", bytes.NewReader([]byte(`{}`)))
	request.Header = map[string][]string{"Content-Type": {"application/json"}}
	response := gohttptest.NewRecorder()
	authService.ServeHTTP(response, request)
	assert.Equal(t, response.Code, 200)
}

type notReadable struct{}

func (n *notReadable) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("failed")
}

func TestAuthServiceRawHTTPAuthorization_UnreadableBody(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)
	authService := &AuthService{Index: indexMock, MaxHttpRequestBodySize: defaultMaxHttpRequestBytes}
	request, _ := http.NewRequest("POST", "http://myapp.io/check", &notReadable{})
	request.Header = map[string][]string{"Content-Type": {"application/json"}}
	response := gohttptest.NewRecorder()
	authService.ServeHTTP(response, request)
	assert.Equal(t, response.Code, 400)
}

func TestAuthServiceRawHTTPAuthorization_PayloadSizeTooLarge(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)
	authService := &AuthService{Index: indexMock, MaxHttpRequestBodySize: 1024}
	request, _ := http.NewRequest("GET", "http://myapp.io/check", bytes.NewReader(make([]byte, 1025)))
	request.Header = map[string][]string{"Content-Type": {"application/json"}}
	response := gohttptest.NewRecorder()
	authService.ServeHTTP(response, request)
	assert.Equal(t, response.Code, 413)
}

func TestAuthServiceRawHTTPAuthorization_WithHeaders(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()

	authConfig := mockAnonymousAccessAuthConfig()
	authConfig.ResponseConfigs = []auth.AuthConfigEvaluator{&evaluators.ResponseConfig{
		Name:       "x-auth-data",
		Wrapper:    "httpHeader",
		WrapperKey: "x-auth-data",
		DynamicJSON: &response.DynamicJSON{
			Properties: []json.JSONProperty{{Name: "headers", Value: &json.JSONValue{Pattern: "context.request.http.headers"}}},
		},
	}}
	indexMock := mock_index.NewMockIndex(mockController)
	indexMock.EXPECT().Get("myapp.io").Return(authConfig)
	authService := &AuthService{Index: indexMock, MaxHttpRequestBodySize: defaultMaxHttpRequestBytes}
	request, _ := http.NewRequest("POST", "http://myapp.io/check", bytes.NewReader([]byte(`{}`)))
	request.Header = map[string][]string{"Content-Type": {"application/json"}, "Authorization": {"Bearer secret"}}
	response := gohttptest.NewRecorder()
	authService.ServeHTTP(response, request)
	assert.Equal(t, response.Code, 200)
	assert.Equal(t, response.Header().Get("X-Auth-Data"), `{"headers":{"authorization":"Bearer secret","content-type":"application/json"}}`)
}

func TestAuthServiceRawHTTPAuthorization_K8sAdmissionReviewAuthorized(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	indexMock := mock_index.NewMockIndex(mockController)
	indexMock.EXPECT().Get("myapp.io").Return(mockAnonymousAccessAuthConfig())
	authService := &AuthService{Index: indexMock, MaxHttpRequestBodySize: defaultMaxHttpRequestBytes}
	request, _ := http.NewRequest("POST", "http://myapp.io/check", bytes.NewReader([]byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"2868ade4-a649-4812-b969-3662a7963535","operation":"CREATE","name":"my-secret","object":{"apiVersion":"v1","kind":"Secret","metadata":"my-secret","data":{"hex":"N2ZmNDcyMjhkYzRjNzRkYjZjY2FiNjJlNzY2YTVlMzgK"}}}}`)))
	request.Header = map[string][]string{"Content-Type": {"application/json"}}
	response := gohttptest.NewRecorder()
	authService.ServeHTTP(response, request)
	assert.Equal(t, response.Code, 200)
	assert.Equal(t, response.Body.String(), `{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1","response":{"uid":"2868ade4-a649-4812-b969-3662a7963535","allowed":true}}`)
}

func TestAuthServiceRawHTTPAuthorization_K8sAdmissionReviewForbidden(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	authCred := auth.NewAuthCredential("", "")
	identityConfig := &evaluators.IdentityConfig{Name: "anonymous", Noop: &identity.Noop{AuthCredentials: authCred}}
	authorizationPolicy, _ := authorization.NewOPAAuthorization("a-policy", `allow = false`, nil, false, 0, context.TODO())
	authorizationConfig := &evaluators.AuthorizationConfig{Name: "always-deny", OPA: authorizationPolicy}
	authConfig := &evaluators.AuthConfig{
		IdentityConfigs:      []auth.AuthConfigEvaluator{identityConfig},
		AuthorizationConfigs: []auth.AuthConfigEvaluator{authorizationConfig},
	}
	indexMock := mock_index.NewMockIndex(mockController)
	indexMock.EXPECT().Get("myapp.io").Return(authConfig)
	authService := &AuthService{Index: indexMock, MaxHttpRequestBodySize: defaultMaxHttpRequestBytes}
	request, _ := http.NewRequest("POST", "http://myapp.io/check", bytes.NewReader([]byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"2868ade4-a649-4812-b969-3662a7963535","operation":"CREATE","name":"my-secret","object":{"apiVersion":"v1","kind":"Secret","metadata":"my-secret","data":{"hex":"N2ZmNDcyMjhkYzRjNzRkYjZjY2FiNjJlNzY2YTVlMzgK"}}}}`)))
	request.Header = map[string][]string{"Content-Type": {"application/json"}}
	response := gohttptest.NewRecorder()
	authService.ServeHTTP(response, request)
	assert.Equal(t, response.Code, 200)
	assert.Equal(t, response.Body.String(), `{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1","response":{"uid":"2868ade4-a649-4812-b969-3662a7963535","allowed":false,"status":{"metadata":{},"message":"Unauthorized","code":403}}}`)
	assert.Equal(t, response.Header().Get("Content-Type"), "application/json")
}

func mockAnonymousAccessAuthConfig() *evaluators.AuthConfig {
	authCred := auth.NewAuthCredential("", "")
	identityConfig := &evaluators.IdentityConfig{Name: "anonymous", Noop: &identity.Noop{AuthCredentials: authCred}}
	return &evaluators.AuthConfig{IdentityConfigs: []auth.AuthConfigEvaluator{identityConfig}}
}
