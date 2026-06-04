package metadata

import (
	"context"
	gojson "encoding/json"
	"fmt"
	"net/http"
	gohttptest "net/http/httptest"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/httptest"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/oauth2"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

const (
	testHttpMetadataServerHost string = "127.0.0.1:9005"
	testOAuth2ServerHost       string = "127.0.0.1:9011"
)

func TestGenericHttpCallWithGET(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testHttpMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": httptest.NewHttpServerMockResponseFuncJSON(`{"foo":"bar"}`),
	})
	defer extHttpMetadataServer.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	endpoint := "http://" + testHttpMetadataServerHost + "/metadata"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock())

	sharedCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	sharedCredsMock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
	sharedCredsMock.EXPECT().GetPlacement().Return("authorization_header").AnyTimes()

	metadata := &GenericHttp{
		Endpoint:        endpoint,
		Method:          "GET",
		SharedSecret:    "secret",
		AuthCredentials: sharedCredsMock,
	}

	obj, err := metadata.Call(pipelineMock, ctx)

	assert.NilError(t, err)

	objJSON := obj.(map[string]interface{})
	assert.Equal(t, objJSON["foo"], "bar")
}

func TestGenericHttpCallWithPOST(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testHttpMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": httptest.NewHttpServerMockResponseFuncJSON(`{"foo":"bar"}`),
	})
	defer extHttpMetadataServer.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	endpoint := "http://" + testHttpMetadataServerHost + "/metadata"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock())

	sharedCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	sharedCredsMock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
	sharedCredsMock.EXPECT().GetPlacement().Return("authorization_header").AnyTimes()

	metadata := &GenericHttp{
		Endpoint:        endpoint,
		Method:          "POST",
		Parameters:      []json.JSONProperty{{Name: "user", Value: &json.JSONValue{Pattern: "auth.identity.user"}}},
		ContentType:     "application/x-www-form-urlencoded",
		SharedSecret:    "secret",
		AuthCredentials: sharedCredsMock,
	}

	obj, err := metadata.Call(pipelineMock, ctx)

	assert.NilError(t, err)

	objJSON := obj.(map[string]interface{})
	assert.Equal(t, objJSON["foo"], "bar")
}

func TestGenericHttpCallWithStaticBody(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testHttpMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": httptest.NewHttpServerMockResponseFuncJSON(`{"foo":"bar"}`),
	})
	defer extHttpMetadataServer.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	endpoint := "http://" + testHttpMetadataServerHost + "/metadata"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock())

	sharedCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	sharedCredsMock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
	sharedCredsMock.EXPECT().GetPlacement().Return("authorization_header").AnyTimes()

	metadata := &GenericHttp{
		Endpoint:        endpoint,
		Method:          "POST",
		Body:            &json.JSONValue{Static: `{"foo":"bar"}`},
		ContentType:     "application/json",
		SharedSecret:    "secret",
		AuthCredentials: sharedCredsMock,
	}

	obj, err := metadata.Call(pipelineMock, ctx)

	assert.NilError(t, err)

	objJSON := obj.(map[string]interface{})
	assert.Equal(t, objJSON["foo"], "bar")
}

func TestGenericHttpCallWithDynamicBody(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testHttpMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": httptest.NewHttpServerMockResponseFuncJSON(`{"foo":"bar"}`),
	})
	defer extHttpMetadataServer.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	endpoint := "http://" + testHttpMetadataServerHost + "/metadata"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock())

	sharedCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	sharedCredsMock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
	sharedCredsMock.EXPECT().GetPlacement().Return("authorization_header").AnyTimes()

	metadata := &GenericHttp{
		Endpoint:        endpoint,
		Method:          "POST",
		Body:            &json.JSONValue{Pattern: `\{"foo":"bar","user":\{"name":"{auth.identity.user}"\}\}`},
		ContentType:     "application/json",
		SharedSecret:    "secret",
		AuthCredentials: sharedCredsMock,
	}

	obj, err := metadata.Call(pipelineMock, ctx)

	assert.NilError(t, err)

	objJSON := obj.(map[string]interface{})
	assert.Equal(t, objJSON["foo"], "bar")
}

func TestGenericHttpCallWithURLPlaceholders(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testHttpMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata?p=some-origin": httptest.NewHttpServerMockResponseFuncJSON(`{"foo":"bar"}`),
	})
	defer extHttpMetadataServer.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	endpointWithPlaceholders := "http://" + testHttpMetadataServerHost + "/metadata?p={context.request.http.headers.x-origin}"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock())

	sharedCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	sharedCredsMock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
	sharedCredsMock.EXPECT().GetPlacement().Return("authorization_header").AnyTimes()

	metadata := &GenericHttp{
		Endpoint:        endpointWithPlaceholders,
		Method:          "GET",
		SharedSecret:    "secret",
		AuthCredentials: sharedCredsMock,
	}

	obj, err := metadata.Call(pipelineMock, ctx)

	assert.NilError(t, err)

	objJSON := obj.(map[string]interface{})
	assert.Equal(t, objJSON["foo"], "bar")
}

func TestGenericHttpCallWithCustomHeaders(t *testing.T) {
	// Capture headers sent to the server
	var receivedHeaders http.Header

	// Create test server with custom handler that captures headers
	server := gohttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"foo":"bar"}`))
	}))
	defer server.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock())

	sharedCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	sharedCredsMock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
	sharedCredsMock.EXPECT().GetPlacement().Return("authorization_header").AnyTimes()

	metadata := &GenericHttp{
		Endpoint:     server.URL,
		Method:       "GET",
		SharedSecret: "secret",
		Headers: []json.JSONProperty{
			{Name: "X-Requested-By", Value: &json.JSONValue{Static: "authorino"}},
			{Name: "Content-Type", Value: &json.JSONValue{Static: "to-be-overwritten"}},
		},
		AuthCredentials: sharedCredsMock,
	}

	_, err := metadata.Call(pipelineMock, ctx)

	assert.NilError(t, err)

	// Verify custom headers were sent correctly
	assert.Check(t, receivedHeaders.Get("X-Requested-By") == "authorino", "expected X-Requested-By: authorino")
	// Content-Type should be overwritten to "text/plain" for GET requests (line 157 in generic_http.go)
	assert.Check(t, receivedHeaders.Get("Content-Type") == "text/plain", "expected Content-Type to be overwritten to text/plain for GET requests")
	// Authorization header from credentials (Bearer + SharedSecret)
	assert.Check(t, receivedHeaders.Get("Authorization") == "Bearer secret", "expected Authorization: Bearer secret")
}

func TestGenericHttpWithInvalidJSONResponse(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testHttpMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": httptest.NewHttpServerMockResponseFuncJSON(`{not a valid JSON`),
	})
	defer extHttpMetadataServer.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	endpoint := "http://" + testHttpMetadataServerHost + "/metadata"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock())

	metadata := &GenericHttp{
		Endpoint: endpoint,
		Method:   "GET",
	}

	obj, err := metadata.Call(pipelineMock, ctx)
	assert.ErrorContains(t, err, "invalid")
	assert.Check(t, obj == nil)
}

func TestGenericHttpMultipleElementsJSONResponse(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testHttpMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": httptest.NewHttpServerMockResponseFuncJSON(`{"foo":"bar"}{"blah":"bleh"}`),
	})
	defer extHttpMetadataServer.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	endpoint := "http://" + testHttpMetadataServerHost + "/metadata"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock())

	sharedCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	sharedCredsMock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
	sharedCredsMock.EXPECT().GetPlacement().Return("authorization_header").AnyTimes()

	metadata := &GenericHttp{
		Endpoint:        endpoint,
		Method:          "GET",
		SharedSecret:    "secret",
		AuthCredentials: sharedCredsMock,
	}

	obj, err := metadata.Call(pipelineMock, ctx)

	assert.NilError(t, err)

	objJSON := obj.([]map[string]interface{})
	assert.Equal(t, len(objJSON), 2)
	assert.Equal(t, objJSON[0]["foo"], "bar")
	assert.Equal(t, objJSON[1]["blah"], "bleh")
}

func TestGenericHttpWithTextPlainResponse(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testHttpMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": httptest.NewHttpServerMockResponseFuncPlain("OK"),
	})
	defer extHttpMetadataServer.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	endpoint := "http://" + testHttpMetadataServerHost + "/metadata"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock())

	metadata := &GenericHttp{
		Endpoint: endpoint,
		Method:   "GET",
	}

	obj, err := metadata.Call(pipelineMock, ctx)
	assert.NilError(t, err)
	assert.Equal(t, fmt.Sprintf("%s", obj), "OK")
}

func TestWithOAuth2Authentication(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testHttpMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": httptest.NewHttpServerMockResponseFuncJSON(`{"foo":"bar"}`),
	})
	defer extHttpMetadataServer.Close()

	nonce := 0
	oauth2Server := httptest.NewHttpServerMock(testOAuth2ServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/token": func() httptest.HttpServerMockResponse {
			nonce = nonce + 1
			return httptest.HttpServerMockResponse{
				Status:  http.StatusOK,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    fmt.Sprintf(`{"access_token":"xyz-%d","token_type":"Bearer","expires_in":300}`, nonce), // token expires in 5 min
			}
		},
	})
	defer oauth2Server.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	endpoint := "http://" + testHttpMetadataServerHost + "/metadata"
	tokenUrl := "http://" + testOAuth2ServerHost + "/token"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock()).Times(2)

	sharedCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	sharedCredsMock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
	sharedCredsMock.EXPECT().GetPlacement().Return("authorization_header").AnyTimes()

	metadata := &GenericHttp{
		Endpoint:        endpoint,
		Method:          "GET",
		OAuth2:          oauth2.NewClientCredentialsConfig(tokenUrl, "foo", "secret", []string{}, map[string]string{}),
		AuthCredentials: sharedCredsMock,
	}

	obj, err := metadata.Call(pipelineMock, ctx)
	assert.NilError(t, err)
	objJSON := obj.(map[string]interface{})
	assert.Equal(t, objJSON["foo"], "bar")

	obj, err = metadata.Call(pipelineMock, ctx)
	assert.NilError(t, err)
	objJSON = obj.(map[string]interface{})
	assert.Equal(t, objJSON["foo"], "bar")
}

func TestWithOAuth2AuthenticationWithoutTokenCache(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(testHttpMetadataServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/metadata": httptest.NewHttpServerMockResponseFuncJSON(`{"foo":"bar"}`),
	})
	defer extHttpMetadataServer.Close()

	nonce := 0
	oauth2Server := httptest.NewHttpServerMock(testOAuth2ServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/token": func() httptest.HttpServerMockResponse {
			nonce = nonce + 1
			return httptest.HttpServerMockResponse{
				Status:  http.StatusOK,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    fmt.Sprintf(`{"access_token":"xyz-%d","token_type":"Bearer","expires_in":300}`, nonce), // token expires in 5 min
			}
		},
	})
	defer oauth2Server.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	endpoint := "http://" + testHttpMetadataServerHost + "/metadata"
	tokenUrl := "http://" + testOAuth2ServerHost + "/token"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock()).Times(2)

	sharedCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	sharedCredsMock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
	sharedCredsMock.EXPECT().GetPlacement().Return("authorization_header").AnyTimes()

	metadata := &GenericHttp{
		Endpoint:              endpoint,
		Method:                "GET",
		OAuth2:                oauth2.NewClientCredentialsConfig(tokenUrl, "foo", "secret", []string{}, map[string]string{}),
		OAuth2TokenForceFetch: true,
		AuthCredentials:       sharedCredsMock,
	}

	obj, err := metadata.Call(pipelineMock, ctx)
	assert.NilError(t, err)
	objJSON := obj.(map[string]interface{})
	assert.Equal(t, objJSON["foo"], "bar")

	obj, err = metadata.Call(pipelineMock, ctx)
	assert.NilError(t, err)
	objJSON = obj.(map[string]interface{})
	assert.Equal(t, objJSON["foo"], "bar")
}

func genericHttpAuthDataMock() string {
	type mockIdentityObject struct {
		User string `json:"user"`
	}

	type authorizationJSON struct {
		Context  *envoy_auth.AttributeContext `json:"context"`
		AuthData map[string]interface{}       `json:"auth"`
	}

	authJSON, _ := gojson.Marshal(&authorizationJSON{
		Context: &envoy_auth.AttributeContext{
			Request: &envoy_auth.AttributeContext_Request{
				Http: &envoy_auth.AttributeContext_HttpRequest{
					Headers: map[string]string{
						"x-secret-header": "no-one-knows",
						"x-origin":        "some-origin",
					},
				},
			},
		},
		AuthData: map[string]interface{}{
			"identity": &mockIdentityObject{User: "mock"},
		},
	})

	return string(authJSON)
}
