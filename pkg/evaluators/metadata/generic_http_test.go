package metadata

import (
	"bytes"
	"context"
	gojson "encoding/json"
	"fmt"
	"net/http"
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
	httpRequestMock, _ := http.NewRequest("GET", endpoint, nil)
	sharedCredsMock.EXPECT().BuildRequestWithCredentials(ctx, endpoint, "GET", "secret", nil).Return(httpRequestMock, nil)

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
	requestBody := bytes.NewBuffer([]byte("user=mock"))
	httpRequestMock, _ := http.NewRequest("POST", endpoint, requestBody)
	sharedCredsMock.EXPECT().BuildRequestWithCredentials(ctx, endpoint, "POST", "secret", requestBody).Return(httpRequestMock, nil)

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
	requestBody := bytes.NewBuffer([]byte(`{"foo":"bar"}`))
	httpRequestMock, _ := http.NewRequest("POST", endpoint, requestBody)
	sharedCredsMock.EXPECT().BuildRequestWithCredentials(ctx, endpoint, "POST", "secret", requestBody).Return(httpRequestMock, nil)

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
	requestBody := bytes.NewBuffer([]byte(`{"foo":"bar","user":{"name":"mock"}}`))
	httpRequestMock, _ := http.NewRequest("POST", endpoint, requestBody)
	sharedCredsMock.EXPECT().BuildRequestWithCredentials(ctx, endpoint, "POST", "secret", requestBody).Return(httpRequestMock, nil)

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
	endpoint := "http://" + testHttpMetadataServerHost + "/metadata?p=some-origin"

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(genericHttpAuthDataMock())

	sharedCredsMock := mock_auth.NewMockAuthCredentials(ctrl)
	httpRequestMock, _ := http.NewRequest("GET", endpoint, nil)
	sharedCredsMock.EXPECT().BuildRequestWithCredentials(ctx, endpoint, "GET", "secret", nil).Return(httpRequestMock, nil)

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
	httpRequestMock, _ := http.NewRequest("GET", endpoint, nil)
	sharedCredsMock.EXPECT().BuildRequestWithCredentials(ctx, endpoint, "GET", "", nil).Return(httpRequestMock, nil)

	metadata := &GenericHttp{
		Endpoint: endpoint,
		Method:   "GET",
		Headers: []json.JSONProperty{
			{Name: "X-Requested-By", Value: &json.JSONValue{Static: "authorino"}},
			{Name: "Content-Type", Value: &json.JSONValue{Static: "to-be-overwritten"}},
		},
		AuthCredentials: sharedCredsMock,
	}

	_, err := metadata.Call(pipelineMock, ctx)

	assert.NilError(t, err)
	assert.Equal(t, httpRequestMock.Header.Get("X-Requested-By"), "authorino")
	assert.Equal(t, httpRequestMock.Header.Get("Content-Type"), "text/plain")
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
	httpRequestMock, _ := http.NewRequest("GET", endpoint, nil)
	sharedCredsMock.EXPECT().BuildRequestWithCredentials(ctx, endpoint, "GET", "secret", nil).Return(httpRequestMock, nil)

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
	httpRequestMock, _ := http.NewRequest("GET", endpoint, nil)
	sharedCredsMock.EXPECT().BuildRequestWithCredentials(ctx, endpoint, "GET", "xyz-1", nil).Return(httpRequestMock, nil).Times(2)

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
	httpRequestMock, _ := http.NewRequest("GET", endpoint, nil)
	sharedCredsMock.EXPECT().BuildRequestWithCredentials(ctx, endpoint, "GET", "xyz-1", nil).Return(httpRequestMock, nil)
	sharedCredsMock.EXPECT().BuildRequestWithCredentials(ctx, endpoint, "GET", "xyz-2", nil).Return(httpRequestMock, nil)

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
