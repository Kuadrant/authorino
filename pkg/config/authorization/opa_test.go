package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kuadrant/authorino/pkg/common/auth_credentials"

	envoyAuth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	mockCommon "github.com/kuadrant/authorino/pkg/common/mocks"
	"github.com/open-policy-agent/opa/rego"
	"gotest.tools/assert"

	. "github.com/golang/mock/gomock"
	. "github.com/kuadrant/authorino/pkg/common/mocks"
)

const (
	extHttpServiceHost    string = "127.0.0.1:9005"
	opaInlineRegoDataMock string = `
		method = object.get(input.context.request.http, "method", "")
		path = object.get(input.context.request.http, "path", "")
		allow { method == "GET"; path = "/allow" }`
)

func TestOPAInlineRego(t *testing.T) {
	opa, err := NewOPAAuthorization("test-opa", opaInlineRegoDataMock, OPAExternalSource{}, false, 0, context.TODO())

	assert.NilError(t, err)
	assertOPAAuthorization(t, opa)
}

func TestOPAExternalUrl(t *testing.T) {
	extHttpMetadataServer := NewHttpServerMock(extHttpServiceHost, map[string]HttpServerMockResponseFunc{
		"/rego": func() HttpServerMockResponse { return HttpServerMockResponse{Status: 200, Body: opaInlineRegoDataMock} },
	})
	defer extHttpMetadataServer.Close()

	externalSource := OPAExternalSource{
		Endpoint:        "http://" + extHttpServiceHost + "/rego",
		AuthCredentials: auth_credentials.NewAuthCredential("", ""),
	}

	opa, err := NewOPAAuthorization("test-opa", "", externalSource, false, 0, context.TODO())

	assert.NilError(t, err)
	assertOPAAuthorization(t, opa)
}

func TestOPAInlineRegoAndExternalUrl(t *testing.T) {
	extHttpMetadataServer := NewHttpServerMock(extHttpServiceHost, map[string]HttpServerMockResponseFunc{
		"/rego": func() HttpServerMockResponse { return HttpServerMockResponse{Status: 200, Body: "won't work"} },
	})
	defer extHttpMetadataServer.Close()

	externalSource := OPAExternalSource{
		Endpoint:        "http://" + extHttpServiceHost + "/rego",
		AuthCredentials: auth_credentials.NewAuthCredential("", ""),
	}

	opa, err := NewOPAAuthorization("test-opa", opaInlineRegoDataMock, externalSource, false, 0, context.TODO())

	assert.NilError(t, err)
	assertOPAAuthorization(t, opa)
}

func TestOPAWithPackageInRego(t *testing.T) {
	inlineRego := fmt.Sprintf("package my-rego-123\n%s", opaInlineRegoDataMock)
	opa, err := NewOPAAuthorization("test-opa", inlineRego, OPAExternalSource{}, false, 0, context.TODO())

	assert.NilError(t, err)
	assert.Assert(t, !strings.Contains(opa.Rego, "package"))
	assert.Assert(t, !strings.Contains(opa.Rego, "my-rego-123"))
	assertOPAAuthorization(t, opa)
}

func TestOPAExternalUrlJsonResponse(t *testing.T) {
	jsonData := `{"result": {"id": "empty","raw":"package my-rego-123\n\nmethod = object.get(input.context.request.http, \"method\", \"\")\npath = object.get(input.context.request.http, \"path\", \"\")\n\nallow { method == \"GET\"; path = \"/allow\" }"}}`

	extHttpMetadataServer := NewHttpServerMock(extHttpServiceHost, map[string]HttpServerMockResponseFunc{
		"/rego": func() HttpServerMockResponse {
			return HttpServerMockResponse{Status: 200, Body: jsonData, Headers: map[string]string{"Content-Type": "application/json"}}
		},
	})
	defer extHttpMetadataServer.Close()

	externalSource := OPAExternalSource{
		Endpoint:        "http://" + extHttpServiceHost + "/rego",
		AuthCredentials: auth_credentials.NewAuthCredential("", ""),
	}

	opa, err := NewOPAAuthorization("test-opa", "", externalSource, false, 0, context.TODO())

	assert.NilError(t, err)
	assert.Assert(t, !strings.Contains(opa.Rego, "package"))
	assert.Assert(t, !strings.Contains(opa.Rego, "my-rego-123"))
	assertOPAAuthorization(t, opa)
}

func TestOPAAllValues(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	pipelineMock := mockCommon.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(opaAuthDataMock("/allow", "GET")).Times(1)

	opa, _ := NewOPAAuthorization("test-opa", opaInlineRegoDataMock, OPAExternalSource{}, true, 0, context.TODO())

	results, err := opa.Call(pipelineMock, nil)
	resultSet, _ := results.(rego.Vars)
	authorized, _ := resultSet["allow"].(bool)
	method, _ := resultSet["method"].(string)
	path, _ := resultSet["path"].(string)
	_, undefinedFound := resultSet["undefined"]

	assert.NilError(t, err)
	assert.Assert(t, authorized)
	assert.Equal(t, method, "GET")
	assert.Equal(t, path, "/allow")
	assert.Assert(t, !undefinedFound)
}

func assertOPAAuthorization(t *testing.T, opa *OPA) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	var (
		results    interface{}
		resultSet  rego.Vars
		authorized bool
		err        error
	)
	pipelineMock := mockCommon.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(opaAuthDataMock("/allow", "GET")).Times(1)

	results, err = opa.Call(pipelineMock, nil)
	resultSet, _ = results.(rego.Vars)
	authorized, _ = resultSet["allow"].(bool)
	assert.Assert(t, authorized)
	assert.NilError(t, err)

	pipelineMock.EXPECT().GetAuthorizationJSON().Return(opaAuthDataMock("/allow", "POST")).AnyTimes()

	results, err = opa.Call(pipelineMock, nil)
	resultSet, _ = results.(rego.Vars)
	authorized, _ = resultSet["allow"].(bool)
	assert.Assert(t, !authorized)
	assert.Error(t, err, unauthorizedErrorMsg)
}

func opaAuthDataMock(path string, method string) string {
	type authorizationJSON struct {
		Context *envoyAuth.AttributeContext `json:"context"`
	}

	authJSON, _ := json.Marshal(&authorizationJSON{
		Context: &envoyAuth.AttributeContext{
			Request: &envoyAuth.AttributeContext_Request{
				Http: &envoyAuth.AttributeContext_HttpRequest{
					Method: method,
					Path:   path,
				},
			},
		},
	})

	return string(authJSON)
}
