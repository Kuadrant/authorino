package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/httptest"
	mock_workers "github.com/kuadrant/authorino/pkg/workers/mocks"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

const (
	opaExtHttpServerMockAddr string = "127.0.0.1:9007"
	opaInlineRegoDataMock    string = `
		method = object.get(input.context.request.http, "method", "")
		path = object.get(input.context.request.http, "path", "")
		allow { method == "GET"; path = "/allow" }`
)

func TestOPAInlineRego(t *testing.T) {
	opa, err := NewOPAAuthorization("test-opa", opaInlineRegoDataMock, &OPAExternalSource{}, false, 0, context.TODO())

	assert.NilError(t, err)
	assertOPAAuthorization(t, opa)
}

func TestOPAExternalUrl(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(opaExtHttpServerMockAddr, map[string]httptest.HttpServerMockResponseFunc{
		"/rego": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: opaInlineRegoDataMock}
		},
	})
	defer extHttpMetadataServer.Close()

	externalSource := &OPAExternalSource{
		Endpoint:        "http://" + opaExtHttpServerMockAddr + "/rego",
		AuthCredentials: auth.NewAuthCredential("", ""),
	}

	opa, err := NewOPAAuthorization("test-opa", "", externalSource, false, 0, context.TODO())

	assert.NilError(t, err)
	assertOPAAuthorization(t, opa)
}

func TestOPAInlineRegoAndExternalUrl(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(opaExtHttpServerMockAddr, map[string]httptest.HttpServerMockResponseFunc{
		"/rego": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: "won't work"}
		},
	})
	defer extHttpMetadataServer.Close()

	externalSource := &OPAExternalSource{
		Endpoint:        "http://" + opaExtHttpServerMockAddr + "/rego",
		AuthCredentials: auth.NewAuthCredential("", ""),
	}

	opa, err := NewOPAAuthorization("test-opa", opaInlineRegoDataMock, externalSource, false, 0, context.TODO())

	assert.NilError(t, err)
	assertOPAAuthorization(t, opa)
}

func TestOPAWithPackageInRego(t *testing.T) {
	inlineRego := fmt.Sprintf("package my-rego-123\n%s", opaInlineRegoDataMock)
	opa, err := NewOPAAuthorization("test-opa", inlineRego, &OPAExternalSource{}, false, 0, context.TODO())

	assert.NilError(t, err)
	assert.Assert(t, !strings.Contains(opa.Rego, "package"))
	assert.Assert(t, !strings.Contains(opa.Rego, "my-rego-123"))
	assertOPAAuthorization(t, opa)
}

func TestOPAExternalUrlJsonResponse(t *testing.T) {
	jsonData := `{"result": {"id": "empty","raw":"package my-rego-123\n\nmethod = object.get(input.context.request.http, \"method\", \"\")\npath = object.get(input.context.request.http, \"path\", \"\")\n\nallow { method == \"GET\"; path = \"/allow\" }"}}`

	extHttpMetadataServer := httptest.NewHttpServerMock(opaExtHttpServerMockAddr, map[string]httptest.HttpServerMockResponseFunc{
		"/rego": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: jsonData, Headers: map[string]string{"Content-Type": "application/json"}}
		},
	})
	defer extHttpMetadataServer.Close()

	externalSource := &OPAExternalSource{
		Endpoint:        "http://" + opaExtHttpServerMockAddr + "/rego",
		AuthCredentials: auth.NewAuthCredential("", ""),
	}

	opa, err := NewOPAAuthorization("test-opa", "", externalSource, false, 0, context.TODO())

	assert.NilError(t, err)
	assert.Assert(t, !strings.Contains(opa.Rego, "package"))
	assert.Assert(t, !strings.Contains(opa.Rego, "my-rego-123"))
	assertOPAAuthorization(t, opa)
}

func TestOPAExternalUrlMissingContentType(t *testing.T) {
	extHttpMetadataServer := httptest.NewHttpServerMock(opaExtHttpServerMockAddr, map[string]httptest.HttpServerMockResponseFunc{
		"/rego": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{Status: 200, Body: opaInlineRegoDataMock, Headers: map[string]string{"Content-Type": ""}}
		},
	})
	defer extHttpMetadataServer.Close()

	externalSource := &OPAExternalSource{
		Endpoint:        "http://" + opaExtHttpServerMockAddr + "/rego",
		AuthCredentials: auth.NewAuthCredential("", ""),
	}

	opa, err := NewOPAAuthorization("test-opa", "", externalSource, false, 0, context.TODO())

	assert.NilError(t, err)
	assertOPAAuthorization(t, opa)
}

func TestOPAExternalUrlWithTTL(t *testing.T) {
	changed := false
	extHttpMetadataServer := httptest.NewHttpServerMock(opaExtHttpServerMockAddr, map[string]httptest.HttpServerMockResponseFunc{
		"/rego": func() httptest.HttpServerMockResponse {
			var rego string
			if changed {
				rego = opaInlineRegoDataMock + `allow { method == "POST"; path = "/allow" }`
			} else {
				rego = opaInlineRegoDataMock
				changed = true
			}

			return httptest.HttpServerMockResponse{Status: 200, Body: rego}
		},
	})
	defer extHttpMetadataServer.Close()

	externalSource := &OPAExternalSource{
		Endpoint:        "http://" + opaExtHttpServerMockAddr + "/rego",
		AuthCredentials: auth.NewAuthCredential("", ""),
		TTL:             3,
	}

	opa, err := NewOPAAuthorization("test-opa", "", externalSource, false, 0, context.TODO())
	defer func(opa *OPA) {
		_ = opa.Clean(context.Background())
	}(opa)

	assert.NilError(t, err)
	assert.Check(t, strings.Contains(opa.Rego, "GET"))
	assert.Check(t, opa.ExternalSource.refresher != nil)

	time.Sleep(4 * time.Second)
	assert.Check(t, strings.Contains(opa.Rego, "POST"))
}

func TestOPAClean(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	refresher := mock_workers.NewMockWorker(ctrl)
	opa, _ := NewOPAAuthorization("test-opa", "", nil, false, 0, context.TODO())
	opa.ExternalSource = &OPAExternalSource{
		Endpoint:        "http://" + opaExtHttpServerMockAddr + "/rego",
		AuthCredentials: auth.NewAuthCredential("", ""),
		refresher:       refresher,
	}
	refresher.EXPECT().Stop()
	err := opa.Clean(context.Background())
	assert.NilError(t, err)
}

func TestOPAAllValues(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(opaAuthDataMock("/allow", "GET")).Times(1)

	opa, _ := NewOPAAuthorization("test-opa", opaInlineRegoDataMock, &OPAExternalSource{}, true, 0, context.TODO())

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

func TestOPANonBooleanAllowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(opaAuthDataMock("/allow", "GET")).Times(1)

	opa, _ := NewOPAAuthorization("test-opa", `allow = "foo"`, &OPAExternalSource{}, false, 0, context.TODO())

	results, err := opa.Call(pipelineMock, nil)
	resultSet, _ := results.(rego.Vars)
	authorized, ok := resultSet["allow"].(bool)
	assert.Assert(t, !authorized)
	assert.Assert(t, !ok)
	assert.ErrorContains(t, err, "Unauthorized")
}

func assertOPAAuthorization(t *testing.T, opa *OPA) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var (
		results    interface{}
		resultSet  rego.Vars
		authorized bool
		err        error
	)
	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
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
		Context *envoy_auth.AttributeContext `json:"context"`
	}

	authJSON, _ := json.Marshal(&authorizationJSON{
		Context: &envoy_auth.AttributeContext{
			Request: &envoy_auth.AttributeContext_Request{
				Http: &envoy_auth.AttributeContext_HttpRequest{
					Method: method,
					Path:   path,
				},
			},
		},
	})

	return string(authJSON)
}

func BenchmarkOPAAuthz(b *testing.B) {
	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(opaAuthDataMock("/allow", "GET")).MinTimes(1)
	opa, _ := NewOPAAuthorization("test-opa", opaInlineRegoDataMock, &OPAExternalSource{}, false, 0, context.TODO())

	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = opa.Call(pipelineMock, nil)
	}
	b.StopTimer()
	assert.NilError(b, err)
}
