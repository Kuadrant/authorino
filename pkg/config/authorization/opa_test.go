package authorization

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/kuadrant/authorino/pkg/common/auth_credentials"

	envoyAuth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	mockCommon "github.com/kuadrant/authorino/pkg/common/mocks"
	"gotest.tools/assert"

	. "github.com/golang/mock/gomock"
	. "github.com/kuadrant/authorino/pkg/common/mocks"
)

const (
	extHttpServiceHost string = "127.0.0.1:9005"
	regoData           string = `
			method = object.get(input.context.request.http, "method", "")
			path = object.get(input.context.request.http, "path", "")

			allow {
              method == "GET"
              path = "/allow"
          }`
	jsonData string = "{\"result\": {\"id\": \"empty\",\n" +
		"\"raw\":\"package my-rego-123\\n method = object.get(input.context.request.http," +
		" \\\"method\\\", \\\"\\\")\\n path = object.get(input.context.request.http, \\\"path\\\"," +
		" \\\"\\\")\\n\\nallow {\\n method == \\\"GET\\\"\\n path = \\\"/allow\\\"\\n}\"}}"
)

type authorizationData struct {
	Context *envoyAuth.AttributeContext `json:"context"`
}

func TestNewOPAAuthorizationInlineRego(t *testing.T) {
	opa, err := NewOPAAuthorization("test-opa", regoData, OPAExternalSource{}, 0, context.TODO())

	assert.NilError(t, err)
	assertOPAAuthorization(t, opa)

}

func TestNewOPAAuthorizationExternalUrl(t *testing.T) {
	extHttpMetadataServer := NewHttpServerMock(extHttpServiceHost, map[string]HttpServerMockResponses{
		"/rego": {Status: 200, Body: regoData},
	})
	defer extHttpMetadataServer.Close()

	externalSource := OPAExternalSource{
		Endpoint:        "http://" + extHttpServiceHost + "/rego",
		AuthCredentials: auth_credentials.NewAuthCredential("", ""),
	}

	opa, err := NewOPAAuthorization("test-opa", "", externalSource, 0, context.TODO())

	assert.NilError(t, err)
	assertOPAAuthorization(t, opa)
}

// TestNewOPAAuthorizationBoth it will take the rego from Inline parameter and won't download it from the external URL
func TestNewOPAAuthorizationBoth(t *testing.T) {
	extHttpMetadataServer := NewHttpServerMock(extHttpServiceHost, map[string]HttpServerMockResponses{
		"/rego": {Status: 200, Body: "won't work"},
	})
	defer extHttpMetadataServer.Close()

	externalSource := OPAExternalSource{
		Endpoint:        "http://" + extHttpServiceHost + "/rego",
		AuthCredentials: auth_credentials.NewAuthCredential("", ""),
	}

	opa, err := NewOPAAuthorization("test-opa", regoData, externalSource, 0, context.TODO())

	assert.NilError(t, err)
	assertOPAAuthorization(t, opa)
}

func TestNewOPAAuthorizationWithPackageInRego(t *testing.T) {
	data := fmt.Sprintf("package my-rego-123\n%s", regoData)
	opa, err := NewOPAAuthorization("test-opa", data, OPAExternalSource{}, 0, context.TODO())

	assert.NilError(t, err)
	assert.Assert(t, !strings.Contains(opa.Rego, "package"))
	assert.Assert(t, !strings.Contains(opa.Rego, "my-rego-123"))
	assertOPAAuthorization(t, opa)
}

func TestNewOPAAuthorizationJsonResponse(t *testing.T) {
	extHttpMetadataServer := NewHttpServerMock(extHttpServiceHost, map[string]HttpServerMockResponses{
		"/rego": {Status: 200, Body: jsonData, Headers: map[string]string{"Content-Type": "application/json"}},
	})
	defer extHttpMetadataServer.Close()

	externalSource := OPAExternalSource{
		Endpoint:        "http://" + extHttpServiceHost + "/rego",
		AuthCredentials: auth_credentials.NewAuthCredential("", ""),
	}

	opa, err := NewOPAAuthorization("test-opa", "", externalSource, 0, context.TODO())

	assert.NilError(t, err)
	assert.Assert(t, !strings.Contains(opa.Rego, "package"))
	assert.Assert(t, !strings.Contains(opa.Rego, "my-rego-123"))
	assertOPAAuthorization(t, opa)
}

func assertOPAAuthorization(t *testing.T, opa *OPA) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	var (
		authorized bool
		err        error
	)
	pipelineMock := mockCommon.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetDataForAuthorization().Return(dataForAuth("/allow", "GET")).Times(1)

	authorized, err = opa.Call(pipelineMock, nil)
	assert.Assert(t, authorized)
	assert.NilError(t, err)

	pipelineMock.EXPECT().GetDataForAuthorization().Return(dataForAuth("/allow", "POST")).AnyTimes()

	authorized, err = opa.Call(pipelineMock, nil)
	assert.Assert(t, !authorized)
	assert.Error(t, err, unauthorizedErrorMsg)
}

func dataForAuth(path string, method string) *authorizationData {
	return &authorizationData{
		Context: &envoyAuth.AttributeContext{
			Request: &envoyAuth.AttributeContext_Request{
				Http: &envoyAuth.AttributeContext_HttpRequest{
					Method: method,
					Path:   path,
				},
			},
		},
	}
}
