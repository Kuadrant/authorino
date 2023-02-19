package authorization

import (
	"context"
	gojson "encoding/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/httptest"
	"github.com/kuadrant/authorino/pkg/json"

	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang/mock/gomock"
	"google.golang.org/grpc"
	"gotest.tools/assert"
)

const testAuthzedServerEndpoint string = "127.0.0.1:9010"

// testAuthzedPermissionService implements authzedpb.PermissionsServiceServer
type testAuthzedPermissionService struct {
	checkPermissionHandler func() *authzedpb.CheckPermissionResponse
	authzedpb.UnimplementedPermissionsServiceServer
}

func (s *testAuthzedPermissionService) CheckPermission(context.Context, *authzedpb.CheckPermissionRequest) (*authzedpb.CheckPermissionResponse, error) {
	return s.checkPermissionHandler(), nil
}

func TestAuthzedCallAuthorized(t *testing.T) {
	testAuthzedServer := httptest.NewGrpcServerMock(testAuthzedServerEndpoint, func(server *grpc.Server) {
		authzedpb.RegisterPermissionsServiceServer(server, &testAuthzedPermissionService{
			checkPermissionHandler: func() *authzedpb.CheckPermissionResponse {
				return &authzedpb.CheckPermissionResponse{
					CheckedAt:      &authzedpb.ZedToken{Token: "GhUKEzE2NzU3MDIzODUwMDAwMDAwMDA="},
					Permissionship: authzedpb.CheckPermissionResponse_Permissionship(authzedpb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION),
				}
			},
		})
	})
	defer testAuthzedServer.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(testAuthzedAuthDataMock())

	authzed := &Authzed{
		Endpoint:     testAuthzedServerEndpoint,
		Insecure:     true,
		SharedSecret: "secret",
		Subject:      json.JSONValue{Static: "1"},
		SubjectKind:  json.JSONValue{Static: "user"},
		Resource:     json.JSONValue{Static: "123"},
		ResourceKind: json.JSONValue{Static: "post"},
		Permission:   json.JSONValue{Static: "read"},
	}

	obj, err := authzed.Call(pipelineMock, ctx)

	assert.NilError(t, err)

	objJSON, _ := gojson.Marshal(obj)
	assert.Equal(t, string(objJSON), `{"checked_at":{"token":"GhUKEzE2NzU3MDIzODUwMDAwMDAwMDA="},"permissionship":2}`)
}

func TestAuthzedCallForbidden(t *testing.T) {
	testAuthzedServer := httptest.NewGrpcServerMock(testAuthzedServerEndpoint, func(server *grpc.Server) {
		authzedpb.RegisterPermissionsServiceServer(server, &testAuthzedPermissionService{
			checkPermissionHandler: func() *authzedpb.CheckPermissionResponse {
				return &authzedpb.CheckPermissionResponse{
					CheckedAt:      &authzedpb.ZedToken{Token: "GhUKEzE2NzU3MDIzODUwMDAwMDAwMDA="},
					Permissionship: authzedpb.CheckPermissionResponse_Permissionship(authzedpb.CheckPermissionResponse_PERMISSIONSHIP_NO_PERMISSION),
				}
			},
		})
	})
	defer testAuthzedServer.Close()

	ctx := context.TODO()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(testAuthzedAuthDataMock())

	authzed := &Authzed{
		Endpoint:     testAuthzedServerEndpoint,
		Insecure:     true,
		SharedSecret: "secret",
		Subject:      json.JSONValue{Static: "1"},
		SubjectKind:  json.JSONValue{Static: "user"},
		Resource:     json.JSONValue{Static: "123"},
		ResourceKind: json.JSONValue{Static: "post"},
		Permission:   json.JSONValue{Static: "read"},
	}

	obj, err := authzed.Call(pipelineMock, ctx)
	assert.ErrorContains(t, err, authzedpb.CheckPermissionResponse_PERMISSIONSHIP_NO_PERMISSION.String())
	assert.ErrorContains(t, err, "token=GhUKEzE2NzU3MDIzODUwMDAwMDAwMDA=")
	assert.Check(t, obj == nil)
}

func testAuthzedAuthDataMock() string {
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
