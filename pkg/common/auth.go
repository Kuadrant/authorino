package common

import (
	"golang.org/x/net/context"

	"github.com/kuadrant/authorino/pkg/common/auth_credentials"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type AuthPipeline interface {
	Evaluate() AuthResult
	GetRequest() *envoy_auth.CheckRequest
	GetHttp() *envoy_auth.AttributeContext_HttpRequest
	GetAPI() interface{}
	GetResolvedIdentity() (interface{}, interface{})
	GetResolvedMetadata() map[interface{}]interface{}
	GetDataForAuthorization() interface{}
	GetPostAuthorizationData() interface{}
}

// AuthConfigEvaluator interface represents the configuration pieces of Identity, Metadata and Authorization
type AuthConfigEvaluator interface {
	Call(AuthPipeline, context.Context) (interface{}, error)
}

type NamedConfigEvaluator interface {
	GetName() string
}

type IdentityConfigEvaluator interface {
	GetAuthCredentials() auth_credentials.AuthCredentials
	GetOIDC() interface{}
	ResolveExtendedProperties(AuthPipeline) (interface{}, error)
}

type APIKeySecretFinder interface {
	FindSecretByName(types.NamespacedName) *v1.Secret
}

type WristbandIssuer interface {
	AuthConfigEvaluator
	GetIssuer() string
	OpenIDConfig() (string, error)
	JWKS() (string, error)
}

type ResponseConfigEvaluator interface {
	NamedConfigEvaluator
	GetWristbandIssuer() WristbandIssuer
}

// AuthResult holds the result data for building the response to an auth check
type AuthResult struct {
	// Code is gRPC response code to the auth check
	Code rpc.Code `json:"code,omitempty"`
	// Status is HTTP status code to override the default mapping between gRPC response codes and HTTP status messages
	// for auth
	Status envoy_type.StatusCode `json:"status,omitempty"`
	// Message is X-Ext-Auth-Reason message returned in an injected HTTP response header, to explain the reason of the
	// auth check result
	Message string `json:"message,omitempty"`
	// Headers are other HTTP headers to inject in the response
	Headers []map[string]string `json:"headers,omitempty"`
	// Metadata are Envoy dynamic metadata content
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Success tells whether the auth check result was successful and therefore access can be granted to the requested
// resource or it has failed (deny access)
func (result *AuthResult) Success() bool {
	return result.Code == rpc.OK
}
