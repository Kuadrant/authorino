package common

import (
	"golang.org/x/net/context"

	"github.com/kuadrant/authorino/pkg/common/auth_credentials"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type AuthPipeline interface {
	GetParentContext() *context.Context
	GetRequest() *envoy_auth.CheckRequest
	GetHttp() *envoy_auth.AttributeContext_HttpRequest
	GetAPI() interface{}
	GetResolvedIdentity() (interface{}, interface{})
	GetResolvedMetadata() map[interface{}]interface{}
	GetDataForAuthorization() interface{}
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
