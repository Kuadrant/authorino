package common

import (
	"golang.org/x/net/context"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

type AuthContext interface {
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
	Call(AuthContext, context.Context) (interface{}, error)
}

type NamedConfigEvaluator interface {
	GetName() string
}

type IdentityConfigEvaluator interface {
	GetOIDC() interface{}
}
