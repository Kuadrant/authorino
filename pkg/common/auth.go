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
	GetIdentity() interface{} // FIXME: it should return the entire map
	GetMetadata() map[string]interface{}
	FindIdentityConfigByName(name string) (interface{}, error)
}

// AuthConfigEvaluator interface represents the configuration pieces of Identity, Metadata and Authorization
type AuthConfigEvaluator interface {
	Call(AuthContext, context.Context) (interface{}, error)
}

type IdentityConfigEvaluator interface {
	AuthConfigEvaluator
	GetOIDC() interface{}
}
