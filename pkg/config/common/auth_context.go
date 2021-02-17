package common

import (
	"golang.org/x/net/context"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

type AuthContext interface {
	GetParentContext() *context.Context
	GetRequest() *envoy_auth.CheckRequest
	GetAPI() interface{}
	GetIdentity() interface{} // FIXME: it should return the entire map
	GetMetadata() map[string]interface{}

	FindIdentityByName(name string) (interface{}, error)
	AuthorizationToken() (string, error)
}

// AuthConfigEvaluator interface represents the configuration pieces of Identity, Metadata and Authorization
type AuthConfigEvaluator interface {
	Call(AuthContext) (interface{}, error)
}
