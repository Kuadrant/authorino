package common

import (
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"golang.org/x/net/context"
)

type AuthContext interface {
	GetParentContext() *context.Context
	GetRequest() *auth.CheckRequest
	GetAPI() interface{}
	GetIdentity() interface{} // FIXME: it should return the entire map
	GetMetadata() map[string]interface{}

	FindIdentityByName(name string) (interface{}, error)
	AuthorizationToken() (string, error)
}
