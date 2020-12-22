package internal

import (
	"golang.org/x/net/context"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
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
