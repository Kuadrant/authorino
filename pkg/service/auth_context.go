package service

import (
	"fmt"
	"strings"

	"github.com/3scale/authorino/pkg/config"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"golang.org/x/net/context"
)

// AuthContext holds the context of each auth request, including the request itself (sent by the client),
// the auth config of the requested API and the lists of identity verifications, metadata add-ons and
// authorization policies, and their corresponding results after evaluated
type AuthContext struct {
	ParentContext *context.Context
	Request *auth.CheckRequest
	API *APIConfig

	Identity map[*config.IdentityConfig] interface{}
	Metadata map[*config.MetadataConfig] interface{}
	Authorization map[*config.AuthorizationConfig] interface{}
}

// Evaluate evaluates all steps of the auth pipeline (identity → metadata → policy enforcement)
func (self *AuthContext) Evaluate() error {
	self.Identity = make(map[*config.IdentityConfig] interface{})
	self.Metadata = make(map[*config.MetadataConfig] interface{})
	self.Authorization = make(map[*config.AuthorizationConfig] interface{})

	// identity (authentication)
	identityConfigs := self.API.IdentityConfigs
	for i := range identityConfigs {
		c := identityConfigs[i]
		if ret, err := c.Call(self); err != nil { return err } else {
			self.Identity[&c] = ret
			break;
		}
	}

	// metadata
	metadataConfigs := self.API.MetadataConfigs
	for i := range metadataConfigs {
		c := metadataConfigs[i]
		if ret, err := c.Call(self); err != nil { return err } else { self.Metadata[&c] = ret }
	}

	// policy enforcement (authorization)
	authorizationConfigs := self.API.AuthorizationConfigs
	for i := range metadataConfigs {
		c := authorizationConfigs[i]
		if ret, err := c.Call(self); err != nil { return err } else { self.Authorization[&c] = ret }
	}

	return nil
}

func (self *AuthContext) GetParentContext() *context.Context {
	return self.ParentContext
}

func (self *AuthContext) GetRequest() *auth.CheckRequest {
	return self.Request
}

func (self *AuthContext) GetAPI() interface{} {
	return self.API
}

func (self *AuthContext) GetIdentity() interface{} { // FIXME: it should return the entire map, not only the first value
	var id interface{}
	for _, v := range self.Identity {
		id = v
		break
	}
	return id
}

func (self *AuthContext) GetMetadata() map[string]interface{} {
	m := make(map[string]interface{})
	for key, value := range self.Metadata {
		t, _ := key.GetType()
		m[t] = value // FIXME: It will override instead of including all the metadata values of the same type
	}
	return m
}

func (self *AuthContext) FindIdentityByName(name string) (interface{}, error) {
	for id := range self.Identity {
		if id.OIDC.Name == name {
			return id.OIDC, nil
		}
	}
	return nil, fmt.Errorf("Cannot find OIDC token")
}

func (self *AuthContext) AuthorizationToken() (string, error) {
	authHeader, authHeaderOK := self.Request.Attributes.Request.Http.Headers["authorization"]

	var splitToken []string

	if authHeaderOK {
		splitToken = strings.Split(authHeader, "Bearer ")
	}
	if !authHeaderOK || len(splitToken) != 2 {
		return "", fmt.Errorf("Authorization header malformed or not provided")
	}

	return splitToken[1], nil
}
