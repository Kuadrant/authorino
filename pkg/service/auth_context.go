package service

import (
	"fmt"
	"strings"

	"github.com/3scale/authorino/pkg/config"
	"github.com/3scale/authorino/pkg/config/internal"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"golang.org/x/net/context"
)

// AuthContext holds the context of each auth request, including the request itself (sent by the client),
// the auth config of the requested API and the lists of identity verifications, metadata add-ons and
// authorization policies, and their corresponding results after evaluated
type AuthContext struct {
	ParentContext *context.Context
	Request       *auth.CheckRequest
	API           *config.APIConfig

	Identity      map[*config.IdentityConfig]interface{}
	Metadata      map[*config.MetadataConfig]interface{}
	Authorization map[*config.AuthorizationConfig]interface{}
}

// AuthObjectConfig provides an interface for APIConfig objects that implements a Call method
type AuthObjectConfig interface {
	Call(ctx internal.AuthContext) (interface{}, error)
}

func (authContext *AuthContext) getAuthObject(authObjConfig AuthObjectConfig, ch chan bool) (interface{}, error) {
	if ret, err := authObjConfig.Call(authContext); err != nil {
		return nil, err
	} else {
		ch <- true
		return ret, nil
	}
}

// Evaluate evaluates all steps of the auth pipeline (identity → metadata → policy enforcement)
func (self *AuthContext) Evaluate() error {
	identityCh, metadataCh, authCh := make(chan bool), make(chan bool), make(chan bool)

	// identity
	for _, config := range self.API.IdentityConfigs {
		var idAuthObjCfg AuthObjectConfig = &config
		go func() {
			if authObj, err := self.getAuthObject(idAuthObjCfg, identityCh); err == nil {
				self.Identity[&config] = authObj
			}
		}()
	}
	<-identityCh

	// metadata
	for _, config := range self.API.MetadataConfigs {
		var idAuthObjCfg AuthObjectConfig = &config
		go func() {
			if authObj, err := self.getAuthObject(idAuthObjCfg, identityCh); err == nil {
				self.Metadata[&config] = authObj
			}
		}()
	}
	<-metadataCh

	// policy enforcement (authorization)
	for _, config := range self.API.AuthorizationConfigs {
		go func() error {
			if ret, err := config.Call(self); err != nil {
				return err
			} else {
				self.Authorization[&config] = ret
				metadataCh <- true
				return nil
			}
		}()
	}
	<-authCh

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
