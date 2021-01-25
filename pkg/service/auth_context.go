package service

import (
	"fmt"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/3scale-labs/authorino/pkg/config"
	"github.com/3scale-labs/authorino/pkg/config/common"

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
	Call(ctx common.AuthContext) (interface{}, error)
}

type configCallback = func(config AuthObjectConfig, obj interface{})

func (authContext *AuthContext) getAuthObject(ctx context.Context, objConfig AuthObjectConfig, cb configCallback) error {
	select {
	case <-ctx.Done():
		fmt.Printf("context cancelled objConfig %v terminting\n", objConfig)
		return nil
	default:
		if authObj, err := objConfig.Call(authContext); err != nil {
			return fmt.Errorf("Invalid auth object config %v ", err)
		} else {
			cb(objConfig, authObj)
			return nil
		}
	}
}

func (authContext *AuthContext) getAuthObjects(configs []AuthObjectConfig, cb configCallback) error {
	errGroup, ctx := errgroup.WithContext(context.Background())

	for _, config := range configs {
		objConfig := config
		errGroup.Go(func() error {
			return authContext.getAuthObject(ctx, objConfig, cb)
		})
	}
	if err := errGroup.Wait(); err != nil {
		return err
	} else {
		fmt.Println("Successfully fetched all auth objects.")
		return nil
	}
}

// GetIDObject gets an Identity auth object given an Identity config.
func (authContext *AuthContext) GetIDObject() error {
	configs := make([]AuthObjectConfig, len(authContext.API.IdentityConfigs))
	// Convert []SpecificType to []interfaceType
	for i, conf := range authContext.API.IdentityConfigs {
		cpConf := conf
		configs[i] = &cpConf
	}
	return authContext.getAuthObjects(configs,
		func(conf AuthObjectConfig, authObj interface{}) {
			// Caution: type assertion not checked
			v, _ := conf.(*config.IdentityConfig)
			authContext.Identity[v] = authObj
		})
}

// GetMDObject gets a Metadata auth object given a Metadata config.
func (authContext *AuthContext) GetMDObject() error {
	configs := make([]AuthObjectConfig, len(authContext.API.MetadataConfigs))
	// Convert []SpecificType to []interfaceType
	for i, conf := range authContext.API.MetadataConfigs {
		cpConf := conf
		configs[i] = &cpConf
	}
	return authContext.getAuthObjects(configs,
		func(conf AuthObjectConfig, authObj interface{}) {
			// Caution: type assertion not checked
			v, _ := conf.(*config.MetadataConfig)
			authContext.Metadata[v] = authObj
		})
}

// GetAuthObject gets an Authorization object given an Authorization config.
func (authContext *AuthContext) GetAuthObject() error {
	configs := make([]AuthObjectConfig, len(authContext.API.AuthorizationConfigs))
	// Convert []SpecificType to []interfaceType
	for i, conf := range authContext.API.AuthorizationConfigs {
		cpConf := conf
		configs[i] = &cpConf
	}
	return authContext.getAuthObjects(configs,
		func(conf AuthObjectConfig, authObj interface{}) {
			// Caution: type assertion not checked
			v, _ := conf.(*config.AuthorizationConfig)
			authContext.Authorization[v] = authObj
		})
}

// Evaluate evaluates all steps of the auth pipeline (identity → metadata → policy enforcement)
func (authContext *AuthContext) Evaluate() error {
	// identity
	if err := authContext.GetIDObject(); err != nil {
		return err
	}

	// metadata
	if err := authContext.GetMDObject(); err != nil {
		return err
	}

	// policy enforcement (authorization)
	if err := authContext.GetAuthObject(); err != nil {
		return err
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
