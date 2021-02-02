package service

import (
	"fmt"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/3scale-labs/authorino/pkg/config"
	"github.com/3scale-labs/authorino/pkg/config/common"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"golang.org/x/net/context"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	authCxtLog = ctrl.Log.WithName("Authorino").WithName("AuthContext")
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

type configCallback = func(config common.AuthConfigEvaluator, obj interface{})

// NewAuthContext creates an AuthContext instance
func NewAuthContext(parentCtx context.Context, req *auth.CheckRequest, apiConfig config.APIConfig) AuthContext {

	return AuthContext{
		ParentContext: &parentCtx,
		Request:       req,
		API:           &apiConfig,
		Identity:      make(map[*config.IdentityConfig]interface{}),
		Metadata:      make(map[*config.MetadataConfig]interface{}),
		Authorization: make(map[*config.AuthorizationConfig]interface{}),
	}

}

func (authContext *AuthContext) evaluateAuthConfig(ctx context.Context, config common.AuthConfigEvaluator, cb configCallback) error {
	select {
	case <-ctx.Done():
		authCxtLog.Info("Context cancelled objConfig terminating", "config", config)
		return nil
	default:
		if authObj, err := config.Call(authContext); err != nil {
			authCxtLog.Error(err, "Invalid auth object config")
			return err
		} else {
			cb(config, authObj)
			return nil
		}
	}
}

func (authContext *AuthContext) evaluateAuthConfigs(authConfigs []common.AuthConfigEvaluator, cb configCallback) error {
	errGroup, ctx := errgroup.WithContext(context.Background())

	for _, authConfig := range authConfigs {
		objConfig := authConfig
		errGroup.Go(func() error {
			return authContext.evaluateAuthConfig(ctx, objConfig, cb)
		})
	}
	if err := errGroup.Wait(); err != nil {
		return err
	} else {
		authCxtLog.Info("Successfully fetched all auth objects.", "authConfigs", authConfigs)
		return nil
	}
}

// Evaluate evaluates all steps of the auth pipeline (identity → metadata → policy enforcement)
func (authContext *AuthContext) Evaluate() error {
	// identity
	if err := authContext.evaluateAuthConfigs(authContext.API.IdentityConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			// Convert from interfaceType to SpecificType
			v, _ := conf.(*config.IdentityConfig)
			authCxtLog.Info("Identity", "Config", conf, "AuthObj", authObj)
			authContext.Identity[v] = authObj
		}); err != nil {
		return err
	}

	// metadata
	if err := authContext.evaluateAuthConfigs(authContext.API.MetadataConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			// Convert from interfaceType to SpecificType
			v, _ := conf.(*config.MetadataConfig)
			authCxtLog.Info("Metadata", "Config", conf, "AuthObj", authObj)
			authContext.Metadata[v] = authObj
		}); err != nil {
		return err
	}

	// policy enforcement (authorization)
	if err := authContext.evaluateAuthConfigs(authContext.API.AuthorizationConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			// Convert from interfaceType to SpecificType
			v, _ := conf.(*config.AuthorizationConfig)
			authCxtLog.Info("Authorization", "Config", conf, "AuthObj", authObj)
			authContext.Authorization[v] = authObj
		}); err != nil {
		return err
	}

	return nil
}

func (authContext *AuthContext) GetParentContext() *context.Context {
	return authContext.ParentContext
}

func (authContext *AuthContext) GetRequest() *auth.CheckRequest {
	return authContext.Request
}

func (authContext *AuthContext) GetAPI() interface{} {
	return authContext.API
}

func (authContext *AuthContext) GetIdentity() interface{} { // FIXME: it should return the entire map, not only the first value
	var id interface{}
	for _, v := range authContext.Identity {
		id = v
		break
	}
	return id
}

func (authContext *AuthContext) GetMetadata() map[string]interface{} {
	m := make(map[string]interface{})
	for metadataCfg, metadataObj := range authContext.Metadata {
		t, _ := metadataCfg.GetType()
		m[t] = metadataObj // FIXME: It will override instead of including all the metadata values of the same type
	}
	return m
}

func (authContext *AuthContext) FindIdentityByName(name string) (interface{}, error) {
	for identityConfig := range authContext.Identity {
		if identityConfig.OIDC.Name == name {
			return identityConfig.OIDC, nil
		}
	}
	return nil, fmt.Errorf("cannot find OIDC token")
}

func (authContext *AuthContext) AuthorizationToken() (string, error) {
	authHeader, authHeaderOK := authContext.Request.Attributes.Request.Http.Headers["authorization"]

	var splitToken []string

	if authHeaderOK {
		splitToken = strings.Split(authHeader, "Bearer ")
	}
	if !authHeaderOK || len(splitToken) != 2 {
		return "", fmt.Errorf("authorization header malformed or not provided")
	}

	return splitToken[1], nil // FIXME: Indexing may panic because because of 'nil' slice
}
