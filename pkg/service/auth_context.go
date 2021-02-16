package service

import (
	"errors"
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
	authCtxLog = ctrl.Log.WithName("Authorino").WithName("AuthContext")
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

type evaluateCallback = func(config common.AuthConfigEvaluator, obj interface{}, err error) error

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

func (authContext *AuthContext) evaluateAuthConfig(ctx context.Context, config common.AuthConfigEvaluator, cb evaluateCallback) error {
	select {
	case <-ctx.Done():
		authCtxLog.Info("Context aborted", "config", config)
		return nil
	default:
		authObj, err := config.Call(authContext)
		return cb(config, authObj, err)
	}
}

func (authContext *AuthContext) evaluateAuthConfigs(ctx context.Context, authConfigs []common.AuthConfigEvaluator, cb evaluateCallback) error {
	errGroup, errCtx := errgroup.WithContext(ctx)

	for _, authConfig := range authConfigs {
		objConfig := authConfig
		errGroup.Go(func() error {
			return authContext.evaluateAuthConfig(errCtx, objConfig, cb)
		})
	}
	if err := errGroup.Wait(); err != nil {
		return err
	} else {
		authCtxLog.Info("Successfully evaluated all auth objects.", "authConfigs", authConfigs)
		return nil
	}
}

// EvaluateIdentity evaluates given identity configs and retrieves the first valid identity object.
func (authContext *AuthContext) EvaluateIdentity() error {
	identityConfigs := authContext.API.IdentityConfigs
	if len(identityConfigs) <= 0 {
		return errors.New("no identity configs found")
	}

	ctx, cancelCtx := context.WithCancel(context.Background())

	successChannel := make(chan bool)

	go func() {
		defer close(successChannel)
		authContext.evaluateAuthConfigs(ctx, identityConfigs,
			func(conf common.AuthConfigEvaluator, authObj interface{}, err error) error {
				if err != nil {
					authCtxLog.Error(err, "error evaluating identity config", "config", conf)
					return nil // Non blocking error
				}
				// Convert from interfaceType to SpecificType
				v, _ := conf.(*config.IdentityConfig)
				authCtxLog.Info("Identity", "Config", conf, "AuthObj", authObj)
				authContext.Identity[v] = authObj
				cancelCtx()
				successChannel <- true
				return nil
			})
	}()
	success := <-successChannel
	if !success {
		return errors.New("error evaluating identity configs")
	}
	return nil
}

// EvaluateMetadata checks evaluates the given metadata configs and retrieve possible info.
func (authContext *AuthContext) EvaluateMetadata() {
	metadataConfigs := authContext.API.MetadataConfigs
	if len(metadataConfigs) <= 0 {
		authCtxLog.Info("No metadata configs found", "Configs", metadataConfigs)
		return
	}
	authContext.evaluateAuthConfigs(context.Background(), metadataConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}, err error) error {
			if err != nil {
				authCtxLog.Error(err, "error evaluating metadata config", "config", conf)
				return nil // Non blocking error
			}
			// Convert from interfaceType to SpecificType
			v, _ := conf.(*config.MetadataConfig)
			authCtxLog.Info("Metadata", "Config", conf, "AuthObj", authObj)
			authContext.Metadata[v] = authObj
			return nil
		})
}

// EvaluateAuthorization evaluates the authorization config, along with any metadata and identity and authorizes it.
func (authContext *AuthContext) EvaluateAuthorization() error {
	authorizationConfigs := authContext.API.AuthorizationConfigs
	if len(authorizationConfigs) <= 0 {
		return errors.New("no authorization configs found")
	}
	return authContext.evaluateAuthConfigs(context.Background(), authContext.API.AuthorizationConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}, err error) error {
			if err != nil {
				authCtxLog.Error(err, "error evaluating authorization config", "config", conf)
				return err
			}
			// Convert from interfaceType to SpecificType
			v, _ := conf.(*config.AuthorizationConfig)
			authCtxLog.Info("Authorization", "Config", conf, "AuthObj", authObj)
			authContext.Authorization[v] = authObj
			return nil
		})
}

// Evaluate evaluates all steps of the auth pipeline (identity → metadata → policy enforcement)
func (authContext *AuthContext) Evaluate() error {
	// identity
	if err := authContext.EvaluateIdentity(); err != nil {
		return err
	}

	// metadata
	authContext.EvaluateMetadata()

	// policy enforcement (authorization)
	if err := authContext.EvaluateAuthorization(); err != nil {
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
