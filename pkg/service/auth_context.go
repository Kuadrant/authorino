package service

import (
	"fmt"
	"strings"
	"sync"

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

type evaluateCallback = func(config common.AuthConfigEvaluator, obj interface{})

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
		if authObj, err := config.Call(authContext); err != nil {
			authCtxLog.Info("Failed to evaluate auth object", "config", config, "error", err)
			return err
		} else {
			cb(config, authObj)
			return nil
		}
	}
}

func (authContext *AuthContext) evaluateOneAuthConfig(authConfigs []common.AuthConfigEvaluator, cb evaluateCallback) error {
	ctx, cancel := context.WithCancel(context.Background())
	waitGroup := new(sync.WaitGroup)
	size := len(authConfigs)
	errorChannel := make(chan error, size)
	successChannel := make(chan bool, size)

	waitGroup.Add(size)

	go func() {
		waitGroup.Wait()
		close(errorChannel)
		close(successChannel)
	}()

	for _, authConfig := range authConfigs {
		objConfig := authConfig
		go func() {
			defer waitGroup.Done()

			err := authContext.evaluateAuthConfig(ctx, objConfig, cb)
			if err != nil {
				errorChannel <- err
			} else {
				successChannel <- true
				cancel() // cancels the context if at least one thread succeeds
			}
		}()
	}

	success := <-successChannel
	err := <-errorChannel

	if success {
		return nil
	} else {
		return err
	}
}

func (authContext *AuthContext) evaluateAllAuthConfigs(authConfigs []common.AuthConfigEvaluator, cb evaluateCallback) error {
	ctx, cancel := context.WithCancel(context.Background())
	waitGroup := new(sync.WaitGroup)
	size := len(authConfigs)
	errorChannel := make(chan error, size)

	waitGroup.Add(size)

	go func() {
		waitGroup.Wait()
		close(errorChannel)
	}()

	for _, authConfig := range authConfigs {
		objConfig := authConfig
		go func() {
			defer waitGroup.Done()

			err := authContext.evaluateAuthConfig(ctx, objConfig, cb)
			if err != nil {
				errorChannel <- err
				cancel() // cancels the context if at least one thread fails
			}
		}()
	}

	err := <-errorChannel
	return err
}

func (authContext *AuthContext) evaluateAnyAuthConfig(authConfigs []common.AuthConfigEvaluator, cb evaluateCallback) {
	ctx := context.Background()
	size := len(authConfigs)
	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(size)

	for _, authConfig := range authConfigs {
		objConfig := authConfig
		go func() {
			defer waitGroup.Done()

			_ = authContext.evaluateAuthConfig(ctx, objConfig, cb)
		}()
	}

	waitGroup.Wait()
}

// Evaluate evaluates all steps of the auth pipeline (identity → metadata → policy enforcement)
func (authContext *AuthContext) Evaluate() error {
	// identity
	if err := authContext.evaluateOneAuthConfig(authContext.API.IdentityConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			v, _ := conf.(*config.IdentityConfig)
			authCtxLog.Info("Identity", "config", conf, "authObj", authObj)
			authContext.Identity[v] = authObj
		}); err != nil {
		return err
	}

	// metadata
	authContext.evaluateAnyAuthConfig(authContext.API.MetadataConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			v, _ := conf.(*config.MetadataConfig)
			authCtxLog.Info("Metadata", "config", conf, "authObj", authObj)
			authContext.Metadata[v] = authObj
		})

	// policy enforcement (authorization)
	if err := authContext.evaluateAllAuthConfigs(authContext.API.AuthorizationConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			v, _ := conf.(*config.AuthorizationConfig)
			authCtxLog.Info("Authorization", "config", conf, "authObj", authObj)
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

func (authContext *AuthContext) GetIdentity() interface{} {
	var id interface{}
	for _, v := range authContext.Identity {
		if v != nil {
			id = v
			break
		}
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
