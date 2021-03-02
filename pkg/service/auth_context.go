package service

import (
	"fmt"
	"sync"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/config"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"golang.org/x/net/context"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	authCtxLog = ctrl.Log.WithName("Authorino").WithName("AuthContext")
)

type EvaluationResponse struct {
	Evaluator common.AuthConfigEvaluator
	Object    interface{}
	Error     error
}

func (evresp *EvaluationResponse) Success() bool {
	return evresp.Error == nil
}

func newEvaluationResponse(evaluator common.AuthConfigEvaluator, obj interface{}, err error) EvaluationResponse {
	return EvaluationResponse{
		Evaluator: evaluator,
		Object:    obj,
		Error:     err,
	}
}

// AuthContext holds the context of each auth request, including the request itself (sent by the client),
// the auth config of the requested API and the lists of identity verifications, metadata add-ons and
// authorization policies, and their corresponding results after evaluated
type AuthContext struct {
	ParentContext *context.Context
	Request       *envoy_auth.CheckRequest
	API           *config.APIConfig

	Identity      map[*config.IdentityConfig]interface{}
	Metadata      map[*config.MetadataConfig]interface{}
	Authorization map[*config.AuthorizationConfig]interface{}
}

// NewAuthContext creates an AuthContext instance
func NewAuthContext(parentCtx context.Context, req *envoy_auth.CheckRequest, apiConfig config.APIConfig) AuthContext {

	return AuthContext{
		ParentContext: &parentCtx,
		Request:       req,
		API:           &apiConfig,
		Identity:      make(map[*config.IdentityConfig]interface{}),
		Metadata:      make(map[*config.MetadataConfig]interface{}),
		Authorization: make(map[*config.AuthorizationConfig]interface{}),
	}

}

func (authContext *AuthContext) evaluateAuthConfig(config common.AuthConfigEvaluator, ctx context.Context, respChannel *chan EvaluationResponse, successCallback func(), failureCallback func()) {
	if err := common.CheckContext(ctx); err != nil {
		authCtxLog.Info("Skipping auth config", "config", config, "reason", err)
		return
	}

	if authObj, err := config.Call(authContext, ctx); err != nil {
		*respChannel <- newEvaluationResponse(config, nil, err)

		authCtxLog.Info("Failed to evaluate auth object", "config", config, "error", err)

		if failureCallback != nil {
			failureCallback()
		}
	} else {
		*respChannel <- newEvaluationResponse(config, authObj, nil)

		if successCallback != nil {
			successCallback()
		}
	}
}

type authConfigEvaluationStrategy func(conf common.AuthConfigEvaluator, ctx context.Context, respChannel *chan EvaluationResponse, cancel func())

func (authContext *AuthContext) evaluateAuthConfigs(authConfigs []common.AuthConfigEvaluator, respChannel *chan EvaluationResponse, es authConfigEvaluationStrategy) {
	ctx, cancel := context.WithCancel(*authContext.ParentContext)
	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(len(authConfigs))

	for _, authConfig := range authConfigs {
		objConfig := authConfig
		go func() {
			defer waitGroup.Done()

			es(objConfig, ctx, respChannel, cancel)
		}()
	}

	waitGroup.Wait()
}

func (authContext *AuthContext) evaluateOneAuthConfig(authConfigs []common.AuthConfigEvaluator, respChannel *chan EvaluationResponse) {
	authContext.evaluateAuthConfigs(authConfigs, respChannel, func(conf common.AuthConfigEvaluator, ctx context.Context, respChannel *chan EvaluationResponse, cancel func()) {
		authContext.evaluateAuthConfig(conf, ctx, respChannel, cancel, nil) // cancels the context if at least one thread succeeds
	})
}

func (authContext *AuthContext) evaluateAllAuthConfigs(authConfigs []common.AuthConfigEvaluator, respChannel *chan EvaluationResponse) {
	authContext.evaluateAuthConfigs(authConfigs, respChannel, func(conf common.AuthConfigEvaluator, ctx context.Context, respChannel *chan EvaluationResponse, cancel func()) {
		authContext.evaluateAuthConfig(conf, ctx, respChannel, nil, cancel) // cancels the context if at least one thread fails
	})
}

func (authContext *AuthContext) evaluateAnyAuthConfig(authConfigs []common.AuthConfigEvaluator, respChannel *chan EvaluationResponse) {
	authContext.evaluateAuthConfigs(authConfigs, respChannel, func(conf common.AuthConfigEvaluator, ctx context.Context, respChannel *chan EvaluationResponse, _ func()) {
		authContext.evaluateAuthConfig(conf, ctx, respChannel, nil, nil)
	})
}

func (authContext *AuthContext) evaluateIdentityConfigs() error {
	configs := authContext.API.IdentityConfigs
	respChannel := make(chan EvaluationResponse, len(configs))

	go func() {
		defer close(respChannel)
		authContext.evaluateOneAuthConfig(configs, &respChannel)
	}()

	var lastError error

	for resp := range respChannel {
		conf, _ := resp.Evaluator.(*config.IdentityConfig)
		obj := resp.Object

		if resp.Success() {
			authContext.Identity[conf] = obj
			authCtxLog.Info("Identity", "config", conf, "authObj", obj)
			return nil
		} else {
			lastError = resp.Error
			authCtxLog.Info("Identity", "config", conf, "error", lastError)
		}
	}

	return lastError
}

func (authContext *AuthContext) evaluateMetadataConfigs() {
	configs := authContext.API.MetadataConfigs
	respChannel := make(chan EvaluationResponse, len(configs))

	go func() {
		defer close(respChannel)
		authContext.evaluateAnyAuthConfig(configs, &respChannel)
	}()

	for resp := range respChannel {
		conf, _ := resp.Evaluator.(*config.MetadataConfig)
		obj := resp.Object

		if resp.Success() {
			authContext.Metadata[conf] = obj
			authCtxLog.Info("Metadata", "config", conf, "authObj", obj)
		} else {
			authCtxLog.Info("Metadata", "config", conf, "error", resp.Error)
		}
	}
}

func (authContext *AuthContext) evaluateAuthorizationConfigs() error {
	configs := authContext.API.AuthorizationConfigs
	respChannel := make(chan EvaluationResponse, len(configs))

	go func() {
		defer close(respChannel)
		authContext.evaluateAllAuthConfigs(configs, &respChannel)
	}()

	for resp := range respChannel {
		conf, _ := resp.Evaluator.(*config.AuthorizationConfig)
		obj := resp.Object

		if resp.Success() {
			authContext.Authorization[conf] = obj
			authCtxLog.Info("Authorization", "config", conf, "authObj", obj)
		} else {
			err := resp.Error
			authCtxLog.Info("Authorization", "config", conf, "error", err)
			return err
		}
	}

	return nil
}

// Evaluate evaluates all steps of the auth pipeline (identity → metadata → policy enforcement)
func (authContext *AuthContext) Evaluate() error {
	// identity
	if err := authContext.evaluateIdentityConfigs(); err != nil {
		return err
	}

	// metadata
	authContext.evaluateMetadataConfigs()

	// policy enforcement (authorization)
	if err := authContext.evaluateAuthorizationConfigs(); err != nil {
		return err
	}

	return nil
}

func (authContext *AuthContext) GetParentContext() *context.Context {
	return authContext.ParentContext
}

func (authContext *AuthContext) GetRequest() *envoy_auth.CheckRequest {
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

func (authContext *AuthContext) FindIdentityByName(name string) (interface{}, error) { //TODO: Assign the identity when creating the UserInfo struct and remove this func
	for identityConfig := range authContext.Identity {
		if identityConfig.OIDC != nil && identityConfig.OIDC.Name == name {
			return identityConfig.OIDC, nil
		}
	}
	return nil, fmt.Errorf("cannot find OIDC token")
}
