package service

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/config"
	"github.com/kuadrant/authorino/pkg/config/identity"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/gogo/googleapis/google/rpc"
	"golang.org/x/net/context"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	authCtxLog = ctrl.Log.WithName("Authorino").WithName("AuthPipeline")
)

type EvaluationResponse struct {
	Evaluator common.AuthConfigEvaluator
	Object    interface{}
	Error     error
}

func (evresp *EvaluationResponse) Success() bool {
	return evresp.Error == nil
}

func (evresp *EvaluationResponse) GetErrorMessage() string {
	return evresp.Error.Error()
}

func newEvaluationResponse(evaluator common.AuthConfigEvaluator, obj interface{}, err error) EvaluationResponse {
	return EvaluationResponse{
		Evaluator: evaluator,
		Object:    obj,
		Error:     err,
	}
}

type AuthResult struct {
	Code    rpc.Code
	Message string
	Headers []map[string]string
}

func (result *AuthResult) Success() bool {
	return result.Code == rpc.OK
}

// AuthPipeline evaluates the context of an auth request upon the auth configs defined for the requested API
// Throughout the pipeline, user identity, ad hoc metadata and authorization policies are evaluated and their
// corresponding resulting objects stored in the respective maps.
type AuthPipeline struct {
	ParentContext *context.Context
	Request       *envoy_auth.CheckRequest
	API           *config.APIConfig

	Identity      map[*config.IdentityConfig]interface{}
	Metadata      map[*config.MetadataConfig]interface{}
	Authorization map[*config.AuthorizationConfig]interface{}
}

// NewAuthPipeline creates an AuthPipeline instance
func NewAuthPipeline(parentCtx context.Context, req *envoy_auth.CheckRequest, apiConfig config.APIConfig) AuthPipeline {
	return AuthPipeline{
		ParentContext: &parentCtx,
		Request:       req,
		API:           &apiConfig,
		Identity:      make(map[*config.IdentityConfig]interface{}),
		Metadata:      make(map[*config.MetadataConfig]interface{}),
		Authorization: make(map[*config.AuthorizationConfig]interface{}),
	}
}

func (pipeline *AuthPipeline) evaluateAuthConfig(config common.AuthConfigEvaluator, ctx context.Context, respChannel *chan EvaluationResponse, successCallback func(), failureCallback func()) {
	if err := common.CheckContext(ctx); err != nil {
		authCtxLog.Info("Skipping auth config", "config", config, "reason", err)
		return
	}

	if authObj, err := config.Call(pipeline, ctx); err != nil {
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

func (pipeline *AuthPipeline) evaluateAuthConfigs(authConfigs []common.AuthConfigEvaluator, respChannel *chan EvaluationResponse, evaluate authConfigEvaluationStrategy) {
	ctx, cancel := context.WithCancel(*pipeline.ParentContext)
	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(len(authConfigs))

	for _, authConfig := range authConfigs {
		objConfig := authConfig
		go func() {
			defer waitGroup.Done()
			evaluate(objConfig, ctx, respChannel, cancel)
		}()
	}

	waitGroup.Wait()
}

func (pipeline *AuthPipeline) evaluateOneAuthConfig(authConfigs []common.AuthConfigEvaluator, respChannel *chan EvaluationResponse) {
	pipeline.evaluateAuthConfigs(authConfigs, respChannel, func(conf common.AuthConfigEvaluator, ctx context.Context, respChannel *chan EvaluationResponse, cancel func()) {
		pipeline.evaluateAuthConfig(conf, ctx, respChannel, cancel, nil) // cancels the context if at least one thread succeeds
	})
}

func (pipeline *AuthPipeline) evaluateAllAuthConfigs(authConfigs []common.AuthConfigEvaluator, respChannel *chan EvaluationResponse) {
	pipeline.evaluateAuthConfigs(authConfigs, respChannel, func(conf common.AuthConfigEvaluator, ctx context.Context, respChannel *chan EvaluationResponse, cancel func()) {
		pipeline.evaluateAuthConfig(conf, ctx, respChannel, nil, cancel) // cancels the context if at least one thread fails
	})
}

func (pipeline *AuthPipeline) evaluateAnyAuthConfig(authConfigs []common.AuthConfigEvaluator, respChannel *chan EvaluationResponse) {
	pipeline.evaluateAuthConfigs(authConfigs, respChannel, func(conf common.AuthConfigEvaluator, ctx context.Context, respChannel *chan EvaluationResponse, _ func()) {
		pipeline.evaluateAuthConfig(conf, ctx, respChannel, nil, nil)
	})
}

func (pipeline *AuthPipeline) evaluateIdentityConfigs() EvaluationResponse {
	configs := pipeline.API.IdentityConfigs
	count := len(configs)
	respChannel := make(chan EvaluationResponse, count)

	go func() {
		defer close(respChannel)
		pipeline.evaluateOneAuthConfig(configs, &respChannel)
	}()

	errors := make(map[string]string)

	for resp := range respChannel {
		conf, _ := resp.Evaluator.(*config.IdentityConfig)
		obj := resp.Object

		if resp.Success() {
			pipeline.Identity[conf] = obj
			authCtxLog.Info("Identity", "config", conf, "authObj", obj)
			return resp
		} else {
			err := resp.Error
			authCtxLog.Info("Identity", "config", conf, "error", err)
			if count == 1 {
				return resp
			} else {
				errors[conf.Name] = err.Error()
			}
		}
	}

	errorsJSON, _ := json.Marshal(errors)
	return EvaluationResponse{
		Error: fmt.Errorf("%s", errorsJSON),
	}
}

func (pipeline *AuthPipeline) evaluateMetadataConfigs() {
	configs := pipeline.API.MetadataConfigs
	respChannel := make(chan EvaluationResponse, len(configs))

	go func() {
		defer close(respChannel)
		pipeline.evaluateAnyAuthConfig(configs, &respChannel)
	}()

	for resp := range respChannel {
		conf, _ := resp.Evaluator.(*config.MetadataConfig)
		obj := resp.Object

		if resp.Success() {
			pipeline.Metadata[conf] = obj
			authCtxLog.Info("Metadata", "config", conf, "authObj", obj)
		} else {
			authCtxLog.Info("Metadata", "config", conf, "error", resp.Error)
		}
	}
}

func (pipeline *AuthPipeline) evaluateAuthorizationConfigs() EvaluationResponse {
	configs := pipeline.API.AuthorizationConfigs
	respChannel := make(chan EvaluationResponse, len(configs))

	go func() {
		defer close(respChannel)
		pipeline.evaluateAllAuthConfigs(configs, &respChannel)
	}()

	for resp := range respChannel {
		conf, _ := resp.Evaluator.(*config.AuthorizationConfig)
		obj := resp.Object

		if resp.Success() {
			pipeline.Authorization[conf] = obj
			authCtxLog.Info("Authorization", "config", conf, "authObj", obj)
		} else {
			authCtxLog.Info("Authorization", "config", conf, "error", resp.Error)
			return resp
		}
	}

	return EvaluationResponse{}
}

func (pipeline *AuthPipeline) issueWristband() EvaluationResponse {
	wristbandIssuer := pipeline.API.Wristband

	if wristbandIssuer == nil {
		return EvaluationResponse{}
	}

	resolvedIdentity, _ := pipeline.GetResolvedIdentity()
	identityEvaluator, _ := resolvedIdentity.(common.IdentityConfigEvaluator)
	if resolvedOIDC, _ := identityEvaluator.GetOIDC().(*identity.OIDC); resolvedOIDC != nil && resolvedOIDC.Endpoint == wristbandIssuer.GetIssuer() {
		return EvaluationResponse{}
	}

	if wristband, err := wristbandIssuer.Call(pipeline, *pipeline.ParentContext); err != nil {
		authCtxLog.Error(err, "Failed to issue wristband")

		return EvaluationResponse{
			Error: err,
		}
	} else {
		return EvaluationResponse{
			Evaluator: wristbandIssuer,
			Object:    wristband,
		}
	}
}

// Evaluate evaluates all steps of the auth pipeline (identity → metadata → policy enforcement)
func (pipeline *AuthPipeline) Evaluate() AuthResult {
	// identity
	if resp := pipeline.evaluateIdentityConfigs(); !resp.Success() {
		return AuthResult{
			Code:    rpc.UNAUTHENTICATED,
			Message: resp.GetErrorMessage(),
			Headers: pipeline.API.GetChallengeHeaders(),
		}
	}

	// metadata
	pipeline.evaluateMetadataConfigs()

	// policy enforcement (authorization)
	if resp := pipeline.evaluateAuthorizationConfigs(); !resp.Success() {
		return AuthResult{
			Code:    rpc.PERMISSION_DENIED,
			Message: resp.GetErrorMessage(),
		}
	}

	// wristband
	wristbandHeader := make(map[string]string)
	if wristband := pipeline.issueWristband().Object; wristband != nil {
		wristbandHeader[X_EXT_AUTH_WRISTBAND] = fmt.Sprintf("%v", wristband)
	}

	return AuthResult{
		Code:    rpc.OK,
		Headers: []map[string]string{wristbandHeader},
	}
}

func (pipeline *AuthPipeline) GetParentContext() *context.Context {
	return pipeline.ParentContext
}

func (pipeline *AuthPipeline) GetRequest() *envoy_auth.CheckRequest {
	return pipeline.Request
}

func (pipeline *AuthPipeline) GetHttp() *envoy_auth.AttributeContext_HttpRequest {
	return pipeline.Request.Attributes.Request.Http
}

func (pipeline *AuthPipeline) GetAPI() interface{} {
	return pipeline.API
}

func (pipeline *AuthPipeline) GetResolvedIdentity() (interface{}, interface{}) {
	for identityConfig, identityObj := range pipeline.Identity {
		if identityObj != nil {
			id := identityConfig
			obj := identityObj
			return id, obj
		}
	}
	return nil, nil
}

func (pipeline *AuthPipeline) GetResolvedMetadata() map[interface{}]interface{} {
	m := make(map[interface{}]interface{})
	for metadataCfg, metadataObj := range pipeline.Metadata {
		if metadataObj != nil {
			m[metadataCfg] = metadataObj
		}
	}
	return m
}

func (pipeline *AuthPipeline) GetDataForAuthorization() interface{} {
	authData := make(map[string]interface{})
	_, authData["identity"] = pipeline.GetResolvedIdentity()

	resolvedMetadata := make(map[string]interface{})
	for config, obj := range pipeline.GetResolvedMetadata() {
		metadataConfig, _ := config.(common.NamedConfigEvaluator)
		resolvedMetadata[metadataConfig.GetName()] = obj
	}
	authData["metadata"] = resolvedMetadata

	type authorizationData struct {
		Context  *envoy_auth.AttributeContext `json:"context"`
		AuthData map[string]interface{}       `json:"auth"`
	}

	return &authorizationData{
		Context:  pipeline.GetRequest().Attributes,
		AuthData: authData,
	}
}
