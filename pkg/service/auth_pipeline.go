package service

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/config"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"golang.org/x/net/context"
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

// NewAuthPipeline creates an AuthPipeline instance
func NewAuthPipeline(parentCtx context.Context, req *envoy_auth.CheckRequest, apiConfig config.APIConfig) common.AuthPipeline {
	logger := log.FromContext(parentCtx).WithName("authpipeline")

	return &AuthPipeline{
		Context:       log.IntoContext(parentCtx, logger),
		Request:       req,
		API:           &apiConfig,
		Identity:      make(map[*config.IdentityConfig]interface{}),
		Metadata:      make(map[*config.MetadataConfig]interface{}),
		Authorization: make(map[*config.AuthorizationConfig]interface{}),
		Response:      make(map[*config.ResponseConfig]interface{}),
		Logger:        logger,
	}
}

// AuthPipeline evaluates the context of an auth request upon the authconfigs defined for the requested API
// Throughout the pipeline, user identity, ad hoc metadata and authorization policies are evaluated and their
// corresponding resulting objects stored in the respective maps.
type AuthPipeline struct {
	Context context.Context
	Request *envoy_auth.CheckRequest
	API     *config.APIConfig

	Identity      map[*config.IdentityConfig]interface{}
	Metadata      map[*config.MetadataConfig]interface{}
	Authorization map[*config.AuthorizationConfig]interface{}
	Response      map[*config.ResponseConfig]interface{}

	Logger log.Logger
}

func (pipeline *AuthPipeline) evaluateAuthConfig(config common.AuthConfigEvaluator, ctx context.Context, respChannel *chan EvaluationResponse, successCallback func(), failureCallback func()) {
	if err := common.CheckContext(ctx); err != nil {
		pipeline.Logger.V(1).Info("skipping config", "config", config, "reason", err)
		return
	}

	if authObj, err := config.Call(pipeline, ctx); err != nil {
		*respChannel <- newEvaluationResponse(config, nil, err)

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
	ctx, cancel := context.WithCancel(pipeline.Context)
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

func groupAuthConfigsByPriority(authConfigs []common.AuthConfigEvaluator) (map[int][]common.AuthConfigEvaluator, []int) {
	priorities := []int{}
	authConfigsByPriority := make(map[int][]common.AuthConfigEvaluator)

	for _, conf := range authConfigs {
		if prioritizableConfig, ok := conf.(common.Prioritizable); ok {
			priority := prioritizableConfig.GetPriority()
			if _, exists := authConfigsByPriority[priority]; !exists {
				priorities = append(priorities, priority)
			}
			authConfigsByPriority[priority] = append(authConfigsByPriority[priority], conf)
		}
	}

	sort.Ints(priorities)

	return authConfigsByPriority, priorities
}

func (pipeline *AuthPipeline) evaluateIdentityConfigs() EvaluationResponse {
	logger := pipeline.Logger.WithName("identity").V(1)
	authConfigsByPriority, priorities := groupAuthConfigsByPriority(pipeline.API.IdentityConfigs)
	count := len(pipeline.API.IdentityConfigs)
	errors := make(map[string]string)

	for _, priority := range priorities {
		configs := authConfigsByPriority[priority]
		respChannel := make(chan EvaluationResponse, len(configs))

		go func() {
			defer close(respChannel)
			pipeline.evaluateOneAuthConfig(configs, &respChannel)
		}()

		for resp := range respChannel {
			conf, _ := resp.Evaluator.(*config.IdentityConfig)
			obj := resp.Object

			if resp.Success() {
				// Needs to be done in 2 steps because `IdentityConfigEvaluator.ResolveExtendedProperties()` uses
				// the resolved identity config object already stored in the auth pipeline result, to extend it.
				// Once extended, the identity config object is stored again (replaced) in the auth pipeline result.
				pipeline.Identity[conf] = obj

				if extendedObj, err := conf.ResolveExtendedProperties(pipeline); err != nil {
					resp.Error = err
					logger.Error(err, "failed to extend identity object", "config", conf, "object", obj)
					if count == 1 {
						return resp
					} else {
						errors[conf.Name] = err.Error()
					}
				} else {
					pipeline.Identity[conf] = extendedObj

					logger.Info("identity validated", "config", conf, "object", extendedObj)
					return resp
				}
			} else {
				err := resp.Error
				logger.Info("cannot validate identity", "config", conf, "reason", err)
				if count == 1 {
					return resp
				} else {
					errors[conf.Name] = err.Error()
				}
			}
		}
	}

	errorsJSON, _ := json.Marshal(errors)
	return EvaluationResponse{
		Error: fmt.Errorf("%s", errorsJSON),
	}
}

func (pipeline *AuthPipeline) evaluateMetadataConfigs() {
	logger := pipeline.Logger.WithName("metadata").V(1)
	authConfigsByPriority, priorities := groupAuthConfigsByPriority(pipeline.API.MetadataConfigs)

	for _, priority := range priorities {
		configs := authConfigsByPriority[priority]
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
				logger.Info("fetched auth metadata", "config", conf, "object", obj)
			} else {
				logger.Info("cannot fetch metadata", "config", conf, "reason", resp.Error)
			}
		}
	}
}

func (pipeline *AuthPipeline) evaluateAuthorizationConfigs() EvaluationResponse {
	logger := pipeline.Logger.WithName("authorization").V(1)

	if logger.Enabled() {
		var authJSON interface{}
		json.Unmarshal([]byte(pipeline.GetAuthorizationJSON()), &authJSON)
		logger.Info("evaluating for input", "input", authJSON)
	}

	authConfigsByPriority, priorities := groupAuthConfigsByPriority(pipeline.API.AuthorizationConfigs)

	for _, priority := range priorities {
		configs := authConfigsByPriority[priority]
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
				logger.Info("access granted", "config", conf, "object", obj)
			} else {
				logger.Info("access denied", "config", conf, "reason", resp.Error)
				return resp
			}
		}
	}

	return EvaluationResponse{}
}

func (pipeline *AuthPipeline) evaluateResponseConfigs() {
	logger := pipeline.Logger.WithName("response").V(1)
	authConfigsByPriority, priorities := groupAuthConfigsByPriority(pipeline.API.ResponseConfigs)

	for _, priority := range priorities {
		configs := authConfigsByPriority[priority]
		respChannel := make(chan EvaluationResponse, len(configs))

		go func() {
			defer close(respChannel)
			pipeline.evaluateAllAuthConfigs(configs, &respChannel)
		}()

		for resp := range respChannel {
			conf, _ := resp.Evaluator.(*config.ResponseConfig)
			obj := resp.Object

			if resp.Success() {
				pipeline.Response[conf] = obj
				logger.Info("dynamic response built", "config", conf, "object", obj)
			} else {
				logger.Info("cannot build dynamic response", "config", conf, "reason", resp.Error)
			}
		}
	}
}

// Evaluate evaluates all steps of the auth pipeline (identity → metadata → policy enforcement)
func (pipeline *AuthPipeline) Evaluate() common.AuthResult {
	// phase 1: identity verification
	if resp := pipeline.evaluateIdentityConfigs(); !resp.Success() {
		return pipeline.customizeDenyWith(common.AuthResult{
			Code:    rpc.UNAUTHENTICATED,
			Message: resp.GetErrorMessage(),
			Headers: pipeline.API.GetChallengeHeaders(),
		}, pipeline.API.Unauthenticated)
	}

	// phase 2: external metadata
	pipeline.evaluateMetadataConfigs()

	// phase 3: policy enforcement (authorization)
	if resp := pipeline.evaluateAuthorizationConfigs(); !resp.Success() {
		return pipeline.customizeDenyWith(common.AuthResult{
			Code:    rpc.PERMISSION_DENIED,
			Message: resp.GetErrorMessage(),
		}, pipeline.API.Unauthorized)
	}

	// phase 4: response
	pipeline.evaluateResponseConfigs()

	// auth result
	responseHeaders, responseMetadata := config.WrapResponses(pipeline.Response)
	return common.AuthResult{
		Code:     rpc.OK,
		Headers:  []map[string]string{responseHeaders},
		Metadata: responseMetadata,
	}
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

type authorizationJSON struct {
	Context  *envoy_auth.AttributeContext `json:"context"`
	AuthData map[string]interface{}       `json:"auth"`
}

func (pipeline *AuthPipeline) GetAuthorizationJSON() string {
	authData := make(map[string]interface{})

	// identity
	_, authData["identity"] = pipeline.GetResolvedIdentity()

	// metadata
	metadata := make(map[string]interface{})
	for config, obj := range pipeline.Metadata {
		metadata[config.Name] = obj
	}
	authData["metadata"] = metadata

	// authorization
	authorization := make(map[string]interface{})
	for config, obj := range pipeline.Authorization {
		authorization[config.Name] = obj
	}
	authData["authorization"] = authorization

	// response
	response := make(map[string]interface{})
	for config, obj := range pipeline.Response {
		response[config.Name] = obj
	}
	authData["response"] = response

	authJSON, _ := json.Marshal(&authorizationJSON{
		Context:  pipeline.GetRequest().Attributes,
		AuthData: authData,
	})

	return string(authJSON)
}

func (pipeline *AuthPipeline) customizeDenyWith(authResult common.AuthResult, denyWith *config.DenyWithValues) common.AuthResult {
	if denyWith != nil {
		if denyWith.Code != 0 {
			authResult.Status = envoy_type.StatusCode(denyWith.Code)
		}

		if denyWith.Message != "" {
			authResult.Message = denyWith.Message
		}

		authJSON := pipeline.GetAuthorizationJSON()

		if len(denyWith.Headers) > 0 {
			headers := make([]map[string]string, 0)
			for _, header := range denyWith.Headers {
				value, _ := common.StringifyJSON(header.Value.ResolveFor(authJSON))
				headers = append(headers, map[string]string{header.Name: value})
			}
			authResult.Headers = headers
		}
	}

	return authResult
}
