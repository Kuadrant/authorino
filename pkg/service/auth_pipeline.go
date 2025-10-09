package service

import (
	gojson "encoding/json"
	"fmt"
	"maps"
	"sort"
	"sync"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/context"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/expressions/cel"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/jsonexp"
	"github.com/kuadrant/authorino/pkg/log"
	"github.com/kuadrant/authorino/pkg/metrics"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	gocontext "golang.org/x/net/context"
)

var (
	// evaluator metrics
	authServerEvaluatorTotalMetric     = metrics.NewDynamicCounter("auth_server_evaluator_total", "Total number of evaluations of individual authconfig rule performed by the auth server.")
	authServerEvaluatorCancelledMetric = metrics.NewDynamicCounter("auth_server_evaluator_cancelled", "Number of evaluations of individual authconfig rule cancelled by the auth server.")
	authServerEvaluatorIgnoredMetric   = metrics.NewDynamicCounter("auth_server_evaluator_ignored", "Number of evaluations of individual authconfig rule ignored by the auth server.")
	authServerEvaluatorDeniedMetric    = metrics.NewDynamicCounter("auth_server_evaluator_denied", "Number of denials from individual authconfig rule evaluated by the auth server.")
	authServerEvaluatorDurationMetric  = metrics.NewDynamicHistogram("auth_server_evaluator_duration_seconds", "Response latency of individual authconfig rule evaluated by the auth server (in seconds).")
	// authconfig metrics
	authServerAuthConfigTotalMetric          = metrics.NewDynamicCounter("auth_server_authconfig_total", "Total number of authconfigs enforced by the auth server, partitioned by authconfig.")
	authServerAuthConfigResponseStatusMetric = metrics.NewDynamicCounter("auth_server_authconfig_response_status", "Response status of authconfigs sent by the auth server, partitioned by authconfig.")
	authServerAuthConfigDurationMetric       = metrics.NewDynamicHistogram("auth_server_authconfig_duration_seconds", "Response latency of authconfig enforced by the auth server (in seconds).")
)

func init() {
	metrics.Register(
		authServerEvaluatorTotalMetric,
		authServerEvaluatorCancelledMetric,
		authServerEvaluatorIgnoredMetric,
		authServerEvaluatorDeniedMetric,
		authServerEvaluatorDurationMetric,
		authServerAuthConfigTotalMetric,
		authServerAuthConfigResponseStatusMetric,
		authServerAuthConfigDurationMetric,
	)
}

type EvaluationResponse struct {
	Evaluator auth.AuthConfigEvaluator
	Object    interface{}
	Error     error
}

func (evresp *EvaluationResponse) Success() bool {
	return evresp.Error == nil
}

func (evresp *EvaluationResponse) GetErrorMessage() string {
	return evresp.Error.Error()
}

func newEvaluationResponse(evaluator auth.AuthConfigEvaluator, obj interface{}, err error) EvaluationResponse {
	return EvaluationResponse{
		Evaluator: evaluator,
		Object:    obj,
		Error:     err,
	}
}

// NewAuthPipeline creates an AuthPipeline instance
func NewAuthPipeline(parentCtx gocontext.Context, req *envoy_auth.CheckRequest, authConfig evaluators.AuthConfig) auth.AuthPipeline {
	logger := log.FromContext(parentCtx).WithName("authpipeline")

	return &AuthPipeline{
		Context:       log.IntoContext(parentCtx, logger),
		Request:       req,
		AuthConfig:    &authConfig,
		Identity:      make(map[*evaluators.IdentityConfig]interface{}),
		Metadata:      make(map[*evaluators.MetadataConfig]interface{}),
		Authorization: make(map[*evaluators.AuthorizationConfig]interface{}),
		Response:      make(map[evaluators.ResponseEvaluator]interface{}),
		Callbacks:     make(map[*evaluators.CallbackConfig]interface{}),
		Logger:        logger,
		mu:            sync.RWMutex{},
	}
}

// AuthPipeline evaluates the context of an auth request upon the authconfigs defined for the requested API
// Throughout the pipeline, user identity, ad hoc metadata and authorization policies are evaluated and their
// corresponding resulting objects stored in the respective maps.
type AuthPipeline struct {
	Context    gocontext.Context
	Request    *envoy_auth.CheckRequest
	AuthConfig *evaluators.AuthConfig

	Identity      map[*evaluators.IdentityConfig]interface{}
	Metadata      map[*evaluators.MetadataConfig]interface{}
	Authorization map[*evaluators.AuthorizationConfig]interface{}
	Response      map[evaluators.ResponseEvaluator]interface{}
	Callbacks     map[*evaluators.CallbackConfig]interface{}

	Logger log.Logger

	mu sync.RWMutex
}

func (pipeline *AuthPipeline) evaluateAuthConfig(config auth.AuthConfigEvaluator, ctx gocontext.Context, respChannel *chan EvaluationResponse, successCallback func(), failureCallback func()) {
	monitorable, _ := config.(metrics.Object)

	metrics.ReportMetricWithObject(authServerEvaluatorTotalMetric, monitorable, pipeline.metricLabels())

	if err := context.CheckContext(ctx); err != nil {
		pipeline.Logger.V(1).Info("skipping config", "config", config, "reason", err)
		metrics.ReportMetricWithObject(authServerEvaluatorCancelledMetric, monitorable, pipeline.metricLabels())
		return
	}

	if conditionalEv, ok := config.(auth.ConditionalEvaluator); ok {
		if err := pipeline.evaluateConditions(conditionalEv.GetConditions()); err != nil {
			metrics.ReportMetricWithObject(authServerEvaluatorIgnoredMetric, monitorable, pipeline.metricLabels())
			return
		}
	}

	evaluateFunc := func() {
		if authObj, err := config.Call(pipeline, ctx); err != nil {
			*respChannel <- newEvaluationResponse(config, nil, err)

			metrics.ReportMetricWithObject(authServerEvaluatorDeniedMetric, monitorable, pipeline.metricLabels())

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

	metrics.ReportTimedMetricWithObject(authServerEvaluatorDurationMetric, evaluateFunc, monitorable, pipeline.metricLabels())
}

type authConfigEvaluationStrategy func(conf auth.AuthConfigEvaluator, ctx gocontext.Context, respChannel *chan EvaluationResponse, cancel func())

func (pipeline *AuthPipeline) evaluateAuthConfigs(authConfigs []auth.AuthConfigEvaluator, respChannel *chan EvaluationResponse, evaluate authConfigEvaluationStrategy) {
	ctx, cancel := gocontext.WithCancel(pipeline.Context)
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

func (pipeline *AuthPipeline) evaluateOneAuthConfig(authConfigs []auth.AuthConfigEvaluator, respChannel *chan EvaluationResponse) {
	pipeline.evaluateAuthConfigs(authConfigs, respChannel, func(conf auth.AuthConfigEvaluator, ctx gocontext.Context, respChannel *chan EvaluationResponse, cancel func()) {
		pipeline.evaluateAuthConfig(conf, ctx, respChannel, cancel, nil) // cancels the context if at least one thread succeeds
	})
}

func (pipeline *AuthPipeline) evaluateAllAuthConfigs(authConfigs []auth.AuthConfigEvaluator, respChannel *chan EvaluationResponse) {
	pipeline.evaluateAuthConfigs(authConfigs, respChannel, func(conf auth.AuthConfigEvaluator, ctx gocontext.Context, respChannel *chan EvaluationResponse, cancel func()) {
		pipeline.evaluateAuthConfig(conf, ctx, respChannel, nil, cancel) // cancels the context if at least one thread fails
	})
}

func (pipeline *AuthPipeline) evaluateAnyAuthConfig(authConfigs []auth.AuthConfigEvaluator, respChannel *chan EvaluationResponse) {
	pipeline.evaluateAuthConfigs(authConfigs, respChannel, func(conf auth.AuthConfigEvaluator, ctx gocontext.Context, respChannel *chan EvaluationResponse, _ func()) {
		pipeline.evaluateAuthConfig(conf, ctx, respChannel, nil, nil)
	})
}

func groupAuthConfigsByPriority(authConfigs []auth.AuthConfigEvaluator) (map[int][]auth.AuthConfigEvaluator, []int) {
	priorities := []int{}
	authConfigsByPriority := make(map[int][]auth.AuthConfigEvaluator)

	for _, conf := range authConfigs {
		if prioritizableConfig, ok := conf.(auth.Prioritizable); ok {
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
	authConfigsByPriority, priorities := groupAuthConfigsByPriority(pipeline.AuthConfig.IdentityConfigs)
	count := len(pipeline.AuthConfig.IdentityConfigs)
	errors := make(map[string]string)

	for _, priority := range priorities {
		configs := authConfigsByPriority[priority]
		respChannel := make(chan EvaluationResponse, len(configs))

		go func() {
			defer close(respChannel)
			pipeline.evaluateOneAuthConfig(configs, &respChannel)
		}()

		for resp := range respChannel {
			conf, _ := resp.Evaluator.(*evaluators.IdentityConfig)
			obj := resp.Object

			if resp.Success() {
				// Needs to be done in 2 steps because `IdentityConfigEvaluator.ResolveExtendedProperties()` uses
				// the resolved identity config object already stored in the auth pipeline result, to extend it.
				// Once extended, the identity config object is stored again (replaced) in the auth pipeline result.
				pipeline.setIdentityObj(conf, obj)

				if extendedObj, err := conf.ResolveExtendedProperties(pipeline); err != nil {
					resp.Error = err
					logger.Error(err, "failed to extend identity object", "config", conf, "object", obj)
					if count == 1 {
						return resp
					} else {
						errors[conf.Name] = err.Error()
					}
				} else {
					pipeline.setIdentityObj(conf, extendedObj)

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

	errorsJSON, _ := gojson.Marshal(errors)
	return EvaluationResponse{
		Error: fmt.Errorf("%s", errorsJSON),
	}
}

func (pipeline *AuthPipeline) evaluateMetadataConfigs() {
	logger := pipeline.Logger.WithName("metadata").V(1)
	authConfigsByPriority, priorities := groupAuthConfigsByPriority(pipeline.AuthConfig.MetadataConfigs)

	for _, priority := range priorities {
		configs := authConfigsByPriority[priority]
		respChannel := make(chan EvaluationResponse, len(configs))

		go func() {
			defer close(respChannel)
			pipeline.evaluateAnyAuthConfig(configs, &respChannel)
		}()

		for resp := range respChannel {
			conf, _ := resp.Evaluator.(*evaluators.MetadataConfig)
			obj := resp.Object

			if resp.Success() {
				pipeline.setMetadataObj(conf, obj)
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
		err := gojson.Unmarshal([]byte(pipeline.GetAuthorizationJSON()), &authJSON)
		if err != nil {
			logger.V(1).Error(err, "failed to unmarshal authorization JSON")
		}
		logger.Info("evaluating for input", "input", authJSON)
	}

	authConfigsByPriority, priorities := groupAuthConfigsByPriority(pipeline.AuthConfig.AuthorizationConfigs)

	for _, priority := range priorities {
		configs := authConfigsByPriority[priority]
		respChannel := make(chan EvaluationResponse, len(configs))

		go func() {
			defer close(respChannel)
			pipeline.evaluateAllAuthConfigs(configs, &respChannel)
		}()

		for resp := range respChannel {
			conf, _ := resp.Evaluator.(*evaluators.AuthorizationConfig)
			obj := resp.Object

			if resp.Success() {
				pipeline.setAuthorizationObj(conf, obj)
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
	authConfigsByPriority, priorities := groupAuthConfigsByPriority(pipeline.AuthConfig.ResponseConfigs)

	for _, priority := range priorities {
		configs := authConfigsByPriority[priority]
		respChannel := make(chan EvaluationResponse, len(configs))

		go func() {
			defer close(respChannel)
			pipeline.evaluateAllAuthConfigs(configs, &respChannel)
		}()

		for resp := range respChannel {
			conf, _ := resp.Evaluator.(evaluators.ResponseEvaluator)
			obj := resp.Object

			if resp.Success() {
				pipeline.setResponseObj(conf, obj)
				logger.Info("dynamic response built", "config", conf, "object", obj)
			} else {
				logger.Info("cannot build dynamic response", "config", conf, "reason", resp.Error)
			}
		}
	}
}

func (pipeline *AuthPipeline) executeCallbacks() {
	logger := pipeline.Logger.WithName("callbacks").V(1)
	authConfigsByPriority, priorities := groupAuthConfigsByPriority(pipeline.AuthConfig.CallbackConfigs)

	for _, priority := range priorities {
		configs := authConfigsByPriority[priority]
		respChannel := make(chan EvaluationResponse, len(configs))

		go func() {
			defer close(respChannel)
			pipeline.evaluateAnyAuthConfig(configs, &respChannel)
		}()

		for resp := range respChannel {
			conf, _ := resp.Evaluator.(*evaluators.CallbackConfig)
			obj := resp.Object

			if resp.Success() {
				pipeline.setCallbackObj(conf, obj)
				logger.Info("callback executed", "config", conf, "object", obj)
			} else {
				logger.Info("cannot execute callback", "config", conf, "reason", resp.Error)
			}
		}
	}
}

func (pipeline *AuthPipeline) evaluateConditions(conditions jsonexp.Expression) error {
	if conditions == nil {
		return nil
	}
	if match, err := conditions.Matches(pipeline.GetAuthorizationJSON()); err != nil {
		return err
	} else if !match {
		return fmt.Errorf("unmatching conditions for config")
	}
	return nil
}

func getObjs[T any](m map[*T]interface{}, pipeline *AuthPipeline) map[*T]interface{} {
	pipeline.mu.RLock()
	defer pipeline.mu.RUnlock()
	objs := make(map[*T]interface{})
	for conf, obj := range m {
		objs[conf] = obj
	}
	return objs
}

func (pipeline *AuthPipeline) getIdentityObjs() map[*evaluators.IdentityConfig]interface{} {
	return getObjs(pipeline.Identity, pipeline)
}

func (pipeline *AuthPipeline) setIdentityObj(conf *evaluators.IdentityConfig, obj interface{}) {
	pipeline.mu.Lock()
	defer pipeline.mu.Unlock()
	pipeline.Identity[conf] = obj
}

func (pipeline *AuthPipeline) getMetadataObjs() map[*evaluators.MetadataConfig]interface{} {
	return getObjs(pipeline.Metadata, pipeline)
}

func (pipeline *AuthPipeline) setMetadataObj(conf *evaluators.MetadataConfig, obj interface{}) {
	pipeline.mu.Lock()
	defer pipeline.mu.Unlock()
	pipeline.Metadata[conf] = obj
}

func (pipeline *AuthPipeline) getAuthorizationObjs() map[*evaluators.AuthorizationConfig]interface{} {
	return getObjs(pipeline.Authorization, pipeline)
}

func (pipeline *AuthPipeline) setAuthorizationObj(conf *evaluators.AuthorizationConfig, obj interface{}) {
	pipeline.mu.Lock()
	defer pipeline.mu.Unlock()
	pipeline.Authorization[conf] = obj
}

func (pipeline *AuthPipeline) getResponseObjs() map[evaluators.ResponseEvaluator]interface{} {
	pipeline.mu.RLock()
	defer pipeline.mu.RUnlock()
	objs := make(map[evaluators.ResponseEvaluator]interface{})
	for conf, obj := range pipeline.Response {
		objs[conf] = obj
	}
	return objs
}

func (pipeline *AuthPipeline) setResponseObj(conf evaluators.ResponseEvaluator, obj interface{}) {
	pipeline.mu.Lock()
	defer pipeline.mu.Unlock()
	pipeline.Response[conf] = obj
}

func (pipeline *AuthPipeline) getCallbackObjs() map[*evaluators.CallbackConfig]interface{} {
	return getObjs(pipeline.Callbacks, pipeline)
}

func (pipeline *AuthPipeline) setCallbackObj(conf *evaluators.CallbackConfig, obj interface{}) {
	pipeline.mu.Lock()
	defer pipeline.mu.Unlock()
	pipeline.Callbacks[conf] = obj
}

// Evaluate evaluates all steps of the auth pipeline (identity → metadata → policy enforcement)
func (pipeline *AuthPipeline) Evaluate() auth.AuthResult {
	result := auth.AuthResult{Code: rpc.OK}

	if err := pipeline.evaluateConditions(pipeline.AuthConfig.Conditions); err != nil {
		pipeline.Logger.V(1).Info("skipping", "reason", err)
		return result
	}

	metrics.ReportMetric(authServerAuthConfigTotalMetric, pipeline.metricLabels())

	authResult := make(chan auth.AuthResult)

	go func() {
		defer close(authResult)

		evaluateFunc := func() {
			// phase 1: identity verification
			if resp := pipeline.evaluateIdentityConfigs(); !resp.Success() {
				result.Code = rpc.UNAUTHENTICATED
				result.Message = resp.GetErrorMessage()
				result.Headers = pipeline.AuthConfig.GetChallengeHeaders()
				result = pipeline.customizeDenyWith(result, pipeline.AuthConfig.Unauthenticated)
			} else {
				// phase 2: external metadata
				pipeline.evaluateMetadataConfigs()

				// phase 3: policy enforcement (authorization)
				if resp := pipeline.evaluateAuthorizationConfigs(); !resp.Success() {
					result.Code = rpc.PERMISSION_DENIED
					result.Message = resp.GetErrorMessage()
					result = pipeline.customizeDenyWith(result, pipeline.AuthConfig.Unauthorized)
				} else {
					// phase 4: response
					pipeline.evaluateResponseConfigs()
					responseHeaders := make(map[string]auth.HeaderValue, 0)
					responseMetadata := make(map[string]any, 0)
					for ev, obj := range pipeline.Response {
						if _, ok := ev.(*evaluators.HeaderSuccessResponseEvaluator); ok {
							responseHeaders[ev.GetKey()] = obj.(auth.HeaderValue)
							continue
						}
						responseMetadata[ev.GetKey()] = obj
					}
					result.Headers = []map[string]auth.HeaderValue{responseHeaders}
					result.Metadata = responseMetadata
				}
			}

			// phase 5: callbacks
			pipeline.executeCallbacks()

			pipeline.reportStatusMetric(result.Code)
			authResult <- result
		}

		metrics.ReportTimedMetric(authServerAuthConfigDurationMetric, evaluateFunc, pipeline.metricLabels())
	}()

	return <-authResult
}

func (pipeline *AuthPipeline) reportStatusMetric(rpcStatusCode rpc.Code) {
	metrics.ReportMetricWithStatus(authServerAuthConfigResponseStatusMetric, rpc.Code_name[int32(rpcStatusCode)], pipeline.metricLabels())
}

func (pipeline *AuthPipeline) metricLabels() map[string]string {
	labels := maps.Clone(pipeline.AuthConfig.Labels)
	if labels == nil {
		labels = make(map[string]string)
	}

	// Check for custom labels via the heuristic path
	filteredMetadata := pipeline.GetRequest().GetAttributes().GetMetadataContext().GetFilterMetadata()
	if customLabels, ok := filteredMetadata["io.kuadrant.metrics.labels"]; ok {
		for k, v := range customLabels.Fields {
			switch kind := v.Kind.(type) {
			case *structpb.Value_StringValue:
				// Just a plain string, treat it as already evaluated
				labels[k] = kind.StringValue

			case *structpb.Value_NumberValue:
				labels[k] = fmt.Sprintf("%v", kind.NumberValue)

			case *structpb.Value_BoolValue:
				labels[k] = fmt.Sprintf("%v", kind.BoolValue)

			case *structpb.Value_StructValue:
				// Could be a CEL expression wrapper { "cel_expr": "<expr>" }
				if celExprField, ok := kind.StructValue.Fields["cel_expr"]; ok {
					if exprStr := celExprField.GetStringValue(); exprStr != "" {
						expr, err := cel.NewExpression(exprStr)
						if err != nil {
							pipeline.Logger.Error(err, "failed to parse CEL expression", "expression", exprStr)
							continue
						}
						value, err := expr.ResolveFor(pipeline.GetAuthorizationJSON())
						if err != nil {
							pipeline.Logger.Error(err, "failed to evaluate CEL expression", "expression", exprStr)
							continue
						}
						labels[k] = fmt.Sprintf("%v", value)
					}
				}

			default:
				pipeline.Logger.V(1).Info("unexpected value kind", "kind", kind)
			}
		}
	}

	return labels
}

func (pipeline *AuthPipeline) GetRequest() *envoy_auth.CheckRequest {
	return pipeline.Request
}

func (pipeline *AuthPipeline) GetHttp() *envoy_auth.AttributeContext_HttpRequest {
	return pipeline.Request.Attributes.Request.Http
}

func (pipeline *AuthPipeline) GetAPI() interface{} {
	return pipeline.AuthConfig
}

func (pipeline *AuthPipeline) GetResolvedIdentity() (interface{}, interface{}) {
	for identityConfig, identityObj := range pipeline.getIdentityObjs() {
		if identityObj != nil {
			id := identityConfig
			obj := identityObj
			return id, obj
		}
	}
	return nil, nil
}

type authorizationJSON struct {
	// Deprecated: Use WellKnownAttributes instead.
	Context              *envoy_auth.AttributeContext `json:"context"`
	*WellKnownAttributes `json:""`
}

func (pipeline *AuthPipeline) GetAuthorizationJSON() string {
	authData := make(map[string]interface{})

	// identity
	_, authData["identity"] = pipeline.GetResolvedIdentity()

	// metadata
	metadata := make(map[string]interface{})
	for config, obj := range pipeline.getMetadataObjs() {
		metadata[config.Name] = obj
	}
	authData["metadata"] = metadata

	// authorization
	authorization := make(map[string]interface{})
	for config, obj := range pipeline.getAuthorizationObjs() {
		authorization[config.Name] = obj
	}
	authData["authorization"] = authorization

	// response
	response := make(map[string]interface{})
	for config, obj := range pipeline.getResponseObjs() {
		response[config.GetResponseConfig().Name] = obj
	}
	authData["response"] = response

	// callbacks
	callbacks := make(map[string]interface{})
	for config, obj := range pipeline.getCallbackObjs() {
		callbacks[config.Name] = obj
	}
	if len(callbacks) > 0 {
		authData["callbacks"] = callbacks
	}

	return NewAuthorizationJSON(pipeline.GetRequest(), authData)
}

func (pipeline *AuthPipeline) customizeDenyWith(authResult auth.AuthResult, denyWith *evaluators.DenyWithValues) auth.AuthResult {
	if denyWith != nil {
		if denyWith.Code != 0 {
			authResult.Status = envoy_type.StatusCode(denyWith.Code)
		}

		authJSON := pipeline.GetAuthorizationJSON()

		if denyWith.Message != nil {
			resolved, _ := denyWith.Message.ResolveFor(authJSON)
			authResult.Message, _ = json.StringifyJSON(resolved)
		}

		if denyWith.Body != nil {
			resolved, _ := denyWith.Body.ResolveFor(authJSON)
			authResult.Body, _ = json.StringifyJSON(resolved)
		}

		if len(denyWith.Headers) > 0 {
			headers := make([]map[string]auth.HeaderValue, 0)
			for _, header := range denyWith.Headers {
				resolved, _ := header.Value.ResolveFor(authJSON)
				value, _ := json.StringifyJSON(resolved)
				headers = append(headers, map[string]auth.HeaderValue{header.Name: {Value: value}})
			}
			authResult.Headers = headers
		}
	}

	return authResult
}

func NewAuthorizationJSON(request *envoy_auth.CheckRequest, authPipeline map[string]any) string {
	authJSON, _ := gojson.Marshal(&authorizationJSON{
		Context:             request.Attributes,
		WellKnownAttributes: NewWellKnownAttributes(request.Attributes, authPipeline),
	})
	return string(authJSON)
}
