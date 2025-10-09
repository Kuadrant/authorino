package evaluators

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators/response"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/jsonexp"
	"github.com/kuadrant/authorino/pkg/log"
)

const (
	responseWristband = "RESPONSE_WRISTBAND"
	responseJSON      = "RESPONSE_JSON"
	responsePlain     = "RESPONSE_PLAIN"
)

type ResponseEvaluator interface {
	GetResponseConfig() *ResponseConfig
	GetName() string
	GetType() string
	GetKey() string
	SetCache(EvaluatorCache)
}

type HeaderSuccessResponseEvaluator struct {
	*ResponseConfig
	Key    string
	Action auth.HeaderAction
}

func (e *HeaderSuccessResponseEvaluator) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	obj, err := e.ResponseConfig.Call(pipeline, ctx)
	if err != nil {
		return obj, err
	}
	return e.wrapObjectAsHeaderValue(obj), nil
}

func (e *HeaderSuccessResponseEvaluator) GetName() string {
	return e.ResponseConfig.GetName()
}

func (e *HeaderSuccessResponseEvaluator) GetType() string {
	return e.ResponseConfig.GetType()
}

func (e *HeaderSuccessResponseEvaluator) GetPriority() int {
	return e.ResponseConfig.GetPriority()
}

func (e *HeaderSuccessResponseEvaluator) GetConditions() jsonexp.Expression {
	return e.ResponseConfig.GetConditions()
}

func (e *HeaderSuccessResponseEvaluator) GetWristbandIssuer() auth.WristbandIssuer {
	return e.ResponseConfig.GetWristbandIssuer()
}

func (e *HeaderSuccessResponseEvaluator) MetricsEnabled() bool {
	return e.ResponseConfig.MetricsEnabled()
}

func (e *HeaderSuccessResponseEvaluator) GetResponseConfig() *ResponseConfig {
	return e.ResponseConfig
}

func (e *HeaderSuccessResponseEvaluator) GetKey() string {
	if e.Key != "" {
		return e.Key
	}
	return e.ResponseConfig.Name
}

func (e *HeaderSuccessResponseEvaluator) SetCache(cache EvaluatorCache) {
	e.Cache = cache
}

func (e *HeaderSuccessResponseEvaluator) wrapObjectAsHeaderValue(obj any) auth.HeaderValue {
	var value string
	switch e.GetType() {
	case responseJSON, responseWristband:
		j, _ := json.StringifyJSON(obj)
		value = j
	default:
		value = fmt.Sprintf("%v", obj)
	}
	return auth.HeaderValue{Value: value, Action: e.Action}
}

type DynamicMetadataSuccessResponseEvaluator struct {
	*ResponseConfig
	Key string
}

func (e *DynamicMetadataSuccessResponseEvaluator) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	return e.ResponseConfig.Call(pipeline, ctx)
}

func (e *DynamicMetadataSuccessResponseEvaluator) GetName() string {
	return e.ResponseConfig.GetName()
}

func (e *DynamicMetadataSuccessResponseEvaluator) GetType() string {
	return e.ResponseConfig.GetType()
}

func (e *DynamicMetadataSuccessResponseEvaluator) GetPriority() int {
	return e.ResponseConfig.GetPriority()
}

func (e *DynamicMetadataSuccessResponseEvaluator) GetConditions() jsonexp.Expression {
	return e.ResponseConfig.GetConditions()
}

func (e *DynamicMetadataSuccessResponseEvaluator) GetWristbandIssuer() auth.WristbandIssuer {
	return e.ResponseConfig.GetWristbandIssuer()
}

func (e *DynamicMetadataSuccessResponseEvaluator) MetricsEnabled() bool {
	return e.ResponseConfig.MetricsEnabled()
}

func (e *DynamicMetadataSuccessResponseEvaluator) GetResponseConfig() *ResponseConfig {
	return e.ResponseConfig
}

func (e *DynamicMetadataSuccessResponseEvaluator) GetKey() string {
	if e.Key != "" {
		return e.Key
	}
	return e.ResponseConfig.Name
}

func (e *DynamicMetadataSuccessResponseEvaluator) SetCache(cache EvaluatorCache) {
	e.Cache = cache
}

type ResponseConfig struct {
	Name       string             `yaml:"name"`
	Priority   int                `yaml:"priority"`
	Conditions jsonexp.Expression `yaml:"conditions"`
	Metrics    bool               `yaml:"metrics"`
	Cache      EvaluatorCache

	Wristband   auth.WristbandIssuer  `yaml:"wristband,omitempty"`
	DynamicJSON *response.DynamicJSON `yaml:"json,omitempty"`
	Plain       *response.Plain       `yaml:"plain,omitempty"`
}

func (config *ResponseConfig) GetAuthConfigEvaluator() auth.AuthConfigEvaluator {
	switch config.GetType() {
	case responseWristband:
		return config.Wristband
	case responseJSON:
		return config.DynamicJSON
	case responsePlain:
		return config.Plain
	default:
		return nil
	}
}

// impl:AuthConfigEvaluator

func (config *ResponseConfig) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	if evaluator := config.GetAuthConfigEvaluator(); evaluator == nil {
		return nil, fmt.Errorf("invalid response config")
	} else {
		logger := log.FromContext(ctx).WithName("response")

		cache := config.Cache
		var cacheKey interface{}

		if cache != nil {
			cacheKey, _ = cache.ResolveKeyFor(pipeline.GetAuthorizationJSON())
			if cacheKey != nil {
				if cachedObj, err := cache.Get(cacheKey); err != nil {
					logger.V(1).Error(err, "failed to retrieve data from the cache")
				} else if cachedObj != nil {
					return cachedObj, nil
				}
			}
		}

		obj, err := evaluator.Call(pipeline, log.IntoContext(ctx, logger))

		if err == nil && cacheKey != nil {
			if err := cache.Set(cacheKey, obj); err != nil {
				logger.V(1).Info("unable to store data in the cache", "err", err)
			}
		}

		return obj, err
	}
}

// impl:NamedEvaluator

func (config *ResponseConfig) GetName() string {
	return config.Name
}

// impl:TypedEvaluator

func (config *ResponseConfig) GetType() string {
	switch {
	case config.Wristband != nil:
		return responseWristband
	case config.DynamicJSON != nil:
		return responseJSON
	case config.Plain != nil:
		return responsePlain
	default:
		return ""
	}
}

// impl:Prioritizable

func (config *ResponseConfig) GetPriority() int {
	return config.Priority
}

// impl:ConditionalEvaluator

func (config *ResponseConfig) GetConditions() jsonexp.Expression {
	return config.Conditions
}

// impl:ResponseConfigEvaluator

func (config *ResponseConfig) GetWristbandIssuer() auth.WristbandIssuer {
	return config.Wristband
}

// impl:metrics.Object

func (config *ResponseConfig) MetricsEnabled() bool {
	return config.Metrics
}
