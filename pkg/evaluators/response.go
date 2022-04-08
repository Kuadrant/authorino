package evaluators

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators/response"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/log"
)

const (
	responseWristband = "RESPONSE_WRISTBAND"
	responseJSON      = "RESPONSE_JSON"

	HTTP_HEADER_WRAPPER            = "httpHeader"
	ENVOY_DYNAMIC_METADATA_WRAPPER = "envoyDynamicMetadata"

	DEFAULT_WRAPPER = HTTP_HEADER_WRAPPER
)

func NewResponseConfig(name string, priority int, conditions []json.JSONPatternMatchingRule, wrapper string, wrapperKey string, metricsEnabled bool) *ResponseConfig {
	responseConfig := ResponseConfig{
		Name:       name,
		Priority:   priority,
		Conditions: conditions,
		Wrapper:    DEFAULT_WRAPPER,
		WrapperKey: name,
		Metrics:    metricsEnabled,
	}

	if wrapper != "" {
		responseConfig.Wrapper = wrapper
	}

	if wrapperKey != "" {
		responseConfig.WrapperKey = wrapperKey
	}

	return &responseConfig
}

type ResponseConfig struct {
	Name       string                         `yaml:"name"`
	Priority   int                            `yaml:"priority"`
	Conditions []json.JSONPatternMatchingRule `yaml:"conditions"`
	Wrapper    string                         `yaml:"wrapper"`
	WrapperKey string                         `yaml:"wrapperKey"`
	Metrics    bool                           `yaml:"metrics"`
	Cache      EvaluatorCache

	Wristband   auth.WristbandIssuer  `yaml:"wristband,omitempty"`
	DynamicJSON *response.DynamicJSON `yaml:"json,omitempty"`
}

func (config *ResponseConfig) GetAuthConfigEvaluator() auth.AuthConfigEvaluator {
	switch config.GetType() {
	case responseWristband:
		return config.Wristband
	case responseJSON:
		return config.DynamicJSON
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
			cacheKey = cache.ResolveKeyFor(pipeline.GetAuthorizationJSON())
			if cachedObj, err := cache.Get(cacheKey); err != nil {
				logger.V(1).Error(err, "failed to retrieve data from the cache")
			} else if cachedObj != nil {
				return cachedObj, nil
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
	default:
		return ""
	}
}

// impl:Prioritizable

func (config *ResponseConfig) GetPriority() int {
	return config.Priority
}

// impl:ConditionalEvaluator

func (config *ResponseConfig) GetConditions() []json.JSONPatternMatchingRule {
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

func WrapResponses(responses map[*ResponseConfig]interface{}) (responseHeaders map[string]string, responseMetadata map[string]interface{}) {
	responseHeaders = make(map[string]string)
	responseMetadata = make(map[string]interface{})

	for responseConfig, authObj := range responses {
		switch responseConfig.Wrapper {
		case HTTP_HEADER_WRAPPER:
			responseHeaders[responseConfig.WrapperKey], _ = json.StringifyJSON(authObj)
		case ENVOY_DYNAMIC_METADATA_WRAPPER:
			responseMetadata[responseConfig.WrapperKey] = authObj
		}
	}

	return responseHeaders, responseMetadata
}
