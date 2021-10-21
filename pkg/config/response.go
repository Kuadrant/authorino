package config

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/config/response"
)

const (
	RESPONSE_WRISTBAND    = "RESPONSE_WRISTBAND"
	RESPONSE_DYNAMIC_JSON = "RESPONSE_DYNAMIC_JSON"

	HTTP_HEADER_WRAPPER            = "httpHeader"
	ENVOY_DYNAMIC_METADATA_WRAPPER = "envoyDynamicMetadata"

	DEFAULT_WRAPPER = HTTP_HEADER_WRAPPER
)

func NewResponseConfig(name string, wrapper string, wrapperKey string) *ResponseConfig {
	responseConfig := ResponseConfig{
		Name:       name,
		Wrapper:    DEFAULT_WRAPPER,
		WrapperKey: name,
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
	Name       string `yaml:"name"`
	Wrapper    string `yaml:"wrapper"`
	WrapperKey string `yaml:"wrapperKey"`

	Wristband   common.WristbandIssuer `yaml:"wristband,omitempty"`
	DynamicJSON *response.DynamicJSON  `yaml:"json,omitempty"`
}

func (config *ResponseConfig) GetType() (string, error) {
	switch {
	case config.Wristband != nil:
		return RESPONSE_WRISTBAND, nil
	case config.DynamicJSON != nil:
		return RESPONSE_DYNAMIC_JSON, nil
	default:
		return "", fmt.Errorf("invalid response config")
	}
}

func (config *ResponseConfig) GetAuthConfigEvaluator() common.AuthConfigEvaluator {
	t, _ := config.GetType()
	switch t {
	case RESPONSE_WRISTBAND:
		return config.Wristband
	case RESPONSE_DYNAMIC_JSON:
		return config.DynamicJSON
	default:
		return nil
	}
}

// impl:AuthConfigEvaluator

func (config *ResponseConfig) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	if evaluator := config.GetAuthConfigEvaluator(); evaluator != nil {
		logger := log.FromContext(ctx).WithName("response")
		return evaluator.Call(pipeline, log.IntoContext(ctx, logger))
	} else {
		return nil, fmt.Errorf("invalid response config")
	}
}

// impl:NamedConfigEvaluator

func (config *ResponseConfig) GetName() string {
	return config.Name
}

// impl:ResponseConfigEvaluator

func (config *ResponseConfig) GetWristbandIssuer() common.WristbandIssuer {
	return config.Wristband
}

func WrapResponses(responses map[*ResponseConfig]interface{}) (responseHeaders map[string]string, responseMetadata map[string]interface{}) {
	responseHeaders = make(map[string]string)
	responseMetadata = make(map[string]interface{})

	for responseConfig, authObj := range responses {
		switch responseConfig.Wrapper {
		case HTTP_HEADER_WRAPPER:
			responseHeaders[responseConfig.WrapperKey], _ = common.StringifyJSON(authObj)
		case ENVOY_DYNAMIC_METADATA_WRAPPER:
			responseMetadata[responseConfig.WrapperKey] = authObj
		}
	}

	return responseHeaders, responseMetadata
}
