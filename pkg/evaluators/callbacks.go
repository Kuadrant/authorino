package evaluators

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators/metadata"
	"github.com/kuadrant/authorino/pkg/jsonexp"
	"github.com/kuadrant/authorino/pkg/log"
)

const callbackHTTP = "CALLBACK_HTTP"

func NewCallbackConfig(name string, priority int, conditions jsonexp.Expression, metricsEnabled bool) *CallbackConfig {
	callbackConfig := CallbackConfig{
		Name:       name,
		Priority:   priority,
		Conditions: conditions,
		Metrics:    metricsEnabled,
	}

	return &callbackConfig
}

type CallbackConfig struct {
	Name       string             `yaml:"name"`
	Priority   int                `yaml:"priority"`
	Conditions jsonexp.Expression `yaml:"conditions"`
	Metrics    bool               `yaml:"metrics"`

	HTTP *metadata.GenericHttp `yaml:"http,omitempty"`
}

func (config *CallbackConfig) GetAuthConfigEvaluator() auth.AuthConfigEvaluator {
	switch config.GetType() {
	case callbackHTTP:
		return config.HTTP
	default:
		return nil
	}
}

// impl:AuthConfigEvaluator

func (config *CallbackConfig) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	if evaluator := config.GetAuthConfigEvaluator(); evaluator == nil {
		return nil, fmt.Errorf("invalid callback config")
	} else {
		logger := log.FromContext(ctx).WithName("callback")

		obj, err := evaluator.Call(pipeline, log.IntoContext(ctx, logger))

		return obj, err
	}
}

// impl:NamedEvaluator

func (config *CallbackConfig) GetName() string {
	return config.Name
}

// impl:TypedEvaluator

func (config *CallbackConfig) GetType() string {
	switch {
	case config.HTTP != nil:
		return callbackHTTP
	default:
		return ""
	}
}

// impl:Prioritizable

func (config *CallbackConfig) GetPriority() int {
	return config.Priority
}

// impl:ConditionalEvaluator

func (config *CallbackConfig) GetConditions() jsonexp.Expression {
	return config.Conditions
}

// impl:metrics.Object

func (config *CallbackConfig) MetricsEnabled() bool {
	return config.Metrics
}
