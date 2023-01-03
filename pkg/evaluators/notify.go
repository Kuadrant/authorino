package evaluators

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators/metadata"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/log"
)

const notifyHTTP = "NOTIFY_HTTP"

func NewNotifyConfig(name string, priority int, conditions []json.JSONPatternMatchingRule, metricsEnabled bool) *NotifyConfig {
	notifyConfig := NotifyConfig{
		Name:       name,
		Priority:   priority,
		Conditions: conditions,
		Metrics:    metricsEnabled,
	}

	return &notifyConfig
}

type NotifyConfig struct {
	Name       string                         `yaml:"name"`
	Priority   int                            `yaml:"priority"`
	Conditions []json.JSONPatternMatchingRule `yaml:"conditions"`
	Metrics    bool                           `yaml:"metrics"`

	HTTP *metadata.GenericHttp `yaml:"http,omitempty"`
}

func (config *NotifyConfig) GetAuthConfigEvaluator() auth.AuthConfigEvaluator {
	switch config.GetType() {
	case notifyHTTP:
		return config.HTTP
	default:
		return nil
	}
}

// impl:AuthConfigEvaluator

func (config *NotifyConfig) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	if evaluator := config.GetAuthConfigEvaluator(); evaluator == nil {
		return nil, fmt.Errorf("invalid notify config")
	} else {
		logger := log.FromContext(ctx).WithName("notify")

		obj, err := evaluator.Call(pipeline, log.IntoContext(ctx, logger))

		return obj, err
	}
}

// impl:NamedEvaluator

func (config *NotifyConfig) GetName() string {
	return config.Name
}

// impl:TypedEvaluator

func (config *NotifyConfig) GetType() string {
	switch {
	case config.HTTP != nil:
		return notifyHTTP
	default:
		return ""
	}
}

// impl:Prioritizable

func (config *NotifyConfig) GetPriority() int {
	return config.Priority
}

// impl:ConditionalEvaluator

func (config *NotifyConfig) GetConditions() []json.JSONPatternMatchingRule {
	return config.Conditions
}

// impl:metrics.Object

func (config *NotifyConfig) MetricsEnabled() bool {
	return config.Metrics
}
