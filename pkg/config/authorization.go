package config

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/config/authorization"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/log"
)

const (
	authorizationOPA        = "AUTHORIZATION_OPA"
	authorizationJSON       = "AUTHORIZATION_JSON"
	authorizationKubernetes = "AUTHORIZATION_KUBERNETES"
)

type AuthorizationConfig struct {
	Name       string                         `yaml:"name"`
	Priority   int                            `yaml:"priority"`
	Conditions []json.JSONPatternMatchingRule `yaml:"conditions"`
	Metrics    bool                           `yaml:"metrics"`

	OPA             *authorization.OPA                 `yaml:"opa,omitempty"`
	JSON            *authorization.JSONPatternMatching `yaml:"json,omitempty"`
	KubernetesAuthz *authorization.KubernetesAuthz     `yaml:"kubernetes,omitempty"`
}

// impl:AuthConfigEvaluator

func (config *AuthorizationConfig) Call(pipeline auth.AuthPipeline, parentCtx context.Context) (interface{}, error) {
	logger := log.FromContext(parentCtx).WithName("authorization")
	ctx := log.IntoContext(parentCtx, logger)

	switch config.GetType() {
	case authorizationOPA:
		return config.OPA.Call(pipeline, ctx)
	case authorizationJSON:
		return config.JSON.Call(pipeline, ctx)
	case authorizationKubernetes:
		return config.KubernetesAuthz.Call(pipeline, ctx)
	default:
		return false, fmt.Errorf("invalid authorization config")
	}
}

// impl:NamedEvaluator

func (config *AuthorizationConfig) GetName() string {
	return config.Name
}

// impl:TypedEvaluator

func (config *AuthorizationConfig) GetType() string {
	switch {
	case config.OPA != nil:
		return authorizationOPA
	case config.JSON != nil:
		return authorizationJSON
	case config.KubernetesAuthz != nil:
		return authorizationKubernetes
	default:
		return ""
	}
}

// impl:Prioritizable

func (config *AuthorizationConfig) GetPriority() int {
	return config.Priority
}

// impl:ConditionalEvaluator

func (config *AuthorizationConfig) GetConditions() []json.JSONPatternMatchingRule {
	return config.Conditions
}

// impl:metrics.Object

func (config *AuthorizationConfig) MetricsEnabled() bool {
	return config.Metrics
}

// impl:AuthConfigCleaner

func (config *AuthorizationConfig) Clean(ctx context.Context) error {
	if cleaner := config.getCleaner(); cleaner != nil {
		logger := log.FromContext(ctx).WithName("authorization")
		return cleaner.Clean(log.IntoContext(ctx, logger))
	}
	// it is ok for there to be no clean method as not all config types need it
	return nil
}

func (config *AuthorizationConfig) getCleaner() auth.AuthConfigCleaner {
	switch {
	case config.OPA != nil:
		return config.OPA
	default:
		return nil
	}
}
