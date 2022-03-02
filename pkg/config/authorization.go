package config

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/config/authorization"
)

const (
	authorizationOPA        = "AUTHORIZATION_OPA"
	authorizationJSON       = "AUTHORIZATION_JSON"
	authorizationKubernetes = "AUTHORIZATION_KUBERNETES"
)

type AuthorizationConfig struct {
	Name           string                           `yaml:"name"`
	Priority       int                              `yaml:"priority"`
	Conditions     []common.JSONPatternMatchingRule `yaml:"conditions"`
	MetricsEnabled bool                             `yaml:"monit"`

	OPA             *authorization.OPA                 `yaml:"opa,omitempty"`
	JSON            *authorization.JSONPatternMatching `yaml:"json,omitempty"`
	KubernetesAuthz *authorization.KubernetesAuthz     `yaml:"kubernetes,omitempty"`
}

// impl:AuthConfigEvaluator

func (config *AuthorizationConfig) Call(pipeline common.AuthPipeline, parentCtx context.Context) (interface{}, error) {
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

func (config *AuthorizationConfig) GetConditions() []common.JSONPatternMatchingRule {
	return config.Conditions
}

// impl:metrics.Object

func (config *AuthorizationConfig) Measured() bool {
	return config.MetricsEnabled
}
