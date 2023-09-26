package evaluators

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators/authorization"
	"github.com/kuadrant/authorino/pkg/jsonexp"
	"github.com/kuadrant/authorino/pkg/log"
)

const (
	authorizationOPA        = "AUTHORIZATION_OPA"
	authorizationJSON       = "AUTHORIZATION_JSON"
	authorizationKubernetes = "AUTHORIZATION_KUBERNETES"
	authorizationAuthzed    = "AUTHORIZATION_AUTHZED"
)

type AuthorizationConfig struct {
	Name       string             `yaml:"name"`
	Priority   int                `yaml:"priority"`
	Conditions jsonexp.Expression `yaml:"conditions"`
	Metrics    bool               `yaml:"metrics"`
	Cache      EvaluatorCache

	OPA             *authorization.OPA                 `yaml:"opa,omitempty"`
	JSON            *authorization.JSONPatternMatching `yaml:"json,omitempty"`
	KubernetesAuthz *authorization.KubernetesAuthz     `yaml:"kubernetes,omitempty"`
	Authzed         *authorization.Authzed             `yaml:"authzed,omitempty"`
}

func (config *AuthorizationConfig) GetAuthConfigEvaluator() auth.AuthConfigEvaluator {
	switch config.GetType() {
	case authorizationOPA:
		return config.OPA
	case authorizationJSON:
		return config.JSON
	case authorizationKubernetes:
		return config.KubernetesAuthz
	case authorizationAuthzed:
		return config.Authzed
	default:
		return nil
	}
}

// impl:AuthConfigEvaluator

func (config *AuthorizationConfig) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	if evaluator := config.GetAuthConfigEvaluator(); evaluator == nil {
		return nil, fmt.Errorf("invalid authorization config")
	} else {
		logger := log.FromContext(ctx).WithName("authorization")

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
	case config.Authzed != nil:
		return authorizationAuthzed
	default:
		return ""
	}
}

// impl:Prioritizable

func (config *AuthorizationConfig) GetPriority() int {
	return config.Priority
}

// impl:ConditionalEvaluator

func (config *AuthorizationConfig) GetConditions() jsonexp.Expression {
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
