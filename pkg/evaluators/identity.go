package evaluators

import (
	"context"
	gojson "encoding/json"
	"fmt"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/evaluators/identity"
	"github.com/kuadrant/authorino/pkg/jsonexp"
	"github.com/kuadrant/authorino/pkg/log"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

const (
	identityOAuth2     = "IDENTITY_OAUTH2"
	identityOIDC       = "IDENTITY_OIDC"
	identityMTLS       = "IDENTITY_MTLS"
	identityHMAC       = "IDENTITY_HMAC"
	identityAPIKey     = "IDENTITY_APIKEY"
	identityKubernetes = "IDENTITY_KUBERNETES"
	identityPlain      = "IDENTITY_PLAIN"
	identityNoop       = "IDENTITY_NOOP"
)

type IdentityConfig struct {
	Name       string             `yaml:"name"`
	Priority   int                `yaml:"priority"`
	Conditions jsonexp.Expression `yaml:"conditions"`
	Metrics    bool               `yaml:"metrics"`
	Cache      EvaluatorCache

	OAuth2         *identity.OAuth2         `yaml:"oauth2,omitempty"`
	OIDC           *identity.OIDC           `yaml:"oidc,omitempty"`
	MTLS           *identity.MTLS           `yaml:"mtls,omitempty"`
	HMAC           *identity.HMAC           `yaml:"hmac,omitempty"`
	APIKey         *identity.APIKey         `yaml:"apiKey,omitempty"`
	KubernetesAuth *identity.KubernetesAuth `yaml:"kubernetes,omitempty"`
	Plain          *identity.Plain          `yaml:"plain,omitempty"`
	Noop           *identity.Noop           `yaml:"noop,omitempty"`

	ExtendedProperties []IdentityExtension `yaml:"extendedProperties"`
}

func (config *IdentityConfig) GetAuthConfigEvaluator() auth.AuthConfigEvaluator {
	switch config.GetType() {
	case identityOAuth2:
		return config.OAuth2
	case identityOIDC:
		return config.OIDC
	case identityMTLS:
		return config.MTLS
	case identityHMAC:
		return config.HMAC
	case identityAPIKey:
		return config.APIKey
	case identityKubernetes:
		return config.KubernetesAuth
	case identityPlain:
		return config.Plain
	case identityNoop:
		return config.Noop
	default:
		return nil
	}
}

// ensure IdentityConfig implements AuthConfigEvaluator
var _ auth.AuthConfigEvaluator = (*IdentityConfig)(nil)
var _ auth.AuthConfigCleaner = (*IdentityConfig)(nil)

// impl:AuthConfigEvaluator

func (config *IdentityConfig) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	if evaluator := config.GetAuthConfigEvaluator(); evaluator == nil {
		return nil, fmt.Errorf("invalid identity config")
	} else {
		logger := log.FromContext(ctx).WithName("identity")

		cache := config.Cache
		var cacheKey interface{}

		if cache != nil {
			cacheKey, _ = cache.ResolveKeyFor(pipeline.GetAuthorizationJSON())
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

func (config *IdentityConfig) GetName() string {
	return config.Name
}

// impl:TypedEvaluator

func (config *IdentityConfig) GetType() string {
	switch {
	case config.OAuth2 != nil:
		return identityOAuth2
	case config.OIDC != nil:
		return identityOIDC
	case config.MTLS != nil:
		return identityMTLS
	case config.HMAC != nil:
		return identityHMAC
	case config.APIKey != nil:
		return identityAPIKey
	case config.KubernetesAuth != nil:
		return identityKubernetes
	case config.Plain != nil:
		return identityPlain
	case config.Noop != nil:
		return identityNoop
	default:
		return ""
	}
}

// impl:Prioritizable

func (config *IdentityConfig) GetPriority() int {
	return config.Priority
}

// impl:ConditionalEvaluator

func (config *IdentityConfig) GetConditions() jsonexp.Expression {
	return config.Conditions
}

// impl:AuthConfigCleaner

func (config *IdentityConfig) Clean(ctx context.Context) error {
	if cleaner := config.getCleaner(); cleaner != nil {
		logger := log.FromContext(ctx).WithName("identity")
		return cleaner.Clean(log.IntoContext(ctx, logger))
	}
	// it is ok for there to be no clean method as not all config types need it
	return nil
}

func (config *IdentityConfig) getCleaner() auth.AuthConfigCleaner {
	switch {
	case config.OIDC != nil:
		return config.OIDC
	default:
		return nil
	}
}

// impl:IdentityConfigEvaluator

func (config *IdentityConfig) GetOIDC() interface{} {
	return config.OIDC
}

func (config *IdentityConfig) GetAuthCredentials() auth.AuthCredentials {
	evaluator := config.GetAuthConfigEvaluator()
	creds := evaluator.(auth.AuthCredentials)
	return creds
}

func (config *IdentityConfig) ResolveExtendedProperties(pipeline auth.AuthPipeline) (interface{}, error) {
	_, resolvedIdentityObj := pipeline.GetResolvedIdentity()

	// return the original object if there is no extension property to resolve (to save the unnecessary json marshaling/unmarshaling overhead)
	if len(config.ExtendedProperties) == 0 {
		return resolvedIdentityObj, nil
	}

	identityObjAsJSON, _ := gojson.Marshal(resolvedIdentityObj)
	var extendedIdentityObject map[string]interface{}
	err := gojson.Unmarshal(identityObjAsJSON, &extendedIdentityObject)
	if err != nil {
		return nil, err
	}

	authJSON := pipeline.GetAuthorizationJSON()

	for _, extendedProperty := range config.ExtendedProperties {
		resolved, err := extendedProperty.ResolveFor(extendedIdentityObject, authJSON)
		if err != nil {
			return nil, err
		}
		extendedIdentityObject[extendedProperty.Name] = resolved
	}

	return extendedIdentityObject, nil
}

// impl:K8sSecretBasedIdentityConfigEvaluator

func (config *IdentityConfig) AddK8sSecretBasedIdentity(ctx context.Context, new v1.Secret) {
	var ev auth.K8sSecretBasedIdentityConfigEvaluator

	switch config.GetType() {
	case identityMTLS:
		ev = config.MTLS
	case identityAPIKey:
		ev = config.APIKey
	default:
		return
	}

	ev.AddK8sSecretBasedIdentity(ctx, new)
}

func (config *IdentityConfig) RevokeK8sSecretBasedIdentity(ctx context.Context, deleted types.NamespacedName) {
	var ev auth.K8sSecretBasedIdentityConfigEvaluator

	switch config.GetType() {
	case identityMTLS:
		ev = config.MTLS
	case identityAPIKey:
		ev = config.APIKey
	default:
		return
	}

	ev.RevokeK8sSecretBasedIdentity(ctx, deleted)
}

func (config *IdentityConfig) GetK8sSecretLabelSelectors() labels.Selector {
	var ev auth.K8sSecretBasedIdentityConfigEvaluator

	switch config.GetType() {
	case identityMTLS:
		ev = config.MTLS
	case identityAPIKey:
		ev = config.APIKey
	default:
		return nil
	}

	return ev.GetK8sSecretLabelSelectors()
}

// impl:metrics.Object

func (config *IdentityConfig) MetricsEnabled() bool {
	return config.Metrics
}
