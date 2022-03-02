package config

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/config/identity"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	identityOAuth2     = "IDENTITY_OAUTH2"
	identityOIDC       = "IDENTITY_OIDC"
	identityMTLS       = "IDENTITY_MTLS"
	identityHMAC       = "IDENTITY_HMAC"
	identityAPIKey     = "IDENTITY_APIKEY"
	identityKubernetes = "IDENTITY_KUBERNETES"
	identityNoop       = "IDENTITY_NOOP"
)

type IdentityConfig struct {
	Name           string                           `yaml:"name"`
	Priority       int                              `yaml:"priority"`
	Conditions     []common.JSONPatternMatchingRule `yaml:"conditions"`
	MetricsEnabled bool                             `yaml:"monit"`

	OAuth2         *identity.OAuth2         `yaml:"oauth2,omitempty"`
	OIDC           *identity.OIDC           `yaml:"oidc,omitempty"`
	MTLS           *identity.MTLS           `yaml:"mtls,omitempty"`
	HMAC           *identity.HMAC           `yaml:"hmac,omitempty"`
	APIKey         *identity.APIKey         `yaml:"apiKey,omitempty"`
	KubernetesAuth *identity.KubernetesAuth `yaml:"kubernetes,omitempty"`
	Noop           *identity.Noop           `yaml:"noop,omitempty"`

	ExtendedProperties []common.JSONProperty `yaml:"extendedProperties"`
}

func (config *IdentityConfig) GetAuthConfigEvaluator() common.AuthConfigEvaluator {
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
	case identityNoop:
		return config.Noop
	default:
		return nil
	}
}

func (config *IdentityConfig) GetAuthConfigCleaner() common.AuthConfigCleaner {
	switch {
	case config.OIDC != nil:
		return config.OIDC
	default:
		return nil
	}
}

// ensure IdentityConfig implements AuthConfigEvaluator
var _ common.AuthConfigEvaluator = (*IdentityConfig)(nil)
var _ common.AuthConfigCleaner = (*IdentityConfig)(nil)

// impl:AuthConfigEvaluator

func (config *IdentityConfig) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	if evaluator := config.GetAuthConfigEvaluator(); evaluator != nil {
		logger := log.FromContext(ctx).WithName("identity")
		return evaluator.Call(pipeline, log.IntoContext(ctx, logger))
	} else {
		return nil, fmt.Errorf("invalid identity config")
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

func (config *IdentityConfig) GetConditions() []common.JSONPatternMatchingRule {
	return config.Conditions
}

// impl:AuthConfigCleaner
func (config *IdentityConfig) Clean(ctx context.Context) error {
	if evaluator := config.GetAuthConfigCleaner(); evaluator != nil {
		logger := log.FromContext(ctx).WithName("identity")
		return evaluator.Clean(log.IntoContext(ctx, logger))
	}
	// it is ok for there to be no clean method as not all config types need it
	return nil
}

// impl:IdentityConfigEvaluator

func (config *IdentityConfig) GetOIDC() interface{} {
	return config.OIDC
}

func (config *IdentityConfig) GetAuthCredentials() auth_credentials.AuthCredentials {
	evaluator := config.GetAuthConfigEvaluator()
	creds := evaluator.(auth_credentials.AuthCredentials)
	return creds
}

func (config *IdentityConfig) ResolveExtendedProperties(pipeline common.AuthPipeline) (interface{}, error) {
	_, resolvedIdentityObj := pipeline.GetResolvedIdentity()

	// return the original object if there is no extension property to resolve (to save the unnecessary json marshaling/unmarshaling overhead)
	if len(config.ExtendedProperties) == 0 {
		return resolvedIdentityObj, nil
	}

	identityObjAsJSON, _ := json.Marshal(resolvedIdentityObj)
	var extendedIdentityObject map[string]interface{}
	err := json.Unmarshal(identityObjAsJSON, &extendedIdentityObject)
	if err != nil {
		return nil, err
	}

	authJSON := pipeline.GetAuthorizationJSON()

	for _, extendedProperty := range config.ExtendedProperties {
		extendedIdentityObject[extendedProperty.Name] = extendedProperty.Value.ResolveFor(authJSON)
	}

	return extendedIdentityObject, nil
}

// impl:APIKeySecretFinder

func (config *IdentityConfig) FindSecretByName(lookup types.NamespacedName) *v1.Secret {
	apiKey := config.APIKey
	if apiKey != nil {
		return apiKey.FindSecretByName(lookup)
	} else {
		return nil
	}
}

// impl:metrics.Object

func (config *IdentityConfig) Measured() bool {
	return config.MetricsEnabled
}
