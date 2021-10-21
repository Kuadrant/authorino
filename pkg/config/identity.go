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

type IdentityConfig struct {
	Name               string                `yaml:"name"`
	ExtendedProperties []common.JSONProperty `yaml:"extendedProperties"`

	OAuth2         *identity.OAuth2         `yaml:"oauth2,omitempty"`
	OIDC           *identity.OIDC           `yaml:"oidc,omitempty"`
	MTLS           *identity.MTLS           `yaml:"mtls,omitempty"`
	HMAC           *identity.HMAC           `yaml:"hmac,omitempty"`
	APIKey         *identity.APIKey         `yaml:"apiKey,omitempty"`
	KubernetesAuth *identity.KubernetesAuth `yaml:"kubernetes,omitempty"`
}

func (config *IdentityConfig) GetAuthConfigEvaluator() common.AuthConfigEvaluator {
	switch {
	case config.OAuth2 != nil:
		return config.OAuth2
	case config.OIDC != nil:
		return config.OIDC
	case config.MTLS != nil:
		return config.MTLS
	case config.HMAC != nil:
		return config.HMAC
	case config.APIKey != nil:
		return config.APIKey
	case config.KubernetesAuth != nil:
		return config.KubernetesAuth
	default:
		return nil
	}
}

// impl:AuthConfigEvaluator

func (config *IdentityConfig) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	if evaluator := config.GetAuthConfigEvaluator(); evaluator != nil {
		logger := log.FromContext(ctx).WithName("identity")
		return evaluator.Call(pipeline, log.IntoContext(ctx, logger))
	} else {
		return nil, fmt.Errorf("invalid identity config")
	}
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

	authDataObj := pipeline.GetDataForAuthorization()
	authJSON, _ := json.Marshal(authDataObj)

	for _, extendedProperty := range config.ExtendedProperties {
		extendedIdentityObject[extendedProperty.Name] = extendedProperty.Value.ResolveFor(string(authJSON))
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
