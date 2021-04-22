package config

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/auth_credentials"
	"github.com/kuadrant/authorino/pkg/config/identity"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

var (
	// IdentityEvaluator represents the identityConfig struct implementing its Call method
	IdentityEvaluator common.AuthConfigEvaluator
)

type IdentityConfig struct {
	Name string `yaml:"name"`

	OAuth2         *identity.OAuth2         `yaml:"oauth2,omitempty"`
	OIDC           *identity.OIDC           `yaml:"oidc,omitempty"`
	MTLS           *identity.MTLS           `yaml:"mtls,omitempty"`
	HMAC           *identity.HMAC           `yaml:"hmac,omitempty"`
	APIKey         *identity.APIKey         `yaml:"apiKey,omitempty"`
	KubernetesAuth *identity.KubernetesAuth `yaml:"kubernetes,omitempty"`
}

func init() {
	IdentityEvaluator = &IdentityConfig{}
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
		return evaluator.Call(pipeline, ctx)
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

// impl:APIKeySecretFinder

func (config *IdentityConfig) FindSecretByName(lookup types.NamespacedName) *v1.Secret {
	apiKey := config.APIKey
	if apiKey != nil {
		return apiKey.FindSecretByName(lookup)
	} else {
		return nil
	}
}
