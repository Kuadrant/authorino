package config

import (
	"context"
	"fmt"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/config/identity"

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

// Call method will execute the specific Identity implementation's method
func (config *IdentityConfig) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	switch {
	case config.OAuth2 != nil:
		return config.OAuth2.Call(pipeline, ctx)
	case config.OIDC != nil:
		return config.OIDC.Call(pipeline, ctx)
	case config.MTLS != nil:
		return config.MTLS.Call(pipeline, ctx)
	case config.HMAC != nil:
		return config.HMAC.Call(pipeline, ctx)
	case config.APIKey != nil:
		return config.APIKey.Call(pipeline, ctx)
	case config.KubernetesAuth != nil:
		return config.KubernetesAuth.Call(pipeline, ctx)
	default:
		return "", fmt.Errorf("invalid identity config")
	}
}

func (config *IdentityConfig) GetOIDC() interface{} {
	return config.OIDC
}

func (config *IdentityConfig) GetAPIKey() interface{} {
	return config.APIKey
}

func (config *IdentityConfig) FindSecretByName(lookup types.NamespacedName) *v1.Secret {
	apiKey := config.APIKey
	if apiKey != nil {
		return apiKey.FindSecretByName(lookup)
	} else {
		return nil
	}
}
