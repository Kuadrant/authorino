package config

import (
	"context"
	"fmt"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/config/identity"
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
func (config *IdentityConfig) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	switch {
	case config.OAuth2 != nil:
		return config.OAuth2.Call(authContext, ctx)
	case config.OIDC != nil:
		return config.OIDC.Call(authContext, ctx)
	case config.MTLS != nil:
		return config.MTLS.Call(authContext, ctx)
	case config.HMAC != nil:
		return config.HMAC.Call(authContext, ctx)
	case config.APIKey != nil:
		return config.APIKey.Call(authContext, ctx)
	case config.KubernetesAuth != nil:
		return config.KubernetesAuth.Call(authContext, ctx)
	default:
		return "", fmt.Errorf("invalid identity config")
	}
}

func (config *IdentityConfig) GetOIDC() interface{} {
	return config.OIDC
}
