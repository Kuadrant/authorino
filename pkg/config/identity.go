package config

import (
	"fmt"

	"github.com/3scale-labs/authorino/pkg/config/common"
	"github.com/3scale-labs/authorino/pkg/config/identity"
)

var (
	// IdentityEvaluator represents the identityConfig struct implementing its Call method
	IdentityEvaluator common.AuthConfigEvaluator
)

type IdentityConfig struct {
	OIDC   *identity.OIDC   `yaml:"oidc,omitempty"`
	MTLS   *identity.MTLS   `yaml:"mtls,omitempty"`
	HMAC   *identity.HMAC   `yaml:"hmac,omitempty"`
	APIKey *identity.APIKey `yaml:"api_key,omitempty"`
}

func init() {
	IdentityEvaluator = &IdentityConfig{}
}

// Call method will execute the specific Identity implementation's method
func (config *IdentityConfig) Call(ctx common.AuthContext) (interface{}, error) {
	switch {
	case config.OIDC != nil:
		return config.OIDC.Call(ctx)
	case config.MTLS != nil:
		return config.MTLS.Call(ctx)
	case config.HMAC != nil:
		return config.HMAC.Call(ctx)
	case config.APIKey != nil:
		return config.APIKey.Call(ctx)
	default:
		return "", fmt.Errorf("invalid identity config")
	}
}
