package config

import (
	"fmt"

	"github.com/3scale/authorino/pkg/config/identity"
	"github.com/3scale/authorino/pkg/config/internal"
)

type IdentityConfig struct {
	OIDC identity.OIDC `yaml:"oidc,omitempty"`
	MTLS identity.MTLS `yaml:"mtls,omitempty"`
	HMAC identity.HMAC `yaml:"hmac,omitempty"`
	APIKey identity.APIKey `yaml:"api_key,omitempty"`
}

func (self *IdentityConfig) Call(ctx internal.AuthContext) (interface{}, error) {
	switch {
		case self.OIDC != identity.OIDC{}: return self.OIDC.Call(ctx)
		case self.MTLS != identity.MTLS{}: return self.MTLS.Call(ctx)
		case self.HMAC != identity.HMAC{}: return self.HMAC.Call(ctx)
		case self.APIKey != identity.APIKey{}: return self.APIKey.Call(ctx)
		default: return "", fmt.Errorf("Invalid identity config")
	}
}
