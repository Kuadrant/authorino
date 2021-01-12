package config

import (
	"fmt"
	"github.com/3scale-labs/authorino/pkg/config/authorization"
	"github.com/3scale-labs/authorino/pkg/config/internal"
)

type AuthorizationConfig struct {
	OPA *authorization.OPA       `yaml:"opa"`
	JWT *authorization.JWTClaims `yaml:"jwt"`
}

func (self *AuthorizationConfig) Call(ctx internal.AuthContext) (bool, error) {
	switch {
	case self.OPA != nil:
		return self.OPA.Call(ctx)
	case self.JWT != nil:
		return self.JWT.Call(ctx)
	default:
		return false, fmt.Errorf("Invalid authorization configs")
	}
}
