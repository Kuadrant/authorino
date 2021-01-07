package config

import (
	"fmt"
	"reflect"

	"github.com/3scale-labs/authorino/pkg/config/authorization"
	"github.com/3scale-labs/authorino/pkg/config/internal"
)

type AuthorizationConfig struct {
	OPA authorization.OPA       `yaml:"opa"`
	JWT authorization.JWTClaims `yaml:"jwt"`
}

func (self *AuthorizationConfig) Call(ctx internal.AuthContext) (bool, error) {
	switch {
	case self.OPA != authorization.OPA{}:
		return self.OPA.Call(ctx)
	case !reflect.DeepEqual(self.JWT, authorization.JWTClaims{}):
		return self.JWT.Call(ctx)
	default:
		return false, fmt.Errorf("Invalid authorization configs")
	}
}
