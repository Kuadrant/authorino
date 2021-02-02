package config

import (
	"fmt"

	"github.com/3scale-labs/authorino/pkg/config/authorization"
	"github.com/3scale-labs/authorino/pkg/config/common"
)

var (
	// AuthorizationEvaluator represents the authorizationConfig struct implementing its Call method
	AuthorizationEvaluator common.AuthConfigEvaluator
)

type AuthorizationConfig struct {
	OPA *authorization.OPA       `yaml:"opa"`
	JWT *authorization.JWTClaims `yaml:"jwt"`
}

func (config *AuthorizationConfig) Call(ctx common.AuthContext) (interface{}, error) {
	switch {
	case config.OPA != nil:
		return config.OPA.Call(ctx)
	case config.JWT != nil:
		return config.JWT.Call(ctx)
	default:
		return false, fmt.Errorf("invalid authorization configs")
	}
}
