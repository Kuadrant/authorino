package config

import (
	"context"
	"fmt"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/config/authorization"
)

var (
	// AuthorizationEvaluator represents the authorizationConfig struct implementing its Call method
	AuthorizationEvaluator common.AuthConfigEvaluator
)

type AuthorizationConfig struct {
	Name string                             `yaml:"name"`
	OPA  *authorization.OPA                 `yaml:"opa,omitempty"`
	JSON *authorization.JSONPatternMatching `yaml:"json,omitempty"`
}

func (config *AuthorizationConfig) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	switch {
	case config.OPA != nil:
		return config.OPA.Call(authContext, ctx)
	case config.JSON != nil:
		return config.JSON.Call(authContext, ctx)
	default:
		return false, fmt.Errorf("invalid authorization configs")
	}
}
