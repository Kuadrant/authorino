package config

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/config/authorization"
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

func (config *AuthorizationConfig) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	switch {
	case config.OPA != nil:
		return config.OPA.Call(pipeline, ctx)
	case config.JSON != nil:
		return config.JSON.Call(pipeline, ctx)
	default:
		return false, fmt.Errorf("invalid authorization configs")
	}
}
