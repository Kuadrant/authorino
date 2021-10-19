package config

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/config/authorization"
)

var (
	// AuthorizationEvaluator represents the authorizationConfig struct implementing its Call method
	AuthorizationEvaluator common.AuthConfigEvaluator
)

type AuthorizationConfig struct {
	Name            string                             `yaml:"name"`
	OPA             *authorization.OPA                 `yaml:"opa,omitempty"`
	JSON            *authorization.JSONPatternMatching `yaml:"json,omitempty"`
	KubernetesAuthz *authorization.KubernetesAuthz     `yaml:"kubernetes,omitempty"`
}

func (config *AuthorizationConfig) Call(pipeline common.AuthPipeline, ctx context.Context, parentLogger log.Logger) (interface{}, error) {
	logger := parentLogger.WithName("authorization")

	switch {
	case config.OPA != nil:
		return config.OPA.Call(pipeline, ctx, logger)
	case config.JSON != nil:
		return config.JSON.Call(pipeline, ctx, logger)
	case config.KubernetesAuthz != nil:
		return config.KubernetesAuthz.Call(pipeline, ctx, logger)
	default:
		return false, fmt.Errorf("invalid authorization configs")
	}
}
