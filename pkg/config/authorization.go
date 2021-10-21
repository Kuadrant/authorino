package config

import (
	"context"
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/common/log"
	"github.com/kuadrant/authorino/pkg/config/authorization"
)

type AuthorizationConfig struct {
	Name            string                             `yaml:"name"`
	OPA             *authorization.OPA                 `yaml:"opa,omitempty"`
	JSON            *authorization.JSONPatternMatching `yaml:"json,omitempty"`
	KubernetesAuthz *authorization.KubernetesAuthz     `yaml:"kubernetes,omitempty"`
}

// impl:AuthConfigEvaluator

func (config *AuthorizationConfig) Call(pipeline common.AuthPipeline, parentCtx context.Context) (interface{}, error) {
	logger := log.FromContext(parentCtx).WithName("authorization")
	ctx := log.IntoContext(parentCtx, logger)

	switch {
	case config.OPA != nil:
		return config.OPA.Call(pipeline, ctx)
	case config.JSON != nil:
		return config.JSON.Call(pipeline, ctx)
	case config.KubernetesAuthz != nil:
		return config.KubernetesAuthz.Call(pipeline, ctx)
	default:
		return false, fmt.Errorf("invalid authorization config")
	}
}
