package config

import (
	"context"
	"fmt"
	"sync"

	"github.com/kuadrant/authorino/pkg/common"

	multierror "github.com/hashicorp/go-multierror"
)

// APIConfig holds the static configuration to be evaluated in the auth pipeline
type APIConfig struct {
	Labels     map[string]string
	Conditions []common.JSONPatternMatchingRule `yaml:"conditions"`

	IdentityConfigs      []common.AuthConfigEvaluator `yaml:"identity,omitempty"`
	MetadataConfigs      []common.AuthConfigEvaluator `yaml:"metadata,omitempty"`
	AuthorizationConfigs []common.AuthConfigEvaluator `yaml:"authorization,omitempty"`
	ResponseConfigs      []common.AuthConfigEvaluator `yaml:"response,omitempty"`

	DenyWith
}

func (config *APIConfig) GetChallengeHeaders() []map[string]string {
	challengeHeaders := make([]map[string]string, 0)

	for _, authConfig := range config.IdentityConfigs {
		idConfig := authConfig.(*IdentityConfig)
		challenge := fmt.Sprintf("%v realm=\"%v\"", idConfig.GetAuthCredentials().GetCredentialsKeySelector(), idConfig.Name)
		challengeHeaders = append(challengeHeaders, map[string]string{"WWW-Authenticate": challenge})
	}

	return challengeHeaders
}

func (config *APIConfig) Clean(ctx context.Context) error {
	evaluators := []common.AuthConfigEvaluator{}
	evaluators = append(evaluators, config.IdentityConfigs...)
	evaluators = append(evaluators, config.MetadataConfigs...)
	evaluators = append(evaluators, config.AuthorizationConfigs...)
	evaluators = append(evaluators, config.ResponseConfigs...)

	var errors error
	var wait sync.WaitGroup
	wait.Add(len(evaluators))

	for _, evaluator := range evaluators {
		go func(e common.AuthConfigEvaluator) {
			defer wait.Done()
			if cleaner, ok := e.(common.AuthConfigCleaner); ok {
				if err := cleaner.Clean(ctx); err != nil {
					errors = multierror.Append(errors, err)
				}
			}
		}(evaluator)
	}

	wait.Wait()

	return errors
}

type DenyWith struct {
	Unauthenticated *DenyWithValues
	Unauthorized    *DenyWithValues
}

type DenyWithValues struct {
	Code    int32
	Message string
	Headers []common.JSONProperty
}
