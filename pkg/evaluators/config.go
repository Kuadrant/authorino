package evaluators

import (
	"context"
	"fmt"
	"sync"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/jsonexp"

	multierror "github.com/hashicorp/go-multierror"
)

// AuthConfig holds the static configuration to be evaluated in the auth pipeline
type AuthConfig struct {
	Labels     map[string]string
	Conditions jsonexp.Expression `yaml:"conditions"`

	IdentityConfigs      []auth.AuthConfigEvaluator `yaml:"identity,omitempty"`
	MetadataConfigs      []auth.AuthConfigEvaluator `yaml:"metadata,omitempty"`
	AuthorizationConfigs []auth.AuthConfigEvaluator `yaml:"authorization,omitempty"`
	ResponseConfigs      []auth.AuthConfigEvaluator `yaml:"response,omitempty"`
	CallbackConfigs      []auth.AuthConfigEvaluator `yaml:"callbacks,omitempty"`

	DenyWith
}

func (config *AuthConfig) GetChallengeHeaders() []map[string]auth.HeaderValue {
	challengeHeaders := make([]map[string]auth.HeaderValue, 0)

	for _, authConfig := range config.IdentityConfigs {
		if idConfig, ok := authConfig.(*IdentityConfig); ok {
			challenge := fmt.Sprintf("%v realm=\"%v\"", idConfig.GetAuthCredentials().GetCredentialsKeySelector(), idConfig.Name)
			challengeHeaders = append(challengeHeaders, map[string]auth.HeaderValue{"WWW-Authenticate": {Value: challenge}})
		}
	}

	return challengeHeaders
}

func (config *AuthConfig) Clean(ctx context.Context) error {
	evaluators := []auth.AuthConfigEvaluator{}
	evaluators = append(evaluators, config.IdentityConfigs...)
	evaluators = append(evaluators, config.MetadataConfigs...)
	evaluators = append(evaluators, config.AuthorizationConfigs...)
	evaluators = append(evaluators, config.ResponseConfigs...)
	evaluators = append(evaluators, config.CallbackConfigs...)

	var errors error
	var wait sync.WaitGroup
	wait.Add(len(evaluators))

	for _, evaluator := range evaluators {
		go func(e auth.AuthConfigEvaluator) {
			defer wait.Done()
			if cleaner, ok := e.(auth.AuthConfigCleaner); ok {
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
	Message expressions.Value
	Headers []json.JSONProperty
	Body    expressions.Value
}
