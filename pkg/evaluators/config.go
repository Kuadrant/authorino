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

func (config *AuthConfig) GetChallengeHeaders() []map[string]string {
	challengeHeaders := make([]map[string]string, 0)

	for _, authConfig := range config.IdentityConfigs {
		if idConfig, ok := authConfig.(*IdentityConfig); ok {
			challenge := fmt.Sprintf("%v realm=\"%v\"", idConfig.GetAuthCredentials().GetIdentifier(), idConfig.Name)
			challengeHeaders = append(challengeHeaders, map[string]string{"WWW-Authenticate": challenge})
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
	Code      int32
	Message   expressions.Value
	Headers   []json.JSONProperty
	Body      expressions.Value
	Overrides []auth.AuthConfigEvaluator
}

// DenyWithOverride is a conditional customization of a denial response.
// It is evaluated as an auth config so it follows the same priority and condition semantics as the phases of the auth pipeline.
type DenyWithOverride struct {
	Name       string
	Priority   int
	Conditions jsonexp.Expression
	DenyWithValues
}

// Call resolves to the override itself; an override is selected when its conditions match.
func (o *DenyWithOverride) Call(_ auth.AuthPipeline, _ context.Context) (interface{}, error) {
	return o, nil
}

func (o *DenyWithOverride) GetName() string {
	return o.Name
}

func (o *DenyWithOverride) GetPriority() int {
	return o.Priority
}

func (o *DenyWithOverride) GetConditions() jsonexp.Expression {
	return o.Conditions
}
