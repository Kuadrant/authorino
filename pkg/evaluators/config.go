package evaluators

import (
	"context"
	"fmt"
	"sync"

	"github.com/kuadrant/authorino/pkg/auth"
	"github.com/kuadrant/authorino/pkg/expressions"
	"github.com/kuadrant/authorino/pkg/json"
	"github.com/kuadrant/authorino/pkg/jsonexp"
	"github.com/kuadrant/authorino/pkg/log"

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

// Start kicks off whatever the evaluators of this config should only be running once the config is
// valid and reachable. Unlike Clean, it runs sequentially: there is nothing to parallelise here and
// it keeps the panic surface of the reconcile path small.
func (config *AuthConfig) Start(ctx context.Context) error {
	var errs error

	for _, evaluator := range config.allEvaluators() {
		if starter, ok := evaluator.(auth.AuthConfigStarter); ok {
			if err := starter.Start(ctx); err != nil {
				errs = multierror.Append(errs, err)
			}
		}
	}

	return errs
}

func (config *AuthConfig) allEvaluators() []auth.AuthConfigEvaluator {
	evaluators := []auth.AuthConfigEvaluator{}
	evaluators = append(evaluators, config.IdentityConfigs...)
	evaluators = append(evaluators, config.MetadataConfigs...)
	evaluators = append(evaluators, config.AuthorizationConfigs...)
	evaluators = append(evaluators, config.ResponseConfigs...)
	evaluators = append(evaluators, config.CallbackConfigs...)
	return evaluators
}

func (config *AuthConfig) Clean(ctx context.Context) error {
	evaluators := config.allEvaluators()

	var errors error
	var wait sync.WaitGroup
	wait.Add(len(evaluators))

	for _, evaluator := range evaluators {
		go func(e auth.AuthConfigEvaluator) {
			defer wait.Done()
			// cleanup runs in its own goroutine, so a panic here would be unrecoverable by the
			// caller and would take the whole process down with it
			defer func() {
				if r := recover(); r != nil {
					// only the name of the config is logged: evaluators hold credentials in
					// exported fields (OAuth2.ClientSecret, OPAExternalSource.SharedSecret)
					logger := log.FromContext(ctx)
					if named, ok := e.(auth.NamedEvaluator); ok {
						logger = logger.WithValues("config", named.GetName())
					}
					logger.Error(fmt.Errorf("%v", r), "recovered from panic while cleaning up evaluator")
				}
			}()
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
