package evaluators

import (
	"context"
	"testing"

	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/evaluators/authorization"
	"github.com/kuadrant/authorino/pkg/evaluators/identity"
	"github.com/kuadrant/authorino/pkg/evaluators/metadata"
	"github.com/kuadrant/authorino/pkg/evaluators/response"
	"github.com/kuadrant/authorino/pkg/metrics"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

type recordingCache struct {
	config    metrics.Object
	evaluator auth.AuthConfigEvaluator
	calls     int
}

func (c *recordingCache) Call(_ context.Context, _ auth.AuthPipeline, config metrics.Object, evaluator auth.AuthConfigEvaluator) (any, error) {
	c.calls++
	c.config, c.evaluator = config, evaluator
	return "from cache", nil
}

func (c *recordingCache) Shutdown() error { return nil }

func TestEvaluatorConfigsCallThroughCache(t *testing.T) {
	noop := &identity.Noop{}
	genericHTTP := &metadata.GenericHttp{}
	patternMatching := &authorization.JSONPatternMatching{}
	plain := &response.Plain{}

	for name, tc := range map[string]struct {
		config    func(EvaluatorCache) auth.AuthConfigEvaluator
		evaluator auth.AuthConfigEvaluator
	}{
		"identity": {func(c EvaluatorCache) auth.AuthConfigEvaluator {
			return &IdentityConfig{Name: "x", Noop: noop, Cache: c}
		}, noop},
		"metadata": {func(c EvaluatorCache) auth.AuthConfigEvaluator {
			return &MetadataConfig{Name: "x", GenericHTTP: genericHTTP, Cache: c}
		}, genericHTTP},
		"authorization": {func(c EvaluatorCache) auth.AuthConfigEvaluator {
			return &AuthorizationConfig{Name: "x", JSON: patternMatching, Cache: c}
		}, patternMatching},
		"response": {func(c EvaluatorCache) auth.AuthConfigEvaluator {
			return &ResponseConfig{Name: "x", Plain: plain, Cache: c}
		}, plain},
	} {
		t.Run(name, func(t *testing.T) {
			cache := &recordingCache{}
			config := tc.config(cache)

			obj, err := config.Call(mock_auth.NewMockAuthPipeline(gomock.NewController(t)), t.Context())

			assert.NilError(t, err)
			assert.Equal(t, obj, "from cache")
			assert.Equal(t, cache.calls, 1)
			assert.Equal(t, cache.config, config.(metrics.Object))
			assert.Equal(t, cache.evaluator, tc.evaluator)
		})
	}
}
