package evaluators

import (
	"context"
	"testing"

	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"

	"go.uber.org/mock/gomock"
	"gotest.tools/assert"
)

type authConfigEvaluatorCleanerMock struct {
	cleaned bool
}

func (a authConfigEvaluatorCleanerMock) Call(_ auth.AuthPipeline, _ context.Context) (interface{}, error) {
	return nil, nil
}
func (a *authConfigEvaluatorCleanerMock) Clean(_ context.Context) error {
	a.cleaned = true
	return nil
}

func TestCleanConfig(t *testing.T) {
	ctrl := gomock.NewController(t)

	ev1a := mock_auth.NewMockAuthConfigEvaluator(ctrl)
	ev1b := &authConfigEvaluatorCleanerMock{}
	ev2a := mock_auth.NewMockAuthConfigEvaluator(ctrl)
	ev2b := &authConfigEvaluatorCleanerMock{}
	ev3a := mock_auth.NewMockAuthConfigEvaluator(ctrl)
	ev3b := &authConfigEvaluatorCleanerMock{}
	ev4a := mock_auth.NewMockAuthConfigEvaluator(ctrl)
	ev4b := &authConfigEvaluatorCleanerMock{}
	ev5a := mock_auth.NewMockAuthConfigEvaluator(ctrl)
	ev5b := &authConfigEvaluatorCleanerMock{}

	config := AuthConfig{
		IdentityConfigs:      []auth.AuthConfigEvaluator{ev1a, ev1b},
		MetadataConfigs:      []auth.AuthConfigEvaluator{ev2a, ev2b},
		AuthorizationConfigs: []auth.AuthConfigEvaluator{ev3a, ev3b},
		ResponseConfigs:      []auth.AuthConfigEvaluator{ev4a, ev4b},
		CallbackConfigs:      []auth.AuthConfigEvaluator{ev5a, ev5b},
	}

	err := config.Clean(context.Background())
	assert.NilError(t, err)
	for _, ev := range []*authConfigEvaluatorCleanerMock{ev1b, ev2b, ev3b, ev4b, ev5b} {
		assert.Check(t, ev.cleaned)
	}
}
