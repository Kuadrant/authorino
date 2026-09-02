package evaluators

import (
	"context"
	"fmt"
	"strings"
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

type failingCleaner struct{ name string }

func (f *failingCleaner) Call(_ auth.AuthPipeline, _ context.Context) (interface{}, error) {
	return nil, nil
}
func (f *failingCleaner) GetName() string { return f.name }
func (f *failingCleaner) Clean(_ context.Context) error {
	return fmt.Errorf("failed to clean %s", f.name)
}

type panickingCleaner struct{ failingCleaner }

func (p *panickingCleaner) Clean(_ context.Context) error {
	panic("boom")
}

// Every cleaner that fails must be reported: the errors used to be accumulated with a shared
// read-modify-write, which races and can drop one.
func TestCleanReportsEveryFailure(t *testing.T) {
	config := &AuthConfig{IdentityConfigs: []auth.AuthConfigEvaluator{
		&failingCleaner{name: "one"},
		&failingCleaner{name: "two"},
		&failingCleaner{name: "three"},
		&failingCleaner{name: "four"},
	}}

	err := config.Clean(context.TODO())
	assert.Check(t, err != nil)

	for _, name := range []string{"one", "two", "three", "four"} {
		assert.Check(t, strings.Contains(err.Error(), "failed to clean "+name), "missing error for %q in %v", name, err)
	}
}

// A panicking cleaner must not take the process down, and must be reported rather than swallowed.
func TestCleanRecoversFromPanickingCleaner(t *testing.T) {
	config := &AuthConfig{IdentityConfigs: []auth.AuthConfigEvaluator{
		&panickingCleaner{failingCleaner{name: "kaboom"}},
		&failingCleaner{name: "one"},
	}}

	err := config.Clean(context.TODO())
	assert.Check(t, err != nil)
	assert.Check(t, strings.Contains(err.Error(), "recovered from panic"), "panic not reported: %v", err)
	assert.Check(t, strings.Contains(err.Error(), "kaboom"), "evaluator name not reported: %v", err)
	assert.Check(t, strings.Contains(err.Error(), "failed to clean one"), "other errors lost: %v", err)
}

// A panicking starter must not take the reconcile goroutine, and therefore the process, down.
func TestStartRecoversFromPanickingStarter(t *testing.T) {
	config := &AuthConfig{IdentityConfigs: []auth.AuthConfigEvaluator{
		&panickingStarter{name: "kaboom"},
	}}

	err := config.Start(context.TODO())
	assert.Check(t, err != nil)
	assert.Check(t, strings.Contains(err.Error(), "recovered from panic"), "panic not reported: %v", err)
	assert.Check(t, strings.Contains(err.Error(), "kaboom"), "evaluator name not reported: %v", err)
}

type panickingStarter struct{ name string }

func (p *panickingStarter) Call(_ auth.AuthPipeline, _ context.Context) (interface{}, error) {
	return nil, nil
}
func (p *panickingStarter) GetName() string               { return p.name }
func (p *panickingStarter) Start(_ context.Context) error { panic("boom") }
