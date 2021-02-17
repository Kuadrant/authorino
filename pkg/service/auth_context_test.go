package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/3scale-labs/authorino/pkg/config"
	"github.com/3scale-labs/authorino/pkg/config/common"
	"gotest.tools/assert"
)

type successConfig struct{}
type failConfig struct{}

func (c *successConfig) Call(ctx common.AuthContext) (interface{}, error) {
	return nil, nil
}

func (c *failConfig) Call(ctx common.AuthContext) (interface{}, error) {
	return nil, fmt.Errorf("Failed")
}

func newAuthContext(identityConfigs []common.AuthConfigEvaluator) AuthContext {
	apiConfig := config.APIConfig{
		Enabled:              true,
		IdentityConfigs:      identityConfigs,
		MetadataConfigs:      nil,
		AuthorizationConfigs: nil,
	}

	return NewAuthContext(context.TODO(), nil, apiConfig)
}

func TestEvaluateOneAuthConfig(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &failConfig{})
	authContext := newAuthContext(identityConfigs)

	swap := false
	err := authContext.evaluateOneAuthConfig(
		authContext.API.IdentityConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			swap = true
		},
	)
	assert.NilError(t, err)
	assert.Check(t, swap)
}

func TestEvaluateOneAuthConfigWithoutSuccess(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &failConfig{}, &failConfig{})
	authContext := newAuthContext(identityConfigs)

	swap := false
	err := authContext.evaluateOneAuthConfig(
		authContext.API.IdentityConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			swap = true
		},
	)
	assert.Error(t, err, "Failed")
	assert.Check(t, !swap)
}

func TestEvaluateOneAuthConfigWithoutError(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &successConfig{})
	authContext := newAuthContext(identityConfigs)

	swap := false
	err := authContext.evaluateOneAuthConfig(
		authContext.API.IdentityConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			swap = true
		},
	)
	assert.NilError(t, err)
	assert.Check(t, swap)
}

func TestEvaluateAllAuthConfigs(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &successConfig{})
	authContext := newAuthContext(identityConfigs)

	swap := false
	err := authContext.evaluateAllAuthConfigs(
		authContext.API.IdentityConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			swap = true
		},
	)
	assert.NilError(t, err)
	assert.Check(t, swap)
}

func TestEvaluateAllAuthConfigsWithError(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &failConfig{})
	authContext := newAuthContext(identityConfigs)

	swap := false
	err := authContext.evaluateAllAuthConfigs(
		authContext.API.IdentityConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			swap = true
		},
	)
	assert.Error(t, err, "Failed")
	assert.Check(t, !swap)
}

func TestEvaluateAnyAuthConfig(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &successConfig{})
	authContext := newAuthContext(identityConfigs)

	swap := false
	authContext.evaluateAnyAuthConfig(
		authContext.API.IdentityConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			swap = true
		},
	)
	assert.Check(t, swap)
}

func TestEvaluateAnyAuthConfigsWithoutSuccess(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &failConfig{}, &failConfig{})
	authContext := newAuthContext(identityConfigs)

	swap := false
	authContext.evaluateAnyAuthConfig(
		authContext.API.IdentityConfigs,
		func(conf common.AuthConfigEvaluator, authObj interface{}) {
			swap = true
		},
	)
	assert.Check(t, !swap)
}
