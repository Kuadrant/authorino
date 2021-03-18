package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/3scale-labs/authorino/pkg/common"
	"github.com/3scale-labs/authorino/pkg/config"
	"gotest.tools/assert"
)

type successConfig struct{}
type failConfig struct{}

func (c *successConfig) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	return nil, nil
}

func (c *failConfig) Call(authContext common.AuthContext, ctx context.Context) (interface{}, error) {
	return nil, fmt.Errorf("Failed")
}

func newAuthContext(identityConfigs []common.AuthConfigEvaluator) AuthContext {
	apiConfig := config.APIConfig{
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
	respChannel := make(chan EvaluationResponse, 2)

	swap := false

	go func() {
		defer close(respChannel)
		authContext.evaluateOneAuthConfig(authContext.API.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if resp.Success() {
			swap = true
		}
	}

	assert.Check(t, swap)
}

func TestEvaluateOneAuthConfigWithoutSuccess(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &failConfig{}, &failConfig{})
	authContext := newAuthContext(identityConfigs)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		authContext.evaluateOneAuthConfig(authContext.API.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if resp.Success() {
			swap = true
		} else {
			err = resp.Error
		}
	}

	assert.Check(t, !swap)
	assert.Error(t, err, "Failed")
}

func TestEvaluateOneAuthConfigWithoutError(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &successConfig{})
	authContext := newAuthContext(identityConfigs)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		authContext.evaluateOneAuthConfig(authContext.API.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if resp.Success() {
			swap = true
		} else {
			err = resp.Error
		}
	}

	assert.Check(t, swap)
	assert.NilError(t, err)
}

func TestEvaluateAllAuthConfigs(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &successConfig{})
	authContext := newAuthContext(identityConfigs)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		authContext.evaluateAllAuthConfigs(authContext.API.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if resp.Success() {
			swap = true
		} else {
			err = resp.Error
		}
	}

	assert.Check(t, swap)
	assert.NilError(t, err)
}

func TestEvaluateAllAuthConfigsWithError(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &failConfig{})
	authContext := newAuthContext(identityConfigs)
	respChannel := make(chan EvaluationResponse, 2)

	var err error

	go func() {
		defer close(respChannel)
		authContext.evaluateAllAuthConfigs(authContext.API.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if !resp.Success() {
			err = resp.Error
		}
	}

	assert.Error(t, err, "Failed")
}

func TestEvaluateAllAuthConfigsWithoutSuccess(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &failConfig{}, &failConfig{})
	authContext := newAuthContext(identityConfigs)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		authContext.evaluateAllAuthConfigs(authContext.API.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if resp.Success() {
			swap = true
		} else {
			err = resp.Error
		}
	}

	assert.Check(t, !swap)
	assert.Error(t, err, "Failed")
}

func TestEvaluateAnyAuthConfig(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &failConfig{})
	authContext := newAuthContext(identityConfigs)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		authContext.evaluateAnyAuthConfig(authContext.API.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if resp.Success() {
			swap = true
		} else {
			err = resp.Error
		}
	}

	assert.Check(t, swap)
	assert.Error(t, err, "Failed")
}

func TestEvaluateAnyAuthConfigsWithoutSuccess(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &failConfig{}, &failConfig{})
	authContext := newAuthContext(identityConfigs)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		authContext.evaluateAnyAuthConfig(authContext.API.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if resp.Success() {
			swap = true
		} else {
			err = resp.Error
		}
	}

	assert.Check(t, !swap)
	assert.Error(t, err, "Failed")
}

func TestEvaluateAnyAuthConfigsWithoutError(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &successConfig{})
	authContext := newAuthContext(identityConfigs)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		authContext.evaluateAnyAuthConfig(authContext.API.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if resp.Success() {
			swap = true
		} else {
			err = resp.Error
		}
	}

	assert.Check(t, swap)
	assert.NilError(t, err)
}
