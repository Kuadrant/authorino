package service

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"gotest.tools/assert"

	"github.com/kuadrant/authorino/pkg/common"
	"github.com/kuadrant/authorino/pkg/config"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

const (
	rawRequest string = `{
		"attributes": {
			"request": {
				"http": {
					"headers": {
						"authorization": "Bearer n3ex87bye9238ry8"
					}
				}
			}
		}
	}`
)

type successConfig struct{}
type failConfig struct{}

func (c *successConfig) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	return nil, nil
}

func (c *failConfig) Call(pipeline common.AuthPipeline, ctx context.Context) (interface{}, error) {
	return nil, fmt.Errorf("Failed")
}

func newAuthPipeline(identityConfigs []common.AuthConfigEvaluator, req *envoy_auth.CheckRequest) AuthPipeline {
	metadataConfigs := make([]common.AuthConfigEvaluator, 0)
	authorizationConfigs := make([]common.AuthConfigEvaluator, 0)

	apiConfig := config.APIConfig{
		IdentityConfigs:      identityConfigs,
		MetadataConfigs:      metadataConfigs,
		AuthorizationConfigs: authorizationConfigs,
	}

	return NewAuthPipeline(context.TODO(), req, apiConfig)
}

func TestEvaluateOneAuthConfig(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{}, &failConfig{})
	pipeline := newAuthPipeline(identityConfigs, nil)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false

	go func() {
		defer close(respChannel)
		pipeline.evaluateOneAuthConfig(pipeline.API.IdentityConfigs, &respChannel)
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
	pipeline := newAuthPipeline(identityConfigs, nil)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateOneAuthConfig(pipeline.API.IdentityConfigs, &respChannel)
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
	pipeline := newAuthPipeline(identityConfigs, nil)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateOneAuthConfig(pipeline.API.IdentityConfigs, &respChannel)
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
	pipeline := newAuthPipeline(identityConfigs, nil)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAllAuthConfigs(pipeline.API.IdentityConfigs, &respChannel)
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
	pipeline := newAuthPipeline(identityConfigs, nil)
	respChannel := make(chan EvaluationResponse, 2)

	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAllAuthConfigs(pipeline.API.IdentityConfigs, &respChannel)
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
	pipeline := newAuthPipeline(identityConfigs, nil)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAllAuthConfigs(pipeline.API.IdentityConfigs, &respChannel)
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
	pipeline := newAuthPipeline(identityConfigs, nil)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAnyAuthConfig(pipeline.API.IdentityConfigs, &respChannel)
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
	pipeline := newAuthPipeline(identityConfigs, nil)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAnyAuthConfig(pipeline.API.IdentityConfigs, &respChannel)
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
	pipeline := newAuthPipeline(identityConfigs, nil)
	respChannel := make(chan EvaluationResponse, 2)

	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAnyAuthConfig(pipeline.API.IdentityConfigs, &respChannel)
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

func TestGetDataForAuthorization(t *testing.T) {
	var identityConfigs []common.AuthConfigEvaluator
	identityConfigs = append(identityConfigs, &successConfig{})
	request := envoy_auth.CheckRequest{}
	_ = json.Unmarshal([]byte(rawRequest), &request)
	pipeline := newAuthPipeline(identityConfigs, &request)
	data := pipeline.GetDataForAuthorization()
	if dataJSON, err := json.Marshal(&data); err != nil {
		t.Error(err)
	} else {
		requestJSON, _ := json.Marshal(request.GetAttributes())
		expectedJSON := fmt.Sprintf(`{"context":%s,"auth":{"identity":null,"metadata":{}}}`, requestJSON)
		assert.Equal(t, expectedJSON, string(dataJSON))
	}
}
