package service

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/kuadrant/authorino/pkg/common"
	mock_auth_credentials "github.com/kuadrant/authorino/pkg/common/auth_credentials/mocks"
	"github.com/kuadrant/authorino/pkg/config"
	"github.com/kuadrant/authorino/pkg/config/identity"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

const rawRequest string = `{
	"attributes": {
		"request": {
			"http": {
				"host": "my-api",
				"path": "/operation",
				"method": "GET",
				"headers": {
					"authorization": "Bearer n3ex87bye9238ry8"
				}
			}
		}
	}
}`

var (
	requestMock = envoy_auth.CheckRequest{}
	_           = json.Unmarshal([]byte(rawRequest), &requestMock)
)

type successConfig struct{}
type failConfig struct{}

func (c *successConfig) Call(_ common.AuthPipeline, _ context.Context) (interface{}, error) {
	return nil, nil
}

func (c *failConfig) Call(_ common.AuthPipeline, _ context.Context) (interface{}, error) {
	return nil, fmt.Errorf("Failed")
}

func newTestAuthPipeline(apiConfig config.APIConfig, req *envoy_auth.CheckRequest) AuthPipeline {
	p := NewAuthPipeline(context.TODO(), req, apiConfig)
	pipeline, _ := p.(*AuthPipeline)
	return *pipeline
}

func TestEvaluateOneAuthConfig(t *testing.T) {
	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&successConfig{}, &failConfig{}},
	}, &requestMock)

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
	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&failConfig{}, &failConfig{}},
	}, &requestMock)

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
	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&successConfig{}, &successConfig{}},
	}, &requestMock)

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
	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&successConfig{}, &successConfig{}},
	}, &requestMock)

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
	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&successConfig{}, &failConfig{}},
	}, &requestMock)

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
	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&failConfig{}, &failConfig{}},
	}, &requestMock)

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
	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&successConfig{}, &failConfig{}},
	}, &requestMock)

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
	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&failConfig{}, &failConfig{}},
	}, &requestMock)

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
	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&successConfig{}, &successConfig{}},
	}, &requestMock)

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
	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&successConfig{}, &successConfig{}},
	}, &requestMock)

	data := pipeline.GetDataForAuthorization()
	if dataJSON, err := json.Marshal(&data); err != nil {
		t.Error(err)
	} else {
		requestJSON, _ := json.Marshal(requestMock.GetAttributes())
		expectedJSON := fmt.Sprintf(`{"context":%s,"auth":{"identity":null,"metadata":{}}}`, requestJSON)
		assert.Equal(t, expectedJSON, string(dataJSON))
	}
}

func TestEvaluateWithCustomDenyOptions(t *testing.T) {
	request := envoy_auth.CheckRequest{}
	_ = json.Unmarshal([]byte(rawRequest), &request)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	authCredMock := mock_auth_credentials.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(request.GetAttributes().GetRequest().Http).Return("xxx", nil)
	authCredMock.EXPECT().GetCredentialsKeySelector().Return("APIKEY")

	pipeline := newTestAuthPipeline(config.APIConfig{
		IdentityConfigs: []common.AuthConfigEvaluator{&config.IdentityConfig{Name: "falty-api-key", APIKey: &identity.APIKey{AuthCredentials: authCredMock}}},
		DenyWith: config.DenyWith{
			Unauthenticated: &config.DenyWithValues{
				Code: 302,
				Headers: []common.JSONProperty{
					{Name: "X-Static-Header", Value: common.JSONValue{Static: "some-value"}},
					{Name: "Location", Value: common.JSONValue{Pattern: "https://my-app.io/login?redirect_to=https://{context.request.http.host}{context.request.http.path}"}},
				},
			},
		},
	}, &request)

	authResult := pipeline.Evaluate()
	assert.Equal(t, authResult.Code, rpc.UNAUTHENTICATED)
	assert.Equal(t, authResult.Status, envoy_type_v3.StatusCode_Found)
	assert.Equal(t, authResult.Message, "the API Key provided is invalid")
	assert.Equal(t, len(authResult.Headers), 2)
	headers, _ := json.Marshal(authResult.Headers)
	assert.Equal(t, string(headers), `[{"X-Static-Header":"some-value"},{"Location":"https://my-app.io/login?redirect_to=https://my-api/operation"}]`)
}
