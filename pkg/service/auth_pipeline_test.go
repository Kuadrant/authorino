package service

import (
	"context"
	gojson "encoding/json"
	"fmt"
	"testing"

	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/evaluators/identity"
	"github.com/kuadrant/authorino/pkg/json"

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
	_           = gojson.Unmarshal([]byte(rawRequest), &requestMock)
)

type successConfig struct {
	called     bool
	priority   int
	conditions []json.JSONPatternMatchingRule
}

type failConfig struct {
	called   bool
	priority int
}

func (c *successConfig) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	c.called = true
	return nil, nil
}

func (c *successConfig) GetPriority() int {
	return c.priority
}

func (c *successConfig) GetConditions() []json.JSONPatternMatchingRule {
	return c.conditions
}

func (c *failConfig) Call(pipeline auth.AuthPipeline, ctx context.Context) (interface{}, error) {
	c.called = true
	return nil, fmt.Errorf("Failed")
}

func (c *failConfig) GetPriority() int {
	return c.priority
}

func newTestAuthPipeline(authConfig evaluators.AuthConfig, req *envoy_auth.CheckRequest) AuthPipeline {
	p := NewAuthPipeline(context.TODO(), req, authConfig)
	pipeline, _ := p.(*AuthPipeline)
	return *pipeline
}

func TestEvaluateOneAuthConfig(t *testing.T) {
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&successConfig{}, &failConfig{}},
	}, &requestMock)

	respChannel := make(chan EvaluationResponse, 2)
	swap := false

	go func() {
		defer close(respChannel)
		pipeline.evaluateOneAuthConfig(pipeline.AuthConfig.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if resp.Success() {
			swap = true
		}
	}

	assert.Check(t, swap)
}

func TestEvaluateOneAuthConfigWithoutSuccess(t *testing.T) {
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&failConfig{}, &failConfig{}},
	}, &requestMock)

	respChannel := make(chan EvaluationResponse, 2)
	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateOneAuthConfig(pipeline.AuthConfig.IdentityConfigs, &respChannel)
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
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&successConfig{}, &successConfig{}},
	}, &requestMock)

	respChannel := make(chan EvaluationResponse, 2)
	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateOneAuthConfig(pipeline.AuthConfig.IdentityConfigs, &respChannel)
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
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&successConfig{}, &successConfig{}},
	}, &requestMock)

	respChannel := make(chan EvaluationResponse, 2)
	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAllAuthConfigs(pipeline.AuthConfig.IdentityConfigs, &respChannel)
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
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&successConfig{}, &failConfig{}},
	}, &requestMock)

	respChannel := make(chan EvaluationResponse, 2)
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAllAuthConfigs(pipeline.AuthConfig.IdentityConfigs, &respChannel)
	}()

	for resp := range respChannel {
		if !resp.Success() {
			err = resp.Error
		}
	}

	assert.Error(t, err, "Failed")
}

func TestEvaluateAllAuthConfigsWithoutSuccess(t *testing.T) {
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&failConfig{}, &failConfig{}},
	}, &requestMock)

	respChannel := make(chan EvaluationResponse, 2)
	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAllAuthConfigs(pipeline.AuthConfig.IdentityConfigs, &respChannel)
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
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&successConfig{}, &failConfig{}},
	}, &requestMock)

	respChannel := make(chan EvaluationResponse, 2)
	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAnyAuthConfig(pipeline.AuthConfig.IdentityConfigs, &respChannel)
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
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&failConfig{}, &failConfig{}},
	}, &requestMock)

	respChannel := make(chan EvaluationResponse, 2)
	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAnyAuthConfig(pipeline.AuthConfig.IdentityConfigs, &respChannel)
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
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&successConfig{}, &successConfig{}},
	}, &requestMock)

	respChannel := make(chan EvaluationResponse, 2)
	swap := false
	var err error

	go func() {
		defer close(respChannel)
		pipeline.evaluateAnyAuthConfig(pipeline.AuthConfig.IdentityConfigs, &respChannel)
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

func TestAuthPipelineGetAuthorizationJSON(t *testing.T) {
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&successConfig{}, &successConfig{}},
	}, &requestMock)

	requestJSON, _ := gojson.Marshal(requestMock.GetAttributes())
	expectedJSON := fmt.Sprintf(`{"context":%s,"auth":{"authorization":{},"identity":null,"metadata":{},"response":{}}}`, requestJSON)
	assert.Equal(t, pipeline.GetAuthorizationJSON(), expectedJSON)
}

func TestEvaluateWithCustomDenyOptions(t *testing.T) {
	request := envoy_auth.CheckRequest{}
	_ = gojson.Unmarshal([]byte(rawRequest), &request)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsFromReq(request.GetAttributes().GetRequest().Http).Return("xxx", nil)
	authCredMock.EXPECT().GetCredentialsKeySelector().Return("APIKEY")
	authConfigStaticResponse := "testing"

	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs: []auth.AuthConfigEvaluator{&evaluators.IdentityConfig{Name: "faulty-api-key", APIKey: &identity.APIKey{AuthCredentials: authCredMock}}},
		DenyWith: evaluators.DenyWith{
			Unauthenticated: &evaluators.DenyWithValues{
				Code: 302,
				Headers: []json.JSONProperty{
					{Name: "X-Static-Header", Value: json.JSONValue{Static: "some-value"}},
					{Name: "Location", Value: json.JSONValue{Pattern: "https://my-app.io/login?redirect_to=https://{context.request.http.host}{context.request.http.path}"}},
				},
				Body: &json.JSONValue{
					Static: authConfigStaticResponse,
				},
			},
		},
	}, &request)

	authResult := pipeline.Evaluate()
	assert.Equal(t, authResult.Code, rpc.UNAUTHENTICATED)
	assert.Equal(t, authResult.Status, envoy_type_v3.StatusCode_Found)
	assert.Equal(t, authResult.Message, "the API Key provided is invalid")
	assert.Equal(t, authResult.Body, authConfigStaticResponse)

	assert.Equal(t, len(authResult.Headers), 2)
	headers, _ := gojson.Marshal(authResult.Headers)
	assert.Equal(t, string(headers), `[{"X-Static-Header":"some-value"},{"Location":"https://my-app.io/login?redirect_to=https://my-api/operation"}]`)
}

func TestEvaluatePriorities(t *testing.T) {
	request := envoy_auth.CheckRequest{}
	_ = gojson.Unmarshal([]byte(rawRequest), &request)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	idConfig1 := &evaluators.IdentityConfig{Priority: 0, MTLS: &identity.MTLS{}} // since it's going to be called and succeed, it has to be an actual config.IdentityConfig because AuthPipeline depends on it
	idConfig2 := &failConfig{priority: 1}                                        // should never be called; otherwise, it would throw an error as it's not a config.IdentityConfig

	authzConfig1 := &failConfig{priority: 0}
	authzConfig2 := &successConfig{priority: 1} // should never be called

	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs:      []auth.AuthConfigEvaluator{idConfig1, idConfig2},
		AuthorizationConfigs: []auth.AuthConfigEvaluator{authzConfig1, authzConfig2},
	}, &request)

	_ = pipeline.Evaluate()

	assert.Check(t, !idConfig2.called)
	assert.Check(t, authzConfig1.called)
	assert.Check(t, !authzConfig2.called)
}

func TestAuthPipelineWithUnmatchingConditionsInTheAuthConfig(t *testing.T) {
	request := envoy_auth.CheckRequest{}
	_ = gojson.Unmarshal([]byte(rawRequest), &request)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	idConfig := &successConfig{}

	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		Conditions: []json.JSONPatternMatchingRule{
			{
				Selector: "context.request.http.path",
				Operator: "neq",
				Value:    "/operation",
			},
		},
		IdentityConfigs: []auth.AuthConfigEvaluator{idConfig},
	}, &request)

	_ = pipeline.Evaluate()

	assert.Check(t, !idConfig.called)
}

func TestAuthPipelineWithMatchingConditionsInTheAuthConfig(t *testing.T) {
	request := envoy_auth.CheckRequest{}
	_ = gojson.Unmarshal([]byte(rawRequest), &request)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	idConfig := &evaluators.IdentityConfig{MTLS: &identity.MTLS{}} // since it's going to be called and succeed, it has to be an actual config.IdentityConfig because AuthPipeline depends on it
	authzConfig := &successConfig{}

	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		Conditions: []json.JSONPatternMatchingRule{
			{
				Selector: "context.request.http.path",
				Operator: "eq",
				Value:    "/operation",
			},
		},
		IdentityConfigs:      []auth.AuthConfigEvaluator{idConfig},
		AuthorizationConfigs: []auth.AuthConfigEvaluator{authzConfig},
	}, &request)

	_ = pipeline.Evaluate()

	assert.Check(t, authzConfig.called)
}

func TestAuthPipelineWithUnmatchingConditionsInTheEvaluator(t *testing.T) {
	request := envoy_auth.CheckRequest{}
	_ = gojson.Unmarshal([]byte(rawRequest), &request)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	idConfig := &evaluators.IdentityConfig{MTLS: &identity.MTLS{}} // since it's going to be called and succeed, it has to be an actual config.IdentityConfig because AuthPipeline depends on it
	authzConfig := &successConfig{
		conditions: []json.JSONPatternMatchingRule{
			{
				Selector: "context.request.http.path",
				Operator: "neq",
				Value:    "/operation",
			},
		},
	}

	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs:      []auth.AuthConfigEvaluator{idConfig},
		AuthorizationConfigs: []auth.AuthConfigEvaluator{authzConfig},
	}, &request)

	_ = pipeline.Evaluate()

	assert.Check(t, !authzConfig.called)
}

func TestAuthPipelineWithMatchingConditionsInTheEvaluator(t *testing.T) {
	request := envoy_auth.CheckRequest{}
	_ = gojson.Unmarshal([]byte(rawRequest), &request)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	idConfig := &evaluators.IdentityConfig{MTLS: &identity.MTLS{}} // since it's going to be called and succeed, it has to be an actual config.IdentityConfig because AuthPipeline depends on it
	authzConfig := &successConfig{
		conditions: []json.JSONPatternMatchingRule{
			{
				Selector: "context.request.http.path",
				Operator: "eq",
				Value:    "/operation",
			},
		},
	}

	pipeline := newTestAuthPipeline(evaluators.AuthConfig{
		IdentityConfigs:      []auth.AuthConfigEvaluator{idConfig},
		AuthorizationConfigs: []auth.AuthConfigEvaluator{authzConfig},
	}, &request)

	_ = pipeline.Evaluate()

	assert.Check(t, authzConfig.called)
}
