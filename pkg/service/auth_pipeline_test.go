package service

import (
	"context"
	gojson "encoding/json"
	"fmt"
	"testing"

	"github.com/kuadrant/authorino/pkg/auth"
	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/evaluators"
	"github.com/kuadrant/authorino/pkg/evaluators/authorization"
	"github.com/kuadrant/authorino/pkg/evaluators/identity"
	"github.com/kuadrant/authorino/pkg/httptest"
	"github.com/kuadrant/authorino/pkg/json"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

const (
	rawRequest string = `{
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

	oidcServerHost = "127.0.0.1:9009"
)

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

func newTestAuthPipeline(authConfig evaluators.AuthConfig, req *envoy_auth.CheckRequest) *AuthPipeline {
	p := NewAuthPipeline(context.TODO(), req, authConfig)
	pipeline, _ := p.(*AuthPipeline)
	return pipeline
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

	idConfig1 := &evaluators.IdentityConfig{Priority: 0, Noop: &identity.Noop{}} // since it's going to be called and succeed, it has to be an actual config.IdentityConfig because AuthPipeline depends on it
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

	idConfig := &evaluators.IdentityConfig{Noop: &identity.Noop{}} // since it's going to be called and succeed, it has to be an actual config.IdentityConfig because AuthPipeline depends on it
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

	idConfig := &evaluators.IdentityConfig{Noop: &identity.Noop{}} // since it's going to be called and succeed, it has to be an actual config.IdentityConfig because AuthPipeline depends on it
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

	idConfig := &evaluators.IdentityConfig{Noop: &identity.Noop{}} // since it's going to be called and succeed, it has to be an actual config.IdentityConfig because AuthPipeline depends on it
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

func BenchmarkAuthPipeline(b *testing.B) {
	request := envoy_auth.CheckRequest{}
	_ = gojson.Unmarshal([]byte(rawRequest), &request)

	ctrl := gomock.NewController(b)
	defer ctrl.Finish()

	authServer := httptest.NewHttpServerMock(oidcServerHost, map[string]httptest.HttpServerMockResponseFunc{
		"/.well-known/openid-configuration": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{
				Status:  200,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    fmt.Sprintf(`{ "issuer": "http://%v", "authorization_endpoint": "http://%v/auth", "jwks_uri": "http://%v/jwks" }`, oidcServerHost, oidcServerHost, oidcServerHost),
			}
		},
		"/jwks": func() httptest.HttpServerMockResponse {
			return httptest.HttpServerMockResponse{
				Status:  200,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    `{"keys":[{"kid":"yrm-Ijpxd_wwsVfOGQTYa64uftEe8v7TnlC1L-IxeII","kty":"RSA","alg":"RS256","use":"sig","n":"qg4_I36bRzbiWGu0Zu3TAxpkHDyr0syUDaDnKpiEw9MJBEjSHgt1DixlskaHCXHchfkTrUuS9ugcayJAAF0KQ6S48hvvALNAVXW9anHoX6armV5K2-gwDMob35WYyfb-2jgxa457YKrL_sm-lLagyhVnrK-pV5lLRHPG3G6xiXtDs9xgPykQcGz0rW7H1Ppiz5WiSdOw3YsigfIZwW0SuOsQSSi_yAsfoUzcIXBeGOnmwi0XLgaC4qp1hf1z25pyF2Z2_IPac8ERqnxf2tGoi_blkk5Gq7SNDrkyWmrVeOKyw93xRHgmVoMKOBiP-uYUY7hY9PUJwctKerb84R88Yw","e":"AQAB","x5c":["MIICnzCCAYcCBgGCSVmJ+jANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhrdWFkcmFudDAeFw0yMjA3MjkwOTQ0NDFaFw0zMjA3MjkwOTQ2MjFaMBMxETAPBgNVBAMMCGt1YWRyYW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqg4/I36bRzbiWGu0Zu3TAxpkHDyr0syUDaDnKpiEw9MJBEjSHgt1DixlskaHCXHchfkTrUuS9ugcayJAAF0KQ6S48hvvALNAVXW9anHoX6armV5K2+gwDMob35WYyfb+2jgxa457YKrL/sm+lLagyhVnrK+pV5lLRHPG3G6xiXtDs9xgPykQcGz0rW7H1Ppiz5WiSdOw3YsigfIZwW0SuOsQSSi/yAsfoUzcIXBeGOnmwi0XLgaC4qp1hf1z25pyF2Z2/IPac8ERqnxf2tGoi/blkk5Gq7SNDrkyWmrVeOKyw93xRHgmVoMKOBiP+uYUY7hY9PUJwctKerb84R88YwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAoylFEufa8mPcXFAJiVHadf93x7ztk1ven1U3GEI4VVScIZfayQ00EmrHM7M4fFaoX+lTx6LN8gUIer1ZZLRmDVjtY8JW9rA7v4l7Z7lONSndpPxD3l0UIuwHGddhCeELDzLuAJt9TBuhHKOgqlWCeya0q0do0AHQBypxLnIGmnI3n2SXCmPGek4gZszNqollVNnOoy4qcG7a6Dxhm6rEnY8l8k9N7EiqP1UJrvaTR+8MSRt3lSWeKnFLlCp71qkUDIMx7l93xCpn2HgT1ZZGQmDPMpCHRoJgoZ0zLUi0b6oiecYeAPUtBMvfHEDIaH2p2zF3S2o/GoXSK8lkp+aSs"],"x5t":"S8Z1Rpj43bGOC3V6iq-TI-6HxME","x5t#S256":"QOlqJE_mRnZQQttd4x5SxZpCcsGDyEsWUP8KeEwsbCY"}]}`,
			}
		},
	})
	defer authServer.Close()

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsKeySelector().Return("Bearer").AnyTimes() // this will only be invoked if the access token below is expired
	authCredMock.EXPECT().GetCredentialsFromReq(gomock.Any()).Return("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5cm0tSWpweGRfd3dzVmZPR1FUWWE2NHVmdEVlOHY3VG5sQzFMLUl4ZUlJIn0.eyJleHAiOjIxNDU4NjU3NzMsImlhdCI6MTY1OTA4ODE3MywianRpIjoiZDI0ODliMWEtYjY0Yi00MzRhLWJhNmItMmQ4OGIyY2I1ZWE3IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjgwODAvYXV0aC9yZWFsbXMva3VhZHJhbnQiLCJhdWQiOlsicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiMWEwYjZjNmUtNDdmNy00ZjI1LWEyNjYtYzg3MzZhOTkxODQ0IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZGVtbyIsInNlc3Npb25fc3RhdGUiOiIxMTdkMTc1Ni1mM2RlLTRjM2MtOWEwZS0zYjU5Mzc2YmI0ZTgiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwibWVtYmVyIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwidmlldy1yZWFsbSIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwicmVhbG0tYWRtaW4iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjExN2QxNzU2LWYzZGUtNGMzYy05YTBlLTNiNTkzNzZiYjRlOCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IlBldGVyIFdobyIsInByZWZlcnJlZF91c2VybmFtZSI6InBldGVyIiwiZ2l2ZW5fbmFtZSI6IlBldGVyIiwiZmFtaWx5X25hbWUiOiJXaG8iLCJlbWFpbCI6InBldGVyQGt1YWRyYW50LmlvIn0.Yy2aWR6_u0NBLx8x--OToYipfQ1f1KcC8zedsKDiymcbBiAaxrBQmaV2JC1PQVEgyxwmyMk0Rao2MdKGWk6pXB9mTUF5FX-pS8mkPIMUt1UVGJgzq7WR9KfRqdZSzRtFQHoDmTeA1-msayMYTAD8xtUH4JYRNbIXjY2cEtn8LjuLpQVR3DR4_ARMrEYXiDBS3rmmFKHdipqU7ozwJ_gtpZv8vfeiO3mUPyQLJKQ-nKpe_Z5z7tm_Ewh5MN2oBfn_0pcdANB3pe2RclGAm-YHlyNDTnAZL2Y1gdCmwzwigk7AJcgWtPqnRzvEQ9zRBxQRai5W5aNKYTxuKIG8k9N05w", nil).MinTimes(1)
	idConfig := &evaluators.IdentityConfig{OIDC: identity.NewOIDC(fmt.Sprintf("http://%v", oidcServerHost), authCredMock, 0, context.TODO())}
	authzConfig := &evaluators.AuthorizationConfig{JSON: &authorization.JSONPatternMatching{Rules: []json.JSONPatternMatchingRule{{Selector: "auth.identity.realm_access.roles", Operator: "incl", Value: "member"}}}}
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{IdentityConfigs: []auth.AuthConfigEvaluator{idConfig}, AuthorizationConfigs: []auth.AuthConfigEvaluator{authzConfig}}, &request)

	var r auth.AuthResult
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r = pipeline.Evaluate()
	}
	b.StopTimer()
	assert.DeepEqual(b, r.Message, "")
	assert.DeepEqual(b, r.Code, rpc.OK)
}
