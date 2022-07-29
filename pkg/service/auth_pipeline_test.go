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
				Body:    `{"keys":[{"kid":"3nJdoKgZqecCAAnPxV6gBtydpvTDFHSfb1HL8jyV4-Q","kty":"RSA","alg":"RS256","use":"sig","n":"oaDJSwhWoVKKzNNWChUTNRHZJEqwF12YQbt6SYynS0eWeFERj69NuBQ62ain73SIKr3bfFk2KY5ycarwTibXApKdj2c-Y9Ytt6CY1J5n5nI-J6tZWJK8-1M4RW6WKBUgofQ-FNz45mNjaUK5DNFExPhAKqTBKBjWo5SJAVJ2KKSvstr1FsiPgmlOIQdQSRtx4TcLFNNrBt4MPnIk91KAAgxXYoaL9hXSP9eVXipN2p6I6ZzPPj4LQRNjZu5SkPhtnGiz96eOB3lMajeM0kDycK3eZgG_-cq26pew3Wws7glC3H8SHze_hisDnCnaWr0v3udoNWBKyMGlVDHWEMNgBw","e":"AQAB","x5c":["MIICnzCCAYcCBgGCQDT/jzANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhrdWFkcmFudDAeFw0yMjA3MjcxNTA4MTFaFw0zMjA3MjcxNTA5NTFaMBMxETAPBgNVBAMMCGt1YWRyYW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoaDJSwhWoVKKzNNWChUTNRHZJEqwF12YQbt6SYynS0eWeFERj69NuBQ62ain73SIKr3bfFk2KY5ycarwTibXApKdj2c+Y9Ytt6CY1J5n5nI+J6tZWJK8+1M4RW6WKBUgofQ+FNz45mNjaUK5DNFExPhAKqTBKBjWo5SJAVJ2KKSvstr1FsiPgmlOIQdQSRtx4TcLFNNrBt4MPnIk91KAAgxXYoaL9hXSP9eVXipN2p6I6ZzPPj4LQRNjZu5SkPhtnGiz96eOB3lMajeM0kDycK3eZgG/+cq26pew3Wws7glC3H8SHze/hisDnCnaWr0v3udoNWBKyMGlVDHWEMNgBwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBFW5Y9ToZE1bFRZPSQP25oqVHqIAjRhU+39BBLr1HxQU+J76tEpFczWFxeb7N8JF7/BWQGVAt4W8YEdd5R1FfmVXXHlgUWwvaPZ6LE1vHpq323ZpUBXwNnQVlP5SV+kYwAMrhNWcBw4I0qZEwhyB1yPxCFAR84GQSqKYGltgnosoG2zkPfibpUuNnG6Dnhuyw+neBa9gVaeuxpnw5rObjZYylbNaGH/qM5fvvJDIrzTweALJfBomqPs+M3yK8iJ2SebHQAJ3YewVS5+IrohRRdOSuON4UEmA8wNtBYlO1TsdHYTAr6frrYmhka54X1zuTqWoWZnjuKcR/N5OAp1vHk"],"x5t":"l9mNQ2xgVVuLzCWYsVSaPkVMaFg","x5t#S256":"LKtSmAc2mMhvfzPXyIAYzFOIFt2rHwL-YbJobdnkMpU"}]}`,
			}
		},
	})
	defer authServer.Close()

	authCredMock := mock_auth.NewMockAuthCredentials(ctrl)
	authCredMock.EXPECT().GetCredentialsKeySelector().Return("Bearer").AnyTimes() // this will only be invoked if the access token below is expired
	authCredMock.EXPECT().GetCredentialsFromReq(gomock.Any()).Return("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIzbkpkb0tnWnFlY0NBQW5QeFY2Z0J0eWRwdlRERkhTZmIxSEw4anlWNC1RIn0.eyJleHAiOjE2NTg5Nzg2OTUsImlhdCI6MTY1ODk0MjY5NSwianRpIjoiOTM3N2NlOTktNDY4OC00MTgyLWE1OGYtOTlmZDVhYzAxYmVjIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjgwODAvYXV0aC9yZWFsbXMva3VhZHJhbnQiLCJhdWQiOlsicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiYTQ4Njc2MDgtNGM5Ni00M2UyLThhNzItMWE4ZjYwYWYyNWIxIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiZGVtbyIsInNlc3Npb25fc3RhdGUiOiJlNGU4NWZlYi1kY2UxLTRjNGItYWExZC00ZDliZWZlMmJiNDciLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwibWVtYmVyIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwidmlldy1yZWFsbSIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwicmVhbG0tYWRtaW4iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6ImU0ZTg1ZmViLWRjZTEtNGM0Yi1hYTFkLTRkOWJlZmUyYmI0NyIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6IlBldGVyIFdobyIsInByZWZlcnJlZF91c2VybmFtZSI6InBldGVyIiwiZ2l2ZW5fbmFtZSI6IlBldGVyIiwiZmFtaWx5X25hbWUiOiJXaG8iLCJlbWFpbCI6InBldGVyQGt1YWRyYW50LmlvIn0.RENI6YkEKKtRbBV8M7Q5QknZ-SfJqY-dHt_n8hyMquizxEy9EVe0vFlF4bPkBv_gOCoOG4KOcoUusBwbaTGCD4ewYI-pBVnGnuFF56mp1gdn54OeegosKwrX-ZGwhX_beV333FxIaM-8Z5c40bfrRX0sVTVnBQYmc2C9iO63AEpXjhV4mf_9FptQw9Q1arcz9unvWUOaAE-s8JtJuJdHz2l2I-Y9nxMapoOQeP_n7IuZtsqw9_nLaoITsgi-NLhkwHRkcbBdqbJbXjsVSOIaE8J1WfBuZVQOCyLxD-aXojlXU8Q6djVSlrmAWO8X9x_mqXLvpNVD8N7LgICMvByU4A", nil).MinTimes(1)
	idConfig := &evaluators.IdentityConfig{OIDC: identity.NewOIDC(fmt.Sprintf("http://%v", oidcServerHost), authCredMock, 0, context.TODO())}
	authzConfig := &evaluators.AuthorizationConfig{JSON: &authorization.JSONPatternMatching{Rules: []json.JSONPatternMatchingRule{{Selector: "auth.identity.realm_access.roles", Operator: "incl", Value: "member"}}}}
	pipeline := newTestAuthPipeline(evaluators.AuthConfig{IdentityConfigs: []auth.AuthConfigEvaluator{idConfig}, AuthorizationConfigs: []auth.AuthConfigEvaluator{authzConfig}}, &request)

	var r auth.AuthResult
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r = pipeline.Evaluate()
	}
	b.StopTimer()
	assert.DeepEqual(b, r.Code, rpc.OK)
}
