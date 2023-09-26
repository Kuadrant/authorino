package authorization

import (
	gojson "encoding/json"
	"testing"

	mock_auth "github.com/kuadrant/authorino/pkg/auth/mocks"
	"github.com/kuadrant/authorino/pkg/jsonexp"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

func TestCall(t *testing.T) {
	ctrl := NewController(t)
	defer ctrl.Finish()

	type authorizationJSON struct {
		Context  *envoy_auth.AttributeContext `json:"context"`
		AuthData map[string]interface{}       `json:"auth"`
	}

	authJSON, _ := gojson.Marshal(&authorizationJSON{
		Context: &envoy_auth.AttributeContext{
			Request: &envoy_auth.AttributeContext_Request{
				Http: &envoy_auth.AttributeContext_HttpRequest{
					Headers: map[string]string{
						"x-secret-header": "no-one-knows",
						"x-origin":        "some-origin",
					},
				},
			},
		},
		AuthData: map[string]interface{}{
			"identity": "some-user-data",
			"metadata": map[string][]string{
				"letters": {"a", "b", "c"},
			},
		},
	})

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(string(authJSON)).AnyTimes()

	var (
		jsonAuth   *JSONPatternMatching
		authorized interface{}
		err        error
	)

	// eq with same value than expected
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "context.request.http.headers.x-secret-header",
			Operator: jsonexp.EqualOperator,
			Value:    "no-one-knows",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, authorized.(bool))
	assert.Check(t, err == nil)

	// eq with different value than expected
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "context.request.http.headers.x-secret-header",
			Operator: jsonexp.EqualOperator,
			Value:    "other-expected",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, !authorized.(bool))
	assert.Error(t, err, "Unauthorized")

	// neq with same value than expected
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "context.request.http.headers.x-secret-header",
			Operator: jsonexp.NotEqualOperator,
			Value:    "other-expected",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, authorized.(bool))
	assert.Check(t, err == nil)

	// neq with different value than expected
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "context.request.http.headers.x-secret-header",
			Operator: jsonexp.NotEqualOperator,
			Value:    "no-one-knows",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, !authorized.(bool))
	assert.Error(t, err, "Unauthorized")

	// incl with value found
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "auth.metadata.letters",
			Operator: jsonexp.IncludesOperator,
			Value:    "a",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, authorized.(bool))
	assert.Check(t, err == nil)

	// incl with value not found
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "auth.metadata.letters",
			Operator: jsonexp.IncludesOperator,
			Value:    "d",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, !authorized.(bool))
	assert.Error(t, err, "Unauthorized")

	// excl with value not found
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "auth.metadata.letters",
			Operator: jsonexp.ExcludesOperator,
			Value:    "d",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, authorized.(bool))
	assert.Check(t, err == nil)

	// excl with value found
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "auth.metadata.letters",
			Operator: jsonexp.ExcludesOperator,
			Value:    "b",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, !authorized.(bool))
	assert.Error(t, err, "Unauthorized")

	// regex matches value
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "context.request.http.headers.x-secret-header",
			Operator: jsonexp.RegexOperator,
			Value:    "(.+)-knows",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, authorized.(bool))
	assert.Check(t, err == nil)

	// regex does not match value
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "context.request.http.headers.x-secret-header",
			Operator: jsonexp.RegexOperator,
			Value:    "(\\d)+",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, !authorized.(bool))
	assert.Error(t, err, "Unauthorized")

	// invalid regex
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(jsonexp.Pattern{
			Selector: "context.request.http.headers.x-secret-header",
			Operator: jsonexp.RegexOperator,
			Value:    "$$^[not-a-regex",
		}),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, !authorized.(bool))
	assert.ErrorContains(t, err, "error parsing regexp")

	// multiple rules
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(
			jsonexp.Pattern{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: jsonexp.EqualOperator,
				Value:    "no-one-knows",
			},
			jsonexp.Pattern{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: jsonexp.NotEqualOperator,
				Value:    "other-expected",
			},
			jsonexp.Pattern{
				Selector: "auth.metadata.letters",
				Operator: jsonexp.IncludesOperator,
				Value:    "a",
			},
			jsonexp.Pattern{
				Selector: "auth.metadata.letters",
				Operator: jsonexp.IncludesOperator,
				Value:    "c",
			},
			jsonexp.Pattern{
				Selector: "auth.metadata.letters",
				Operator: jsonexp.ExcludesOperator,
				Value:    "d",
			},
		),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, authorized.(bool))
	assert.Check(t, err == nil)

	// multiple rules with at least one unauthorized
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(
			jsonexp.Pattern{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: jsonexp.EqualOperator,
				Value:    "no-one-knows",
			},
			jsonexp.Pattern{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: jsonexp.NotEqualOperator,
				Value:    "no-one-knows",
			},
			jsonexp.Pattern{
				Selector: "auth.metadata.letters",
				Operator: jsonexp.IncludesOperator,
				Value:    "xxxxx",
			},
			jsonexp.Pattern{
				Selector: "auth.metadata.letters",
				Operator: jsonexp.IncludesOperator,
				Value:    "c",
			},
			jsonexp.Pattern{
				Selector: "auth.metadata.letters",
				Operator: jsonexp.ExcludesOperator,
				Value:    "d",
			},
		),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, !authorized.(bool))
	assert.Error(t, err, "Unauthorized")

	// rules empty
	jsonAuth = &JSONPatternMatching{
		Rules: jsonexp.All(),
	}

	authorized, err = jsonAuth.Call(pipelineMock, nil)
	assert.Check(t, authorized.(bool))
	assert.Check(t, err == nil)
}

func BenchmarkJSONPatternMatchingAuthz(b *testing.B) {
	ctrl := NewController(b)
	defer ctrl.Finish()

	pipelineMock := mock_auth.NewMockAuthPipeline(ctrl)
	pipelineMock.EXPECT().GetAuthorizationJSON().Return(`{"context":{"request":{"http":{"method":"GET","path":"/allow"}}},"auth":{"identity":{"anonymous":true}}}`).MinTimes(1)
	jsonAuth := &JSONPatternMatching{
		Rules: jsonexp.All(
			jsonexp.Pattern{
				Selector: "context.request.http.method",
				Operator: jsonexp.EqualOperator,
				Value:    "GET",
			},
			jsonexp.Pattern{
				Selector: "context.request.http.path",
				Operator: jsonexp.EqualOperator,
				Value:    "/allow",
			},
		),
	}

	var err error
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = jsonAuth.Call(pipelineMock, nil)
	}
	b.StopTimer()
	assert.NilError(b, err)
}
