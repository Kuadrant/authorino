package authorization

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/3scale-labs/authorino/pkg/common"
	"gopkg.in/yaml.v2"
	"gotest.tools/assert"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

const (
	rawRequest string = `{
		"attributes": {
			"request": {
				"http": {
					"headers": {
						"x-secret-header": "no-one-knows"
					}
				}
			}
		}
	}`

	rawAPIConfig = `
identity:
  - name: whatever
metadata:
  - name: letters`
)

type __Identity struct {
	Name string `yaml:"name"`
}

func (i *__Identity) Call(a common.AuthContext, c context.Context) (interface{}, error) {
	return "authenticated", nil
}

type __Metadata struct {
	Name string `yaml:"name"`
}

func (m *__Metadata) Call(a common.AuthContext, c context.Context) (interface{}, error) {
	someValues := []string{"a", "b", "c"}
	return someValues, nil
}

func (m *__Metadata) GetName() string {
	return m.Name
}

type __Authorization struct {
	Name string               `yaml:"name"`
	JSON *JSONPatternMatching `yaml:"json"`
}

type __AuthContext struct {
	Identity      []__Identity      `yaml:"identity"`
	Metadata      []__Metadata      `yaml:"metadata"`
	Authorization []__Authorization `yaml:"authorization"`
}

func (a *__AuthContext) GetParentContext() *context.Context {
	ctx := context.TODO()
	return &ctx
}

func (a *__AuthContext) GetRequest() *envoy_auth.CheckRequest {
	var req envoy_auth.CheckRequest
	_ = json.Unmarshal([]byte(rawRequest), &req)
	return &req
}

func (a *__AuthContext) GetHttp() *envoy_auth.AttributeContext_HttpRequest {
	return a.GetRequest().GetAttributes().GetRequest().GetHttp()
}

func (a *__AuthContext) GetAPI() interface{} {
	return nil
}

func (a *__AuthContext) GetResolvedIdentity() (interface{}, interface{}) {
	ev := a.Identity[0]
	obj, _ := ev.Call(a, nil)
	return &ev, obj
}

func (a *__AuthContext) GetResolvedMetadata() map[interface{}]interface{} {
	m := make(map[interface{}]interface{})
	ev := a.Metadata[0]
	obj, _ := ev.Call(a, nil)
	m[&ev] = obj
	return m
}

type authContextData struct {
	Request *envoy_auth.AttributeContext `json:"context"`
	Context map[string]interface{}       `json:"auth"`
}

func (a *__AuthContext) ToData() interface{} {
	contextData := make(map[string]interface{})
	_, contextData["identity"] = a.GetResolvedIdentity()

	resolvedMetadata := make(map[string]interface{})
	for config, obj := range a.GetResolvedMetadata() {
		metadataConfig, _ := config.(common.NamedConfigEvaluator)
		resolvedMetadata[metadataConfig.GetName()] = obj
	}
	contextData["metadata"] = resolvedMetadata

	return &authContextData{
		Request: a.GetRequest().Attributes,
		Context: contextData,
	}
}

func TestCall(t *testing.T) {
	var (
		authContext __AuthContext
		jsonAuth    *JSONPatternMatching
		authorized  bool
		err         error
	)

	if err := yaml.Unmarshal([]byte(rawAPIConfig), &authContext); err != nil {
		panic(err)
	}

	// eq with same value than expected
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{
			{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: "eq",
				Value:    "no-one-knows",
			},
		},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, authorized)
	assert.Check(t, err == nil)

	// eq with different value than expected
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{
			{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: "eq",
				Value:    "other-expected",
			},
		},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, !authorized)
	assert.Error(t, err, "Unauthorized")

	// neq with same value than expected
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{
			{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: "neq",
				Value:    "other-expected",
			},
		},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, authorized)
	assert.Check(t, err == nil)

	// neq with different value than expected
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{
			{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: "neq",
				Value:    "no-one-knows",
			},
		},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, !authorized)
	assert.Error(t, err, "Unauthorized")

	// incl with value found
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{
			{
				Selector: "auth.metadata.letters",
				Operator: "incl",
				Value:    "a",
			},
		},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, authorized)
	assert.Check(t, err == nil)

	// incl with value not found
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{
			{
				Selector: "auth.metadata.letters",
				Operator: "incl",
				Value:    "d",
			},
		},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, !authorized)
	assert.Error(t, err, "Unauthorized")

	// excl with value not found
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{
			{
				Selector: "auth.metadata.letters",
				Operator: "excl",
				Value:    "d",
			},
		},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, authorized)
	assert.Check(t, err == nil)

	// excl with value found
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{
			{
				Selector: "auth.metadata.letters",
				Operator: "excl",
				Value:    "b",
			},
		},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, !authorized)
	assert.Error(t, err, "Unauthorized")

	// multiple rules
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{
			{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: "eq",
				Value:    "no-one-knows",
			},
			{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: "neq",
				Value:    "other-expected",
			},
			{
				Selector: "auth.metadata.letters",
				Operator: "incl",
				Value:    "a",
			},
			{
				Selector: "auth.metadata.letters",
				Operator: "incl",
				Value:    "c",
			},
			{
				Selector: "auth.metadata.letters",
				Operator: "excl",
				Value:    "d",
			},
		},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, authorized)
	assert.Check(t, err == nil)

	// multiple rules with at least one unauthorized
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{
			{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: "eq",
				Value:    "no-one-knows",
			},
			{
				Selector: "context.request.http.headers.x-secret-header",
				Operator: "neq",
				Value:    "no-one-knows",
			},
			{
				Selector: "auth.metadata.letters",
				Operator: "incl",
				Value:    "xxxxx",
			},
			{
				Selector: "auth.metadata.letters",
				Operator: "incl",
				Value:    "c",
			},
			{
				Selector: "auth.metadata.letters",
				Operator: "excl",
				Value:    "d",
			},
		},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, !authorized)
	assert.Error(t, err, "Unauthorized")

	// rules empty
	jsonAuth = &JSONPatternMatching{
		Rules: []JSONPatternMatchingRule{},
	}

	authorized, err = jsonAuth.Call(&authContext, nil)
	assert.Check(t, authorized)
	assert.Check(t, err == nil)
}
