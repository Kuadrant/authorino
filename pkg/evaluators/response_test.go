package evaluators

import (
	gojson "encoding/json"
	"testing"

	"github.com/kuadrant/authorino/pkg/evaluators/response"

	"github.com/golang/mock/gomock"
	"gotest.tools/assert"
)

func TestWrapResponseObjectAsHeader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	responseConfig := NewResponseConfig("resp", 0, nil, HTTP_HEADER_WRAPPER, "my-key", false)

	// json
	responseConfig.DynamicJSON = &response.DynamicJSON{}
	type j struct {
		MyProp string `json:"my-prop"`
	}
	var obj j
	_ = gojson.Unmarshal([]byte(`{"my-prop": "my-value"}`), &obj)
	assert.Equal(t, responseConfig.WrapObjectAsHeaderValue(obj), `{"my-prop":"my-value"}`)

	// plain
	responseConfig.DynamicJSON = nil
	responseConfig.Plain = &response.Plain{}
	assert.Equal(t, responseConfig.WrapObjectAsHeaderValue("my-value"), "my-value")
}
