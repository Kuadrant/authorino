package evaluators

import (
	"fmt"
	"testing"

	"github.com/kuadrant/authorino/pkg/json"

	"gotest.tools/assert"
)

func TestResolveIdentityExtension(t *testing.T) {
	obj := map[string]any{
		"username": "beth",
		"sub":      "1234567890",
	}
	authJSON := `{"context":{},"auth":{"identity":{"username":"beth","sub":"1234567890"}}}`

	testCases := []struct {
		name     string
		input    IdentityExtension
		expected string
	}{
		{
			name:     "static value for existing property without overwrite",
			input:    NewIdentityExtension("username", json.JSONValue{Static: "foo"}, false),
			expected: "beth",
		},
		{
			name:     "static value for missing property without overwrite",
			input:    NewIdentityExtension("uid", json.JSONValue{Static: "foo"}, false),
			expected: "foo",
		},
		{
			name:     "static value for existing property without overwrite",
			input:    NewIdentityExtension("username", json.JSONValue{Static: "foo"}, true),
			expected: "foo",
		},
		{
			name:     "static value for missing property without overwrite",
			input:    NewIdentityExtension("uid", json.JSONValue{Static: "foo"}, true),
			expected: "foo",
		},
		{
			name:     "existing pattern for existing property without overwrite",
			input:    NewIdentityExtension("username", json.JSONValue{Pattern: "auth.identity.sub"}, false),
			expected: "beth",
		},
		{
			name:     "existing pattern for missing property without overwrite",
			input:    NewIdentityExtension("uid", json.JSONValue{Pattern: "auth.identity.sub"}, false),
			expected: "1234567890",
		},
		{
			name:     "existing pattern for existing property without overwrite",
			input:    NewIdentityExtension("username", json.JSONValue{Pattern: "auth.identity.sub"}, true),
			expected: "1234567890",
		},
		{
			name:     "existing pattern for missing property without overwrite",
			input:    NewIdentityExtension("uid", json.JSONValue{Pattern: "auth.identity.sub"}, true),
			expected: "1234567890",
		},
		{
			name:     "missing pattern for existing property without overwrite",
			input:    NewIdentityExtension("username", json.JSONValue{Pattern: "auth.identity.full_name"}, false),
			expected: "beth",
		},
		{
			name:     "missing pattern for missing property without overwrite",
			input:    NewIdentityExtension("uid", json.JSONValue{Pattern: "auth.identity.full_name"}, false),
			expected: "",
		},
		{
			name:     "missing pattern for existing property without overwrite",
			input:    NewIdentityExtension("username", json.JSONValue{Pattern: "auth.identity.full_name"}, true),
			expected: "",
		},
		{
			name:     "missing pattern for missing property without overwrite",
			input:    NewIdentityExtension("uid", json.JSONValue{Pattern: "auth.identity.full_name"}, true),
			expected: "",
		},
	}

	for _, tc := range testCases {
		resolved, err := tc.input.ResolveFor(obj, authJSON)
		assert.NilError(t, err)
		actual, _ := json.StringifyJSON(resolved)
		assert.Equal(t, actual, tc.expected, fmt.Sprintf("%s failed: got '%s', want '%s'", tc.name, string(actual), string(tc.expected)))
	}
}
