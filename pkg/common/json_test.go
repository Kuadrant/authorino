package common

import (
	"encoding/json"
	"testing"

	"gotest.tools/assert"
)

func TestJSONValueResolveFor(t *testing.T) {
	jsonData := `{
		"auth": {
			"identity": {
				"username": "john",
				"email": "john@test",
				"email_verified": true,
				"address": {
					"line_1": "123 Test St",
					"postal_code": 987654
				},
				"roles": [
					"user",
					"admin"
				],
				"exp": 1629884250,
			}
		}
	}`

	var value JSONValue
	var resolvedValueAsJSON []byte

	value = JSONValue{Static: "foo"}
	assert.Equal(t, value.ResolveFor(jsonData), "foo")
	assert.Equal(t, value.ResolveFor(""), "foo")

	value = JSONValue{Pattern: "auth.identity.username"}
	assert.Equal(t, value.ResolveFor(jsonData), "john")

	value = JSONValue{Pattern: "auth.identity.email_verified"}
	assert.Equal(t, value.ResolveFor(jsonData), true)

	value = JSONValue{Pattern: "auth.identity.address"}
	resolvedValueAsJSON, _ = json.Marshal(value.ResolveFor(jsonData))
	type address struct {
		Line1      string `json:"line_1"`
		PostalCode int    `json:"postal_code"`
	}
	var resolvedAddress address
	_ = json.Unmarshal(resolvedValueAsJSON, &resolvedAddress)
	assert.Equal(t, resolvedAddress.Line1, "123 Test St")
	assert.Equal(t, resolvedAddress.PostalCode, 987654)

	value = JSONValue{Pattern: "auth.identity.roles"}
	resolvedValueAsJSON, _ = json.Marshal(value.ResolveFor(jsonData))
	var resolvedRoles []string
	_ = json.Unmarshal(resolvedValueAsJSON, &resolvedRoles)
	assert.DeepEqual(t, resolvedRoles, []string{"user", "admin"})
}
