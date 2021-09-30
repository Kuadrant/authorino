package common

import (
	"encoding/json"
	"testing"

	"gotest.tools/assert"

	"github.com/tidwall/gjson"
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

func TestExtractJSONStr(t *testing.T) {
	const jsonData = `{"auth":{"identity":{"serviceaccount":{"name":"my:ns:sa","long-name":"SA in the NS namespace"}}}}`

	assert.Equal(t, gjson.Get(jsonData, `auth.identity.serviceaccount.long-name.@extract`).String(), "SA")
	assert.Equal(t, gjson.Get(jsonData, `auth.identity.serviceaccount.long-name.@extract:{"pos":0}`).String(), "SA")
	assert.Equal(t, gjson.Get(jsonData, `auth.identity.serviceaccount.long-name.@extract:{"pos":8}`).String(), "")
	assert.Equal(t, gjson.Get(jsonData, `auth.identity.serviceaccount.name.@extract:{"sep":":","pos":1}`).String(), "ns")
}

func TestReplaceJSONStr(t *testing.T) {
	const jsonData = `{"auth":{"identity":{"fullname":"John Doe"}}}`

	assert.Equal(t, gjson.Get(jsonData, `auth.identity.fullname.@replace:{"old":"John","new":"Jane"}`).String(), "Jane Doe")
	assert.Equal(t, gjson.Get(jsonData, `auth.identity.fullname.@replace:{"old":"Peter","new":"Jane"}`).String(), "John Doe")
}

func TestCaseJSONStr(t *testing.T) {
	const jsonData = `{"auth":{"identity":{"fullname":"John Doe"}}}`

	assert.Equal(t, gjson.Get(jsonData, `auth.identity.fullname.@case:upper`).String(), "JOHN DOE")
	assert.Equal(t, gjson.Get(jsonData, `auth.identity.fullname.@case:lower`).String(), "john doe")
}
