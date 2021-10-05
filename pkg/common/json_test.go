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

func TestStringifyJSON(t *testing.T) {
	var source interface{}
	var str string
	var err error

	_ = json.Unmarshal([]byte(`"this is a json string"`), &source)
	str, err = StringifyJSON(source)
	assert.Equal(t, str, "this is a json string")
	assert.NilError(t, err)

	_ = json.Unmarshal([]byte("123"), &source)
	str, err = StringifyJSON(source)
	assert.Equal(t, str, "123")
	assert.NilError(t, err)

	_ = json.Unmarshal([]byte("true"), &source)
	str, err = StringifyJSON(source)
	assert.Equal(t, str, "true")
	assert.NilError(t, err)

	_ = json.Unmarshal([]byte("false"), &source)
	str, err = StringifyJSON(source)
	assert.Equal(t, str, "false")
	assert.NilError(t, err)

	_ = json.Unmarshal([]byte("null"), &source)
	str, err = StringifyJSON(source)
	assert.Equal(t, str, "")
	assert.NilError(t, err)

	_ = json.Unmarshal([]byte(`{"a_prop":"a_value"}`), &source)
	str, err = StringifyJSON(source)
	assert.Equal(t, str, `{"a_prop":"a_value"}`)
	assert.NilError(t, err)

	_ = json.Unmarshal([]byte(`["a","b","c"]`), &source)
	str, err = StringifyJSON(source)
	assert.Equal(t, str, `["a","b","c"]`)
	assert.NilError(t, err)

	_ = json.Unmarshal([]byte(`{"prop_str":"str","prop_num":123,"prop_bool":false,"prop_null":null,"prop_obj":{"a_prop":"a_value"},"prop_arr":["a","b","c"]}`), &source)
	str, err = StringifyJSON(source)
	assert.Equal(t, str, `{"prop_arr":["a","b","c"],"prop_bool":false,"prop_null":null,"prop_num":123,"prop_obj":{"a_prop":"a_value"},"prop_str":"str"}`)
	assert.NilError(t, err)

	str, err = StringifyJSON(true)
	assert.Equal(t, str, "true")
	assert.NilError(t, err)

	str, err = StringifyJSON(false)
	assert.Equal(t, str, "false")
	assert.NilError(t, err)

	str, err = StringifyJSON(nil)
	assert.Equal(t, str, "")
	assert.NilError(t, err)

	str, err = StringifyJSON([]string{"a", "b", "c"})
	assert.Equal(t, str, `["a","b","c"]`)
	assert.NilError(t, err)

	type inner struct {
		AProp string `json:"a_prop"`
	}
	type outer struct {
		Str  string      `json:"prop_str"`
		Num  int64       `json:"prop_num"`
		Bool bool        `json:"prop_bool"`
		Null interface{} `json:"prop_null"`
		Arr  []string    `json:"prop_arr"`
		Obj  inner       `json:"prop_obj"`
	}

	str, err = StringifyJSON(outer{
		Str:  "str",
		Num:  123,
		Bool: false,
		Null: nil,
		Arr:  []string{"a", "b", "c"},
		Obj:  inner{AProp: "a_value"},
	})
	assert.Equal(t, str, `{"prop_str":"str","prop_num":123,"prop_bool":false,"prop_null":null,"prop_arr":["a","b","c"],"prop_obj":{"a_prop":"a_value"}}`)
	assert.NilError(t, err)
}
