package common

import (
	"encoding/json"
	"testing"

	"gotest.tools/assert"

	"github.com/tidwall/gjson"
)

func TestJSONValueResolveFor(t *testing.T) {
	const jsonData = `{
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

	// pattern mixing static and variable placeholders ("template")
	value = JSONValue{Pattern: "Hello, {auth.identity.username}!"}
	assert.Equal(t, value.ResolveFor(jsonData), "Hello, john!")

	// template with inner patterns passing arguments to modifier
	value = JSONValue{Pattern: `Email domain: {auth.identity.email.@extract:{"sep":"@","pos":1}}`}
	assert.Equal(t, value.ResolveFor(jsonData), "Email domain: test")

	// simple pattern passing arguments to modifier (not a template)
	value = JSONValue{Pattern: `auth.identity.email.@extract:{"sep":"@","pos":1}`}
	assert.Equal(t, value.ResolveFor(jsonData), "test")
}

func TestIsTemplate(t *testing.T) {
	var value *JSONValue

	// static string
	value = &JSONValue{Pattern: "Just a static string"}
	assert.Check(t, !value.IsTemplate())

	// template
	value = &JSONValue{Pattern: `Hello, {auth.identity.username}!`}
	assert.Check(t, value.IsTemplate())

	value = &JSONValue{Pattern: `http://talker-api.authorino.svc.cluster.local:3000/metadata?encoding=text/plain&original_path={context.request.http.path}`}
	assert.Check(t, value.IsTemplate())

	// json path
	value = &JSONValue{Pattern: `auth.identity.metadata.annotations.authorino\.3scale\.net/username`}
	assert.Check(t, !value.IsTemplate())

	value = &JSONValue{Pattern: `auth.identity.metadata.annotations.authorino\.3scale\.net/username|@case:lower`}
	assert.Check(t, !value.IsTemplate())

	value = &JSONValue{Pattern: `auth.identity.metadata.creationTimestamp`}
	assert.Check(t, !value.IsTemplate())

	// json path with modifier
	value = &JSONValue{Pattern: `auth.identity.metadata.name.@replace:{"old":"john","new":"John"}`}
	assert.Check(t, !value.IsTemplate())

	// technically a template
	value = &JSONValue{Pattern: `{auth.identity.metadata.creationTimestamp}`}
	assert.Check(t, value.IsTemplate())

	// template with modifier
	value = &JSONValue{Pattern: `Hello, {auth.identity.metadata.annotations.authorino\.3scale\.net/name|@extract:{"pos":1}}!`}
	assert.Check(t, value.IsTemplate())

	value = &JSONValue{Pattern: `Hello, \{auth.identity.metadata.annotations.authorino\.3scale\.net/name|@extract:\{"pos":1}}!`}
	assert.Check(t, value.IsTemplate())

	value = &JSONValue{Pattern: `Email domain: {auth.identity.email.@extract:{"sep":"@","pos":1}}`}
	assert.Check(t, value.IsTemplate())

	value = &JSONValue{Pattern: `Email username: {auth.identity.email.@extract:{"sep":"@","pos":0}} | Email domain: {auth.identity.email.@extract:{"sep":"@","pos":1}}`}
	assert.Check(t, value.IsTemplate())

	// template with escaping
	value = &JSONValue{Pattern: `The JSON path is \{auth.identity.metadata.annotations.name.@replace:\{"old":"john","new":"John"\}\}!`}
	assert.Check(t, value.IsTemplate())

	value = &JSONValue{Pattern: `Hello, {auth.identity.metadata.annotations.authorino\.3scale\.net/name}!`}
	assert.Check(t, value.IsTemplate())

	// template with more than one variable placeholder
	value = &JSONValue{Pattern: `http://echo-api.3scale.net/login?redirect_to=https://{context.request.http.host}{context.request.http.path}`}
	assert.Check(t, value.IsTemplate())

	// invalid template
	value = &JSONValue{Pattern: `Not a valid {template!`}
	assert.Check(t, value.IsTemplate())
}

func TestReplaceJSONPlaceholders(t *testing.T) {
	const jsonData = `{
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
				"github.com": "https://github.com/john",
			}
		}
	}`

	var replaced string

	replaced = ReplaceJSONPlaceholders("Nothing to replace", jsonData)
	assert.Equal(t, replaced, "Nothing to replace")

	replaced = ReplaceJSONPlaceholders("Username: {auth.identity.username}", jsonData)
	assert.Equal(t, replaced, "Username: john")

	replaced = ReplaceJSONPlaceholders("Username: {auth.identity.username.@case:upper}", jsonData)
	assert.Equal(t, replaced, "Username: JOHN")

	replaced = ReplaceJSONPlaceholders(`Domain: {auth.identity.email.@extract:{"sep":"@","pos":1}}`, jsonData)
	assert.Equal(t, replaced, "Domain: test")

	replaced = ReplaceJSONPlaceholders("Username: {auth.identity.username}, Email: {auth.identity.email}", jsonData)
	assert.Equal(t, replaced, "Username: john, Email: john@test")

	replaced = ReplaceJSONPlaceholders("{auth.identity.email_verified} (bool)", jsonData)
	assert.Equal(t, replaced, "true (bool)")

	replaced = ReplaceJSONPlaceholders(`Github.com: {auth.identity.github\.com}`, jsonData)
	assert.Equal(t, replaced, "Github.com: https://github.com/john")

	replaced = ReplaceJSONPlaceholders(`Github username: {auth.identity.github\.com|@extract:{"sep":"/","pos":3}|@case:upper}`, jsonData)
	assert.Equal(t, replaced, "Github username: JOHN")

	replaced = ReplaceJSONPlaceholders(`This is NOT a \{variable placeholder\}`, jsonData)
	assert.Equal(t, replaced, `This is NOT a \{variable placeholder\}`)

	replaced = ReplaceJSONPlaceholders("{auth.identity.username}", jsonData)
	assert.Equal(t, replaced, "john")

	replaced = ReplaceJSONPlaceholders(`\\{auth.identity.username}`, jsonData)
	assert.Equal(t, replaced, `\\john`)

	replaced = ReplaceJSONPlaceholders(`\\\{auth.identity.username\}`, jsonData)
	assert.Equal(t, replaced, `\\\{auth.identity.username\}`)

	// invalid placeholder
	replaced = ReplaceJSONPlaceholders("username: {auth.identity.username", jsonData)
	assert.Equal(t, replaced, "username: ")

	// valid placeholder, yet with invalid json pattern
	replaced = ReplaceJSONPlaceholders(`username: {auth.ide{ntit/y.u\sername}`, jsonData)
	assert.Equal(t, replaced, "username: ")
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

func TestBase64JSONStr(t *testing.T) {
	const jsonData = `{"auth":{"identity":{"username":{"encoded":"am9obg==","decoded":"john"}}}}`

	assert.Equal(t, gjson.Get(jsonData, `auth.identity.username.encoded.@base64:decode`).String(), "john")
	assert.Equal(t, gjson.Get(jsonData, `auth.identity.username.decoded.@base64:encode`).String(), "am9obg==")
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
