package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/tidwall/gjson"
)

const (
	operatorEq    = "eq"
	operatorNeq   = "neq"
	operatorIncl  = "incl"
	operatorExcl  = "excl"
	operatorRegex = "matches"

	unsupportedOperatorErrorMsg = "Unsupported operator for JSON authorization"
)

var (
	allCurlyBracesRegex          = regexp.MustCompile("{")
	curlyBracesForModifiersRegex = regexp.MustCompile(`[^@]+@\w+:{`)
)

// JSONProperty represents a name-value pair for a JSON property where the value can be a static value or
// a pattern for a value fetched dynamically from the authorization JSON
type JSONProperty struct {
	Name  string
	Value JSONValue
}

type JSONValue struct {
	// Static value of the JSON property.
	Static interface{}
	// Resolves the value of the JSON property by fetching the pattern from the authorization JSON.
	Pattern string
}

// ResolveFor resolves a value for a given input JSON.
// For static values, it returns the value right away; for patterns, it magically decides whether to process as a
// simple pattern or as a template that mixes static value with variable placeholders that resolve to patterns.
// In case of a template that mixes no variable placeholder, but it contains nothing but a static string value, users
// should use `JSONValue.Static` instead of `JSONValue.Pattern`.
func (v *JSONValue) ResolveFor(jsonData string) interface{} {
	if v.Pattern != "" {
		// If all curly braces in the pattern are for passing arguments to modifiers, then it's likely NOT a template.
		// To be a template, the pattern must contain at least one curly brace delimiting a variable placeholder.
		if v.IsTemplate() {
			return ReplaceJSONPlaceholders(v.Pattern, jsonData)
		} else {
			return gjson.Get(jsonData, v.Pattern).Value()
		}
	} else {
		return v.Static
	}
}

// IsTemplate tells whether a pattern is as a simple pattern or a template that mixes static value with variable
// placeholders that resolve to patterns.
// In case of a template that mixes no variable placeholder, but it contains nothing but a static string value, users
// should use `JSONValue.Static` instead of `JSONValue.Pattern`.
func (v *JSONValue) IsTemplate() bool {
	return len(curlyBracesForModifiersRegex.FindAllStringSubmatch(v.Pattern, -1)) != len(allCurlyBracesRegex.FindAllStringSubmatch(v.Pattern, -1))
}

type JSONPatternMatchingRule struct {
	Selector string
	Operator string
	Value    string
}

func (rule *JSONPatternMatchingRule) EvaluateFor(jsonData string) (bool, error) {
	expectedValue := rule.Value
	obtainedValue := gjson.Get(jsonData, rule.Selector)

	switch rule.Operator {
	case operatorEq:
		return (expectedValue == obtainedValue.String()), nil

	case operatorNeq:
		return (expectedValue != obtainedValue.String()), nil

	case operatorIncl:
		for _, item := range obtainedValue.Array() {
			if expectedValue == item.String() {
				return true, nil
			}
		}
		return false, nil

	case operatorExcl:
		for _, item := range obtainedValue.Array() {
			if expectedValue == item.String() {
				return false, nil
			}
		}
		return true, nil

	case operatorRegex:
		if re, err := regexp.Compile(expectedValue); err != nil {
			return false, err
		} else {
			return re.MatchString(obtainedValue.String()), nil
		}

	default:
		return false, fmt.Errorf(unsupportedOperatorErrorMsg)
	}
}

// UnmashalJSONResponse unmarshalls a generic HTTP response body into a JSON structure
// Pass optionally a pointer to a byte array to get the raw body of the response object written back
func UnmashalJSONResponse(resp *http.Response, v interface{}, b *[]byte) error {
	// read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if b != nil {
		*b = body
	}

	// check http status ok
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, body)
	}

	// decode as json and return if ok
	err = json.Unmarshal(body, v)
	if err == nil {
		return nil
	}

	// check json response content type
	ct := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

func ReplaceJSONPlaceholders(source string, jsonData string) string {
	var replaced, buffer []byte
	var escaping, insidePlaceholder bool
	var nestedCurlyBraces int

	for _, b := range []byte(source) {
		switch b {
		case 123: // '{'
			if escaping {
				replaced = append(replaced, b)
			} else {
				if insidePlaceholder {
					buffer = append(buffer, b)
					nestedCurlyBraces = nestedCurlyBraces + 1
				} else {
					insidePlaceholder = true
				}
			}
			escaping = false
		case 125: // '}'
			if insidePlaceholder {
				if nestedCurlyBraces > 0 {
					buffer = append(buffer, b)
					nestedCurlyBraces = nestedCurlyBraces - 1
				} else {
					if len(buffer) > 0 {
						replaced = append(replaced, []byte(gjson.Get(jsonData, string(buffer)).String())...)
						buffer = []byte{}
					}
					insidePlaceholder = false
				}
			} else {
				replaced = append(replaced, b)
			}
			escaping = false
		case 92: // '\'
			if insidePlaceholder {
				buffer = append(buffer, b)
			} else {
				replaced = append(replaced, b)
				escaping = !escaping
			}
		default:
			if insidePlaceholder {
				buffer = append(buffer, b)
			} else {
				replaced = append(replaced, b)
			}
			escaping = false
		}
	}

	return string(replaced)
}

func StringifyJSON(data interface{}) (string, error) {
	if dataAsJSON, err := json.Marshal(data); err != nil {
		return "", err
	} else {
		return gjson.ParseBytes(dataAsJSON).String(), nil
	}
}

var extractJSONStr = func(json, arg string) string {
	var sep string = " "
	var pos int64 = 0

	if arg != "" {
		gjson.Parse(arg).ForEach(func(key, value gjson.Result) bool {
			switch key.String() {
			case "sep":
				sep = value.String()
			case "pos":
				pos = value.Int()
			}
			return true
		})
	}

	str := gjson.Parse(json).String()
	parts := strings.Split(str, sep)

	if pos >= int64(len(parts)) {
		return "n"
	}

	return fmt.Sprintf("\"%s\"", parts[pos])
}

var replaceJSONStr = func(json, arg string) string {
	if arg == "" {
		return json
	}

	var old, new string

	gjson.Parse(arg).ForEach(func(key, value gjson.Result) bool {
		switch key.String() {
		case "old":
			old = value.String()
		case "new":
			new = value.String()
		}
		return true
	})

	str := gjson.Parse(json).String()
	return fmt.Sprintf("\"%s\"", strings.ReplaceAll(str, old, new))
}

var caseJSONStr = func(json, arg string) string {
	switch arg {
	case "upper":
		return strings.ToUpper(json)
	case "lower":
		return strings.ToLower(json)
	}
	return json
}

var base64JSONStr = func(json, arg string) string {
	str := gjson.Parse(json).String()

	switch arg {
	case "encode":
		encoded := base64.URLEncoding.EncodeToString([]byte(str))
		return fmt.Sprintf("\"%s\"", encoded)
	case "decode":
		decoded, _ := base64.URLEncoding.DecodeString(str)
		return fmt.Sprintf("\"%s\"", decoded)
	default:
		return json
	}
}

func init() {
	gjson.AddModifier("extract", extractJSONStr)
	gjson.AddModifier("replace", replaceJSONStr)
	gjson.AddModifier("case", caseJSONStr)
	gjson.AddModifier("base64", base64JSONStr)
}
