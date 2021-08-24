package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/tidwall/gjson"
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

func (v *JSONValue) ResolveFor(jsonData string) interface{} {
	if v.Pattern != "" {
		return gjson.Get(jsonData, v.Pattern).Value()
	} else {
		return v.Static
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
	replaced := source
	regex := regexp.MustCompile("{([^}]*)}")
	matches := regex.FindAllStringSubmatch(source, -1)
	for _, selector := range matches {
		value := gjson.Get(jsonData, selector[1]).String()
		replaced = strings.ReplaceAll(replaced, "{"+selector[1]+"}", value)
	}
	return replaced
}
