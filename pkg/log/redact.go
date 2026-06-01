package log

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/proto"
	authv1 "k8s.io/api/authentication/v1"
)

const redacted = "***REDACTED***"

var (
	// Global configuration for sensitive fields and headers
	sensitiveFieldsMu sync.RWMutex
	sensitiveFields   = map[string]bool{
		"token":         true,
		"access_token":  true,
		"refresh_token": true,
		"id_token":      true,
		"client_secret": true,
		"password":      true,
		"secret":        true,
		"api_key":       true,
		"apikey":        true,
	}

	sensitiveHeadersMu sync.RWMutex
	sensitiveHeaders   = map[string]bool{
		"authorization": true,
		"cookie":        true,
		"x-api-key":     true,
		"apikey":        true,
	}
)

// AddSensitiveField adds a field name to the list of sensitive fields to redact
func AddSensitiveField(field string) {
	sensitiveFieldsMu.Lock()
	defer sensitiveFieldsMu.Unlock()
	sensitiveFields[strings.ToLower(field)] = true
}

// RemoveSensitiveField removes a field name from the list of sensitive fields
func RemoveSensitiveField(field string) {
	sensitiveFieldsMu.Lock()
	defer sensitiveFieldsMu.Unlock()
	delete(sensitiveFields, strings.ToLower(field))
}

// AddSensitiveHeader adds a header name to the list of sensitive headers to redact
func AddSensitiveHeader(header string) {
	sensitiveHeadersMu.Lock()
	defer sensitiveHeadersMu.Unlock()
	sensitiveHeaders[strings.ToLower(header)] = true
}

// RemoveSensitiveHeader removes a header name from the list of sensitive headers
func RemoveSensitiveHeader(header string) {
	sensitiveHeadersMu.Lock()
	defer sensitiveHeadersMu.Unlock()
	delete(sensitiveHeaders, strings.ToLower(header))
}

// GetSensitiveFields returns a copy of the current sensitive fields map
func GetSensitiveFields() map[string]bool {
	sensitiveFieldsMu.RLock()
	defer sensitiveFieldsMu.RUnlock()
	copy := make(map[string]bool, len(sensitiveFields))
	for k, v := range sensitiveFields {
		copy[k] = v
	}
	return copy
}

// GetSensitiveHeaders returns a copy of the current sensitive headers map
func GetSensitiveHeaders() map[string]bool {
	sensitiveHeadersMu.RLock()
	defer sensitiveHeadersMu.RUnlock()
	copy := make(map[string]bool, len(sensitiveHeaders))
	for k, v := range sensitiveHeaders {
		copy[k] = v
	}
	return copy
}

// RedactedURL returns a URL string with the userinfo (credentials) redacted
func RedactedURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	redactedURL := *u
	if redactedURL.User != nil {
		redactedURL.User = url.UserPassword(redacted, redacted)
	}
	return redactedURL.String()
}

// RedactedURLString parses a URL string and returns it with userinfo redacted
func RedactedURLString(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return RedactedURL(u)
	}
	return rawURL
}

// RedactedFormData returns form-encoded data with sensitive fields redacted
func RedactedFormData(data string) string {
	values, err := url.ParseQuery(data)
	if err != nil {
		return redacted
	}

	// Redact configured sensitive fields
	sensitiveFieldsMu.RLock()
	fieldsToRedact := make(map[string]bool, len(sensitiveFields))
	for k, v := range sensitiveFields {
		fieldsToRedact[k] = v
	}
	sensitiveFieldsMu.RUnlock()

	// Check each field in the values (case-insensitive)
	for fieldName := range values {
		if fieldsToRedact[strings.ToLower(fieldName)] {
			values.Set(fieldName, redacted)
		}
	}

	return values.Encode()
}

// RedactedTokenReview returns a TokenReview with the token redacted
func RedactedTokenReview(tr *authv1.TokenReview) *authv1.TokenReview {
	if tr == nil {
		return nil
	}

	redactedTR := tr.DeepCopy()
	if redactedTR.Spec.Token != "" {
		redactedTR.Spec.Token = redacted
	}

	return redactedTR
}

// RedactedHeaders returns a copy of headers with sensitive values redacted
func RedactedHeaders(headers map[string][]string) map[string][]string {
	if headers == nil {
		return nil
	}

	// Get configured sensitive headers
	sensitiveHeadersMu.RLock()
	headersToRedact := make(map[string]bool, len(sensitiveHeaders))
	for k, v := range sensitiveHeaders {
		headersToRedact[k] = v
	}
	sensitiveHeadersMu.RUnlock()

	redactedHeaders := make(map[string][]string, len(headers))
	for k, v := range headers {
		if headersToRedact[strings.ToLower(k)] {
			redactedHeaders[k] = []string{redacted}
		} else {
			redactedHeaders[k] = v
		}
	}

	return redactedHeaders
}

// RedactedStringMapHeaders returns a copy of headers (map[string]string) with sensitive values redacted
func RedactedStringMapHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}

	// Get configured sensitive headers
	sensitiveHeadersMu.RLock()
	headersToRedact := make(map[string]bool, len(sensitiveHeaders))
	for k, v := range sensitiveHeaders {
		headersToRedact[k] = v
	}
	sensitiveHeadersMu.RUnlock()

	redactedHeaders := make(map[string]string, len(headers))
	for k, v := range headers {
		if headersToRedact[strings.ToLower(k)] {
			redactedHeaders[k] = redacted
		} else {
			redactedHeaders[k] = v
		}
	}

	return redactedHeaders
}

// RedactedRequestBody returns a request body with sensitive content redacted
// For now, we redact all body content that might contain credentials
func RedactedRequestBody(body string, contentType string) string {
	if body == "" {
		return ""
	}

	// For form-encoded data, try to redact specific fields
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		return RedactedFormData(body)
	}

	// For other content types (JSON, etc.), redact the entire body
	// to avoid accidentally leaking credentials in complex nested structures
	return redacted
}

// RedactedAttributeContext returns a deep copy of the AttributeContext with sensitive headers redacted
func RedactedAttributeContext(attrs *envoy_auth.AttributeContext) *envoy_auth.AttributeContext {
	if attrs == nil {
		return nil
	}

	// Create a deep copy using protobuf cloning
	redactedAttrs := proto.Clone(attrs).(*envoy_auth.AttributeContext)

	// Redact headers in the HTTP request if present
	if redactedAttrs.Request != nil && redactedAttrs.Request.Http != nil {
		if redactedAttrs.Request.Http.Headers != nil {
			redactedAttrs.Request.Http.Headers = RedactedStringMapHeaders(redactedAttrs.Request.Http.Headers)
		}
	}

	return redactedAttrs
}

// RedactedAuthorizationJSON returns authorization JSON with sensitive data redacted
// This function attempts to parse the JSON, redact sensitive fields, and re-serialize it.
// If parsing fails, it returns the redacted placeholder to be safe.
func RedactedAuthorizationJSON(authJSON string) interface{} {
	var data map[string]interface{}
	decoder := strings.NewReader(authJSON)
	if err := json.NewDecoder(decoder).Decode(&data); err != nil {
		// If we can't parse it, return redacted to be safe
		return redacted
	}

	// Redact headers in context.request.http.headers
	if context, ok := data["context"].(map[string]interface{}); ok {
		if request, ok := context["request"].(map[string]interface{}); ok {
			if httpReq, ok := request["http"].(map[string]interface{}); ok {
				if headers, ok := httpReq["headers"].(map[string]interface{}); ok {
					httpReq["headers"] = redactHeadersFromInterface(headers)
				}
			}
		}
	}

	// Redact headers in request.headers (copy at top level)
	if request, ok := data["request"].(map[string]interface{}); ok {
		if headers, ok := request["headers"].(map[string]interface{}); ok {
			request["headers"] = redactHeadersFromInterface(headers)
		}
	}

	// Redact identity data in auth.identity
	// The authorization JSON has identity nested under "auth"
	if auth, ok := data["auth"].(map[string]interface{}); ok {
		if identity, ok := auth["identity"].(map[string]interface{}); ok {
			redactSensitiveIdentityFields(identity)
		}

		// Redact metadata in auth.metadata
		// Structure is {"name1": obj1, "name2": obj2, ...}
		if metadata, ok := auth["metadata"].(map[string]interface{}); ok {
			for _, metadataObj := range metadata {
				if metadataMap, ok := metadataObj.(map[string]interface{}); ok {
					redactSensitiveIdentityFields(metadataMap)
				}
			}
		}
	}

	return data
}

// redactHeadersFromInterface converts interface{} headers to map[string]string and redacts them
func redactHeadersFromInterface(headers map[string]interface{}) map[string]string {
	headersMap := make(map[string]string)
	for k, v := range headers {
		if strVal, ok := v.(string); ok {
			headersMap[k] = strVal
		}
	}
	return RedactedStringMapHeaders(headersMap)
}

// redactSensitiveIdentityFields redacts known sensitive fields in identity objects
func redactSensitiveIdentityFields(identity map[string]interface{}) {
	// Get configured sensitive fields
	sensitiveFieldsMu.RLock()
	fieldsToRedact := make(map[string]bool, len(sensitiveFields))
	for k, v := range sensitiveFields {
		fieldsToRedact[k] = v
	}
	sensitiveFieldsMu.RUnlock()

	// Special handling for Kubernetes Secret objects
	if kind, ok := identity["kind"].(string); ok && kind == "Secret" {
		redactKubernetesSecret(identity)
		return
	}

	// Redact fields (case-insensitive)
	for field := range identity {
		if fieldsToRedact[strings.ToLower(field)] {
			identity[field] = redacted
		}
	}

	// Recursively redact nested objects
	for _, value := range identity {
		if nested, ok := value.(map[string]interface{}); ok {
			redactSensitiveIdentityFields(nested)
		}
	}
}

// redactKubernetesSecret redacts all data fields in a Kubernetes Secret
func redactKubernetesSecret(secret map[string]interface{}) {
	// Redact all entries in the 'data' field (base64-encoded secrets)
	if data, ok := secret["data"].(map[string]interface{}); ok {
		for key := range data {
			data[key] = redacted
		}
	}

	// Redact all entries in the 'stringData' field (plain text secrets)
	if stringData, ok := secret["stringData"].(map[string]interface{}); ok {
		for key := range stringData {
			stringData[key] = redacted
		}
	}

	// Redact secrets in annotations (kubectl last-applied-configuration can contain plaintext secrets)
	if metadata, ok := secret["metadata"].(map[string]interface{}); ok {
		if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {
			for key, value := range annotations {
				// kubectl stores the last applied configuration which may contain plaintext secrets
				if strings.Contains(strings.ToLower(key), "last-applied-configuration") {
					if strValue, ok := value.(string); ok {
						// Try to parse and redact secrets from the JSON annotation
						annotations[key] = redactSecretsFromJSONString(strValue)
					}
				}
			}
		}
	}
}

// redactSecretsFromJSONString redacts secrets from a JSON string (used in annotations)
func redactSecretsFromJSONString(jsonStr string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		// If we can't parse it, redact the whole thing to be safe
		return redacted
	}

	// Redact stringData and data fields
	if stringData, ok := data["stringData"].(map[string]interface{}); ok {
		for key := range stringData {
			stringData[key] = redacted
		}
	}
	if dataField, ok := data["data"].(map[string]interface{}); ok {
		for key := range dataField {
			dataField[key] = redacted
		}
	}

	// Re-serialize
	redactedJSON, err := json.Marshal(data)
	if err != nil {
		return redacted
	}
	return string(redactedJSON)
}

// RedactedIdentityObject redacts sensitive data from identity objects
// This is used for logging identity validation results
func RedactedIdentityObject(identity interface{}) interface{} {
	if identity == nil {
		return nil
	}

	// Convert to map[string]interface{} via JSON for uniform handling
	// This handles typed structs (like Kubernetes v1.Secret) as well as maps
	jsonBytes, err := json.Marshal(identity)
	if err != nil {
		// If we can't serialize it, return redacted to be safe
		return redacted
	}

	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		// If we can't deserialize to map, return the original
		// (might be a primitive type like string or number)
		return identity
	}

	// Apply redaction
	redactSensitiveIdentityFields(data)
	return data
}
