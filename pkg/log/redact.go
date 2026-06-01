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

	// Redact identity data - it may contain tokens or sensitive claims
	// We keep the structure but redact string values in common sensitive fields
	if identity, ok := data["identity"].(map[string]interface{}); ok {
		redactSensitiveIdentityFields(identity)
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
