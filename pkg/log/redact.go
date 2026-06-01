package log

import (
	"net/url"
	"strings"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/protobuf/proto"
	authv1 "k8s.io/api/authentication/v1"
)

const redacted = "***REDACTED***"

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

	// Redact common sensitive fields
	sensitiveFields := []string{
		"token",
		"access_token",
		"refresh_token",
		"id_token",
		"client_secret",
		"password",
		"secret",
		"api_key",
		"apikey",
	}

	for _, field := range sensitiveFields {
		if values.Has(field) {
			values.Set(field, redacted)
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

	redactedHeaders := make(map[string][]string, len(headers))
	sensitiveHeaders := map[string]bool{
		"authorization": true,
		"cookie":        true,
		"x-api-key":     true,
		"apikey":        true,
	}

	for k, v := range headers {
		if sensitiveHeaders[strings.ToLower(k)] {
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

	redactedHeaders := make(map[string]string, len(headers))
	sensitiveHeaders := map[string]bool{
		"authorization": true,
		"cookie":        true,
		"x-api-key":     true,
		"apikey":        true,
	}

	for k, v := range headers {
		if sensitiveHeaders[strings.ToLower(k)] {
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
