package log

import (
	"encoding/json"
	"net/url"
	"testing"

	authv1 "k8s.io/api/authentication/v1"
)

func TestRedactedURL(t *testing.T) {
	tests := []struct {
		name             string
		url              string
		shouldContain    string
		shouldNotContain []string
	}{
		{
			name:             "URL with username and password",
			url:              "https://clientid:clientsecret@example.com/token",
			shouldContain:    "@example.com/token",
			shouldNotContain: []string{"clientid", "clientsecret"},
		},
		{
			name:             "URL without credentials",
			url:              "https://example.com/token",
			shouldContain:    "https://example.com/token",
			shouldNotContain: []string{},
		},
		{
			name:             "URL with only username",
			url:              "https://user@example.com/api",
			shouldContain:    "@example.com/api",
			shouldNotContain: []string{"user"},
		},
		{
			name:             "Nil URL",
			url:              "",
			shouldContain:    "",
			shouldNotContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var u *url.URL
			if tt.url != "" {
				var err error
				u, err = url.Parse(tt.url)
				if err != nil {
					t.Fatalf("Failed to parse URL: %v", err)
				}
			}

			result := RedactedURL(u)

			if tt.shouldContain != "" && !contains(result, tt.shouldContain) {
				t.Errorf("RedactedURL() should contain %q, got %v", tt.shouldContain, result)
			}

			for _, notExpected := range tt.shouldNotContain {
				if contains(result, notExpected) {
					t.Errorf("RedactedURL() should not contain %q, got %v", notExpected, result)
				}
			}
		})
	}
}

func TestRedactedURLString(t *testing.T) {
	tests := []struct {
		name             string
		url              string
		shouldContain    string
		shouldNotContain []string
	}{
		{
			name:             "URL string with credentials",
			url:              "https://admin:password123@api.example.com/introspect",
			shouldContain:    "@api.example.com/introspect",
			shouldNotContain: []string{"admin", "password123"},
		},
		{
			name:             "URL string without credentials",
			url:              "https://api.example.com/introspect",
			shouldContain:    "https://api.example.com/introspect",
			shouldNotContain: []string{},
		},
		{
			name:             "Invalid URL",
			url:              "://invalid",
			shouldContain:    "://invalid",
			shouldNotContain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactedURLString(tt.url)

			if tt.shouldContain != "" && !contains(result, tt.shouldContain) {
				t.Errorf("RedactedURLString() should contain %q, got %v", tt.shouldContain, result)
			}

			for _, notExpected := range tt.shouldNotContain {
				if contains(result, notExpected) {
					t.Errorf("RedactedURLString() should not contain %q, got %v", notExpected, result)
				}
			}
		})
	}
}

func TestRedactedFormData(t *testing.T) {
	tests := []struct {
		name             string
		data             string
		shouldNotContain []string
		checkFn          func(*testing.T, string)
	}{
		{
			name:             "Token in form data",
			data:             "token=secret123&token_type_hint=access_token",
			shouldNotContain: []string{"secret123"},
			checkFn: func(t *testing.T, result string) {
				parsed, _ := url.ParseQuery(result)
				if !contains(parsed.Get("token"), "REDACTED") {
					t.Errorf("token should be redacted, got %v", parsed.Get("token"))
				}
				if parsed.Get("token_type_hint") != "access_token" {
					t.Errorf("token_type_hint should be preserved, got %v", parsed.Get("token_type_hint"))
				}
			},
		},
		{
			name:             "Multiple sensitive fields",
			data:             "client_secret=secretvalue&access_token=tokenvalue&grant_type=client_credentials",
			shouldNotContain: []string{"secretvalue", "tokenvalue"},
			checkFn: func(t *testing.T, result string) {
				parsed, _ := url.ParseQuery(result)
				if !contains(parsed.Get("client_secret"), "REDACTED") {
					t.Errorf("client_secret should be redacted")
				}
				if !contains(parsed.Get("access_token"), "REDACTED") {
					t.Errorf("access_token should be redacted")
				}
				if parsed.Get("grant_type") != "client_credentials" {
					t.Errorf("grant_type should be preserved")
				}
			},
		},
		{
			name:             "No sensitive fields",
			data:             "grant_type=client_credentials&scope=read",
			shouldNotContain: []string{},
			checkFn: func(t *testing.T, result string) {
				if !contains(result, "grant_type=client_credentials") {
					t.Errorf("grant_type should be preserved")
				}
				if !contains(result, "scope=read") {
					t.Errorf("scope should be preserved")
				}
			},
		},
		{
			name:             "Password field",
			data:             "username=admin&password=mypassword",
			shouldNotContain: []string{"mypassword"},
			checkFn: func(t *testing.T, result string) {
				parsed, _ := url.ParseQuery(result)
				if parsed.Get("username") != "admin" {
					t.Errorf("username should be preserved")
				}
				if !contains(parsed.Get("password"), "REDACTED") {
					t.Errorf("password should be redacted")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactedFormData(tt.data)

			for _, notExpected := range tt.shouldNotContain {
				if contains(result, notExpected) {
					t.Errorf("RedactedFormData() result should not contain %q, got %v", notExpected, result)
				}
			}

			if tt.checkFn != nil {
				tt.checkFn(t, result)
			}
		})
	}
}

func TestRedactedTokenReview(t *testing.T) {
	tests := []struct {
		name    string
		tr      *authv1.TokenReview
		checkFn func(*testing.T, *authv1.TokenReview)
	}{
		{
			name: "TokenReview with token",
			tr: &authv1.TokenReview{
				Spec: authv1.TokenReviewSpec{
					Token:     "my-secret-token",
					Audiences: []string{"my-api"},
				},
			},
			checkFn: func(t *testing.T, result *authv1.TokenReview) {
				if result.Spec.Token != "***REDACTED***" {
					t.Errorf("Expected token to be redacted, got %v", result.Spec.Token)
				}
				if len(result.Spec.Audiences) != 1 || result.Spec.Audiences[0] != "my-api" {
					t.Errorf("Audiences should be preserved, got %v", result.Spec.Audiences)
				}
			},
		},
		{
			name: "TokenReview with empty token",
			tr: &authv1.TokenReview{
				Spec: authv1.TokenReviewSpec{
					Token:     "",
					Audiences: []string{"my-api"},
				},
			},
			checkFn: func(t *testing.T, result *authv1.TokenReview) {
				if result.Spec.Token != "" {
					t.Errorf("Expected empty token to remain empty, got %v", result.Spec.Token)
				}
			},
		},
		{
			name: "Nil TokenReview",
			tr:   nil,
			checkFn: func(t *testing.T, result *authv1.TokenReview) {
				if result != nil {
					t.Errorf("Expected nil result for nil input, got %v", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactedTokenReview(tt.tr)
			tt.checkFn(t, result)

			// Ensure original is not modified
			if tt.tr != nil && tt.tr.Spec.Token != "" && tt.tr.Spec.Token == "***REDACTED***" {
				t.Error("Original TokenReview was modified")
			}
		})
	}
}

func TestRedactedHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		checkFn func(*testing.T, map[string][]string)
	}{
		{
			name: "Headers with Authorization",
			headers: map[string][]string{
				"Authorization": {"Bearer secret-token"},
				"Content-Type":  {"application/json"},
			},
			checkFn: func(t *testing.T, result map[string][]string) {
				if result["Authorization"][0] != "***REDACTED***" {
					t.Errorf("Authorization should be redacted, got %v", result["Authorization"])
				}
				if result["Content-Type"][0] != "application/json" {
					t.Errorf("Content-Type should be preserved, got %v", result["Content-Type"])
				}
			},
		},
		{
			name: "Headers with Cookie",
			headers: map[string][]string{
				"Cookie":       {"session=abc123"},
				"Content-Type": {"text/html"},
			},
			checkFn: func(t *testing.T, result map[string][]string) {
				if result["Cookie"][0] != "***REDACTED***" {
					t.Errorf("Cookie should be redacted, got %v", result["Cookie"])
				}
			},
		},
		{
			name: "Headers with case variations",
			headers: map[string][]string{
				"authorization": {"Bearer token"},
				"COOKIE":        {"session=xyz"},
			},
			checkFn: func(t *testing.T, result map[string][]string) {
				if result["authorization"][0] != "***REDACTED***" {
					t.Errorf("authorization (lowercase) should be redacted, got %v", result["authorization"])
				}
				if result["COOKIE"][0] != "***REDACTED***" {
					t.Errorf("COOKIE (uppercase) should be redacted, got %v", result["COOKIE"])
				}
			},
		},
		{
			name:    "Nil headers",
			headers: nil,
			checkFn: func(t *testing.T, result map[string][]string) {
				if result != nil {
					t.Errorf("Expected nil result for nil input, got %v", result)
				}
			},
		},
		{
			name: "Headers with X-API-Key",
			headers: map[string][]string{
				"X-API-Key": {"myapikey123"},
			},
			checkFn: func(t *testing.T, result map[string][]string) {
				if result["X-API-Key"][0] != "***REDACTED***" {
					t.Errorf("X-API-Key should be redacted, got %v", result["X-API-Key"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactedHeaders(tt.headers)
			tt.checkFn(t, result)

			// Ensure original is not modified
			if tt.headers != nil {
				for k, v := range tt.headers {
					if len(v) > 0 && v[0] == "***REDACTED***" {
						t.Errorf("Original headers were modified for key %s", k)
					}
				}
			}
		})
	}
}

func TestRedactedRequestBody(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		contentType      string
		shouldNotContain []string
		checkFn          func(*testing.T, string)
	}{
		{
			name:             "Form-encoded body with token",
			body:             "token=secrettoken&grant_type=client_credentials",
			contentType:      "application/x-www-form-urlencoded",
			shouldNotContain: []string{"secrettoken"},
			checkFn: func(t *testing.T, result string) {
				parsed, _ := url.ParseQuery(result)
				if !contains(parsed.Get("token"), "REDACTED") {
					t.Errorf("token should be redacted")
				}
				if parsed.Get("grant_type") != "client_credentials" {
					t.Errorf("grant_type should be preserved")
				}
			},
		},
		{
			name:             "JSON body",
			body:             `{"token":"secret","username":"admin"}`,
			contentType:      "application/json",
			shouldNotContain: []string{"secret", "admin"},
			checkFn: func(t *testing.T, result string) {
				if !contains(result, "REDACTED") {
					t.Errorf("JSON body should be redacted")
				}
			},
		},
		{
			name:             "Empty body",
			body:             "",
			contentType:      "application/json",
			shouldNotContain: []string{},
			checkFn: func(t *testing.T, result string) {
				if result != "" {
					t.Errorf("Empty body should return empty string, got %v", result)
				}
			},
		},
		{
			name:             "Unknown content type",
			body:             "some sensitive data",
			contentType:      "text/plain",
			shouldNotContain: []string{"sensitive"},
			checkFn: func(t *testing.T, result string) {
				if !contains(result, "REDACTED") {
					t.Errorf("Unknown content type body should be redacted")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactedRequestBody(tt.body, tt.contentType)

			for _, notExpected := range tt.shouldNotContain {
				if contains(result, notExpected) {
					t.Errorf("RedactedRequestBody() result should not contain %q, got %v", notExpected, result)
				}
			}

			if tt.checkFn != nil {
				tt.checkFn(t, result)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestAddRemoveSensitiveField(t *testing.T) {
	// Save original state
	originalFields := GetSensitiveFields()
	defer func() {
		// Restore original state
		sensitiveFieldsMu.Lock()
		sensitiveFields = originalFields
		sensitiveFieldsMu.Unlock()
	}()

	// Add a custom field
	AddSensitiveField("custom_token")

	// Test that it's now redacted
	data := "custom_token=secret123&other=value"
	result := RedactedFormData(data)

	parsed, _ := url.ParseQuery(result)
	if !contains(parsed.Get("custom_token"), "REDACTED") {
		t.Errorf("custom_token should be redacted after adding")
	}
	if parsed.Get("other") != "value" {
		t.Errorf("other field should be preserved")
	}

	// Remove the custom field
	RemoveSensitiveField("custom_token")

	// Test that it's no longer redacted
	result2 := RedactedFormData(data)
	parsed2, _ := url.ParseQuery(result2)
	if parsed2.Get("custom_token") != "secret123" {
		t.Errorf("custom_token should not be redacted after removal, got %v", parsed2.Get("custom_token"))
	}
}

func TestAddRemoveSensitiveHeader(t *testing.T) {
	// Save original state
	originalHeaders := GetSensitiveHeaders()
	defer func() {
		// Restore original state
		sensitiveHeadersMu.Lock()
		sensitiveHeaders = originalHeaders
		sensitiveHeadersMu.Unlock()
	}()

	// Add a custom header
	AddSensitiveHeader("X-Custom-Token")

	// Test that it's now redacted
	headers := map[string][]string{
		"X-Custom-Token": {"secret123"},
		"Content-Type":   {"application/json"},
	}
	result := RedactedHeaders(headers)

	if result["X-Custom-Token"][0] != "***REDACTED***" {
		t.Errorf("X-Custom-Token should be redacted after adding")
	}
	if result["Content-Type"][0] != "application/json" {
		t.Errorf("Content-Type should be preserved")
	}

	// Remove the custom header
	RemoveSensitiveHeader("X-Custom-Token")

	// Test that it's no longer redacted
	result2 := RedactedHeaders(headers)
	if result2["X-Custom-Token"][0] != "secret123" {
		t.Errorf("X-Custom-Token should not be redacted after removal, got %v", result2["X-Custom-Token"][0])
	}
}

func TestCaseInsensitiveSensitiveFields(t *testing.T) {
	// Save original state
	originalFields := GetSensitiveFields()
	defer func() {
		sensitiveFieldsMu.Lock()
		sensitiveFields = originalFields
		sensitiveFieldsMu.Unlock()
	}()

	// Add field in mixed case
	AddSensitiveField("MyCustomToken")

	// Test that it matches in various cases
	testCases := []string{
		"mycustomtoken=secret",
		"MyCustomToken=secret",
		"MYCUSTOMTOKEN=secret",
	}

	for _, tc := range testCases {
		result := RedactedFormData(tc)
		if contains(result, "secret") {
			t.Errorf("Field should be redacted regardless of case: %s", tc)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Save original state
	originalFields := GetSensitiveFields()
	originalHeaders := GetSensitiveHeaders()
	defer func() {
		sensitiveFieldsMu.Lock()
		sensitiveFields = originalFields
		sensitiveFieldsMu.Unlock()
		sensitiveHeadersMu.Lock()
		sensitiveHeaders = originalHeaders
		sensitiveHeadersMu.Unlock()
	}()

	// Test concurrent reads and writes
	done := make(chan bool)

	// Writer goroutines
	for i := 0; i < 10; i++ {
		go func(n int) {
			for j := 0; j < 100; j++ {
				if n%2 == 0 {
					AddSensitiveField("test")
					AddSensitiveHeader("test")
				} else {
					RemoveSensitiveField("test")
					RemoveSensitiveHeader("test")
				}
			}
			done <- true
		}(i)
	}

	// Reader goroutines
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = GetSensitiveFields()
				_ = GetSensitiveHeaders()
				_ = RedactedFormData("test=value")
				_ = RedactedHeaders(map[string][]string{"Test": {"value"}})
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestRedactedAuthorizationJSON(t *testing.T) {
	tests := []struct {
		name             string
		authJSON         string
		shouldNotContain []string
		checkFn          func(*testing.T, interface{})
	}{
		{
			name: "Authorization JSON with sensitive headers",
			authJSON: `{
				"context": {
					"request": {
						"http": {
							"headers": {
								"authorization": "Bearer secret-token",
								"cookie": "session=abc123",
								"content-type": "application/json"
							}
						}
					}
				},
				"identity": {
					"username": "john"
				}
			}`,
			shouldNotContain: []string{"secret-token", "abc123"},
			checkFn: func(t *testing.T, result interface{}) {
				data, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("Result should be a map")
				}

				context := data["context"].(map[string]interface{})
				request := context["request"].(map[string]interface{})
				httpReq := request["http"].(map[string]interface{})
				headers := httpReq["headers"].(map[string]string)

				if headers["authorization"] != "***REDACTED***" {
					t.Errorf("authorization header should be redacted, got %v", headers["authorization"])
				}
				if headers["cookie"] != "***REDACTED***" {
					t.Errorf("cookie header should be redacted, got %v", headers["cookie"])
				}
				if headers["content-type"] != "application/json" {
					t.Errorf("content-type should be preserved, got %v", headers["content-type"])
				}
			},
		},
		{
			name: "Authorization JSON with headers in both locations",
			authJSON: `{
				"context": {
					"request": {
						"http": {
							"headers": {
								"authorization": "Bearer context-token",
								"content-type": "application/json"
							}
						}
					}
				},
				"request": {
					"headers": {
						"authorization": "Bearer request-token",
						"cookie": "session=xyz",
						"user-agent": "curl/7.0"
					}
				}
			}`,
			shouldNotContain: []string{"context-token", "request-token", "xyz"},
			checkFn: func(t *testing.T, result interface{}) {
				data, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("Result should be a map")
				}

				// Check context.request.http.headers
				context := data["context"].(map[string]interface{})
				contextRequest := context["request"].(map[string]interface{})
				httpReq := contextRequest["http"].(map[string]interface{})
				contextHeaders := httpReq["headers"].(map[string]string)

				if contextHeaders["authorization"] != "***REDACTED***" {
					t.Errorf("context authorization header should be redacted, got %v", contextHeaders["authorization"])
				}
				if contextHeaders["content-type"] != "application/json" {
					t.Errorf("context content-type should be preserved")
				}

				// Check request.headers
				request := data["request"].(map[string]interface{})
				requestHeaders := request["headers"].(map[string]string)

				if requestHeaders["authorization"] != "***REDACTED***" {
					t.Errorf("request authorization header should be redacted, got %v", requestHeaders["authorization"])
				}
				if requestHeaders["cookie"] != "***REDACTED***" {
					t.Errorf("request cookie header should be redacted, got %v", requestHeaders["cookie"])
				}
				if requestHeaders["user-agent"] != "curl/7.0" {
					t.Errorf("request user-agent should be preserved")
				}
			},
		},
		{
			name: "Authorization JSON with sensitive identity fields",
			authJSON: `{
				"identity": {
					"username": "john",
					"access_token": "secret-access-token",
					"api_key": "my-api-key",
					"nested": {
						"refresh_token": "secret-refresh-token"
					}
				}
			}`,
			shouldNotContain: []string{"secret-access-token", "my-api-key", "secret-refresh-token"},
			checkFn: func(t *testing.T, result interface{}) {
				data, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("Result should be a map")
				}

				identity := data["identity"].(map[string]interface{})
				if identity["username"] != "john" {
					t.Errorf("username should be preserved")
				}
				if identity["access_token"] != "***REDACTED***" {
					t.Errorf("access_token should be redacted")
				}
				if identity["api_key"] != "***REDACTED***" {
					t.Errorf("api_key should be redacted")
				}

				nested := identity["nested"].(map[string]interface{})
				if nested["refresh_token"] != "***REDACTED***" {
					t.Errorf("nested refresh_token should be redacted")
				}
			},
		},
		{
			name:             "Invalid JSON",
			authJSON:         `{invalid json`,
			shouldNotContain: []string{},
			checkFn: func(t *testing.T, result interface{}) {
				if result != "***REDACTED***" {
					t.Errorf("Invalid JSON should return redacted placeholder, got %v", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactedAuthorizationJSON(tt.authJSON)

			// Check that sensitive data is not in the result when serialized
			serialized, _ := json.Marshal(result)
			resultStr := string(serialized)
			for _, notExpected := range tt.shouldNotContain {
				if contains(resultStr, notExpected) {
					t.Errorf("Result should not contain %q, got %v", notExpected, resultStr)
				}
			}

			if tt.checkFn != nil {
				tt.checkFn(t, result)
			}
		})
	}
}
