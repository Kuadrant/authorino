package log

import (
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
