package http

import (
	"context"
	"net/http"
	"strings"
	"testing"

	mock_http "github.com/kuadrant/authorino/pkg/http/mocks"
	"go.uber.org/mock/gomock"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Valid URLs
		{
			name:    "valid http URL",
			url:     "http://example.com",
			wantErr: false,
		},
		{
			name:    "valid https URL",
			url:     "https://example.com",
			wantErr: false,
		},
		{
			name:    "valid URL with path",
			url:     "https://example.com/path/to/resource",
			wantErr: false,
		},
		{
			name:    "valid URL with query parameters",
			url:     "https://example.com/api?foo=bar&baz=qux",
			wantErr: false,
		},
		{
			name:    "valid URL with port",
			url:     "https://example.com:8443/api",
			wantErr: false,
		},
		{
			name:    "valid URL with user info",
			url:     "https://user:pass@example.com/api",
			wantErr: false,
		},
		{
			name:    "valid URL with fragment",
			url:     "https://example.com/page#section",
			wantErr: false,
		},
		{
			name:    "valid URL with encoded characters in query",
			url:     "https://example.com/api?name=John%20Doe&id=123",
			wantErr: false,
		},
		{
			name:    "valid URL with multiple @ in userinfo",
			url:     "https://user@domain:pass@example.com/api",
			wantErr: false,
		},

		// Invalid URLs - malformed
		{
			name:    "completely malformed URL",
			url:     "ht!tp://invalid url with spaces",
			wantErr: true,
		},
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
		},

		// Invalid URLs - missing scheme
		{
			name:    "missing scheme",
			url:     "example.com",
			wantErr: true,
		},
		{
			name:    "missing scheme with path",
			url:     "example.com/path",
			wantErr: true,
		},

		// Invalid URLs - unsupported scheme
		{
			name:    "file scheme",
			url:     "file:///etc/passwd",
			wantErr: true,
		},
		{
			name:    "ftp scheme",
			url:     "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "javascript scheme",
			url:     "javascript:alert(1)",
			wantErr: true,
		},
		{
			name:    "data scheme",
			url:     "data:text/html,<script>alert(1)</script>",
			wantErr: true,
		},
		{
			name:    "gopher scheme",
			url:     "gopher://example.com",
			wantErr: true,
		},

		// Invalid URLs - missing host
		{
			name:    "http scheme without host",
			url:     "http://",
			wantErr: true,
		},
		{
			name:    "https scheme without host",
			url:     "https://",
			wantErr: true,
		},

		// Invalid URLs - control characters
		{
			name:    "URL with tab character in host",
			url:     "http://example.com\t/path",
			wantErr: true,
		},
		{
			name:    "URL with newline in host",
			url:     "http://example.com\n/path",
			wantErr: true,
		},
		{
			name:    "URL with carriage return in host",
			url:     "http://example.com\r/path",
			wantErr: true,
		},
		{
			name:    "URL with null byte",
			url:     "http://example.com\x00/path",
			wantErr: true,
		},

		// Invalid URLs - excessive length
		{
			name:    "URL exceeds maximum length",
			url:     "https://example.com/" + strings.Repeat("a", 2048),
			wantErr: true,
		},

		// Edge cases that should be valid (SSRF targets, but structurally valid URLs)
		// Note: We validate URL structure, not whether the target is safe
		{
			name:    "localhost (valid URL structure)",
			url:     "http://localhost:8080",
			wantErr: false,
		},
		{
			name:    "127.0.0.1 (valid URL structure)",
			url:     "http://127.0.0.1",
			wantErr: false,
		},
		{
			name:    "private IP 10.x.x.x (valid URL structure)",
			url:     "http://10.0.0.1",
			wantErr: false,
		},
		{
			name:    "private IP 192.168.x.x (valid URL structure)",
			url:     "http://192.168.1.1",
			wantErr: false,
		},
		{
			name:    "cloud metadata endpoint (valid URL structure)",
			url:     "http://169.254.169.254/latest/meta-data/",
			wantErr: false,
		},
		{
			name:    "internal Kubernetes service (valid URL structure)",
			url:     "http://kubernetes.default.svc.cluster.local",
			wantErr: false,
		},
		{
			name: "URL at exact max length",
			url: func() string {
				const prefix = "https://example.com/"
				return prefix + strings.Repeat("a", 2048-len(prefix))
			}(),
			wantErr: false,
		},
		{
			name: "URL one char over max length",
			url: func() string {
				const prefix = "https://example.com/"
				return prefix + strings.Repeat("a", 2049-len(prefix))
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewRequest(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		method  string
		url     string
		wantErr bool
	}{
		{
			name:    "valid GET request",
			method:  "GET",
			url:     "https://example.com/api",
			wantErr: false,
		},
		{
			name:    "valid POST request",
			method:  "POST",
			url:     "https://example.com/api",
			wantErr: false,
		},
		{
			name:    "invalid URL with file scheme",
			method:  "GET",
			url:     "file:///etc/passwd",
			wantErr: true,
		},
		{
			name:    "invalid URL with control character",
			method:  "GET",
			url:     "http://example.com\n/path",
			wantErr: true,
		},
		{
			name:    "invalid URL missing scheme",
			method:  "GET",
			url:     "example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := NewRequest(ctx, tt.method, tt.url, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if req == nil {
					t.Error("NewRequest() returned nil request for valid input")
				} else {
					if req.Method != tt.method {
						t.Errorf("NewRequest() method = %v, want %v", req.Method, tt.method)
					}
					if req.URL.String() != tt.url {
						t.Errorf("NewRequest() URL = %v, want %v", req.URL.String(), tt.url)
					}
				}
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Error("NewClient() returned nil")
	}
}

func TestNewRequestWithCredentials(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tests := []struct {
		name            string
		endpoint        string
		method          string
		credentialValue string
		setupMock       func() *mock_http.MockCredentialLocation
		wantErr         bool
		checkHeader     func(t *testing.T, req *http.Request)
		checkURL        func(t *testing.T, req *http.Request)
	}{
		{
			name:            "credentials in authorization header",
			endpoint:        "https://example.com/api",
			method:          "GET",
			credentialValue: "token123",
			setupMock: func() *mock_http.MockCredentialLocation {
				mock := mock_http.NewMockCredentialLocation(ctrl)
				mock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
				mock.EXPECT().GetPlacement().Return(InAuthorizationHeader).AnyTimes()
				return mock
			},
			wantErr: false,
			checkHeader: func(t *testing.T, req *http.Request) {
				if got := req.Header.Get("Authorization"); got != "Bearer token123" {
					t.Errorf("Authorization header = %v, want %v", got, "Bearer token123")
				}
			},
		},
		{
			name:            "credentials in custom header",
			endpoint:        "https://example.com/api",
			method:          "GET",
			credentialValue: "apikey123",
			setupMock: func() *mock_http.MockCredentialLocation {
				mock := mock_http.NewMockCredentialLocation(ctrl)
				mock.EXPECT().GetIdentifier().Return("X-API-Key").AnyTimes()
				mock.EXPECT().GetPlacement().Return(InCustomHeader).AnyTimes()
				return mock
			},
			wantErr: false,
			checkHeader: func(t *testing.T, req *http.Request) {
				if got := req.Header.Get("X-API-Key"); got != "apikey123" {
					t.Errorf("X-API-Key header = %v, want %v", got, "apikey123")
				}
			},
		},
		{
			name:            "credentials in cookie",
			endpoint:        "https://example.com/api",
			method:          "GET",
			credentialValue: "session123",
			setupMock: func() *mock_http.MockCredentialLocation {
				mock := mock_http.NewMockCredentialLocation(ctrl)
				mock.EXPECT().GetIdentifier().Return("session_id").AnyTimes()
				mock.EXPECT().GetPlacement().Return(InCookie).AnyTimes()
				return mock
			},
			wantErr: false,
			checkHeader: func(t *testing.T, req *http.Request) {
				if got := req.Header.Get("Cookie"); got != "session_id=session123" {
					t.Errorf("Cookie header = %v, want %v", got, "session_id=session123")
				}
			},
		},
		{
			name:            "credentials in query - no existing params",
			endpoint:        "https://example.com/api",
			method:          "GET",
			credentialValue: "token123",
			setupMock: func() *mock_http.MockCredentialLocation {
				mock := mock_http.NewMockCredentialLocation(ctrl)
				mock.EXPECT().GetIdentifier().Return("access_token").AnyTimes()
				mock.EXPECT().GetPlacement().Return(InQuery).AnyTimes()
				return mock
			},
			wantErr: false,
			checkURL: func(t *testing.T, req *http.Request) {
				if got := req.URL.String(); got != "https://example.com/api?access_token=token123" {
					t.Errorf("URL = %v, want %v", got, "https://example.com/api?access_token=token123")
				}
			},
		},
		{
			name:            "credentials in query - existing params",
			endpoint:        "https://example.com/api?foo=bar",
			method:          "GET",
			credentialValue: "token123",
			setupMock: func() *mock_http.MockCredentialLocation {
				mock := mock_http.NewMockCredentialLocation(ctrl)
				mock.EXPECT().GetIdentifier().Return("access_token").AnyTimes()
				mock.EXPECT().GetPlacement().Return(InQuery).AnyTimes()
				return mock
			},
			wantErr: false,
			checkURL: func(t *testing.T, req *http.Request) {
				if got := req.URL.String(); got != "https://example.com/api?foo=bar&access_token=token123" {
					t.Errorf("URL = %v, want %v", got, "https://example.com/api?foo=bar&access_token=token123")
				}
			},
		},
		{
			name:            "empty credential value",
			endpoint:        "https://example.com/api",
			method:          "GET",
			credentialValue: "",
			setupMock: func() *mock_http.MockCredentialLocation {
				mock := mock_http.NewMockCredentialLocation(ctrl)
				mock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
				mock.EXPECT().GetPlacement().Return(InAuthorizationHeader).AnyTimes()
				return mock
			},
			wantErr: false,
			checkHeader: func(t *testing.T, req *http.Request) {
				if got := req.Header.Get("Authorization"); got != "" {
					t.Errorf("Authorization header should be empty, got %v", got)
				}
			},
		},
		{
			name:            "nil credentials",
			endpoint:        "https://example.com/api",
			method:          "GET",
			credentialValue: "token123",
			setupMock:       nil, // explicitly nil to test nil credentials
			wantErr:         true,
		},
		{
			name:            "invalid URL",
			endpoint:        "not a valid url",
			method:          "GET",
			credentialValue: "token123",
			setupMock: func() *mock_http.MockCredentialLocation {
				mock := mock_http.NewMockCredentialLocation(ctrl)
				mock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
				mock.EXPECT().GetPlacement().Return(InAuthorizationHeader).AnyTimes()
				return mock
			},
			wantErr: true,
		},
		{
			name:            "unsupported credential location",
			endpoint:        "https://example.com/api",
			method:          "GET",
			credentialValue: "token123",
			setupMock: func() *mock_http.MockCredentialLocation {
				mock := mock_http.NewMockCredentialLocation(ctrl)
				mock.EXPECT().GetIdentifier().Return("Bearer").AnyTimes()
				mock.EXPECT().GetPlacement().Return("unsupported").AnyTimes()
				return mock
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var credentials CredentialLocation
			if tt.setupMock != nil {
				credentials = tt.setupMock()
			}
			req, err := NewRequestWithCredentials(ctx, tt.method, tt.endpoint, nil, credentials, tt.credentialValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRequestWithCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if req == nil {
					t.Error("NewRequestWithCredentials() returned nil request for valid input")
					return
				}
				if req.Method != tt.method {
					t.Errorf("NewRequestWithCredentials() method = %v, want %v", req.Method, tt.method)
				}
				if tt.checkHeader != nil {
					tt.checkHeader(t, req)
				}
				if tt.checkURL != nil {
					tt.checkURL(t, req)
				}
			}
		})
	}
}
