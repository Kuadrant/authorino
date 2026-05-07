package service

import (
	"testing"

	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyauth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
)

func TestNewWellKnownAttributes(t *testing.T) {
	envoyAttrs := &envoyauth.AttributeContext{
		MetadataContext: &envoycore.Metadata{},
		Request: &envoyauth.AttributeContext_Request{
			Http: &envoyauth.AttributeContext_HttpRequest{
				Headers: map[string]string{
					"referer":    "www.kuadrant.io",
					"user-agent": "best browser ever",
				},
				Path:     "/force",
				Protocol: "HTTP/2.1",
				Method:   "GET",
			},
			Time: &timestamp.Timestamp{},
		},
		Source: &envoyauth.AttributeContext_Peer{
			Service: "svc.rebels.local",
		},
		Destination: &envoyauth.AttributeContext_Peer{
			Service: "svc.rogue-1.local",
			Labels:  map[string]string{"squad": "rogue"},
		},
	}
	authData := map[string]interface{}{
		"identity":      map[string]any{"user": "luke", "group": "rebels"},
		"metadata":      map[string]any{"squad": "rogue"},
		"authorization": map[string]any{"group": "rebels"},
		"response":      map[string]any{"status": 200},
	}

	wellKnownAttributes := NewWellKnownAttributes(envoyAttrs, authData)

	assert.Equal(t, "/force", wellKnownAttributes.Request.Path)
	assert.Equal(t, "www.kuadrant.io", wellKnownAttributes.Request.Referer)
	assert.Equal(t, "best browser ever", wellKnownAttributes.Request.UserAgent)
	assert.Equal(t, "svc.rebels.local", wellKnownAttributes.Source.Service)
	assert.Equal(t, map[string]string{"squad": "rogue"}, wellKnownAttributes.Destination.Labels)
	assert.Equal(t, map[string]any{"user": "luke", "group": "rebels"}, wellKnownAttributes.Auth.Identity)
	assert.Equal(t, map[string]any{"squad": "rogue"}, wellKnownAttributes.Auth.Metadata)
	assert.Equal(t, map[string]any{"group": "rebels"}, wellKnownAttributes.Auth.Authorization)
	assert.Equal(t, map[string]any{"status": 200}, wellKnownAttributes.Auth.Response)
	assert.Nil(t, wellKnownAttributes.Auth.Callbacks)
	assert.Nil(t, wellKnownAttributes.Request.GRPC)
}

func TestNewWellKnownAttributesGRPC(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		headers      map[string]string
		expectedGRPC *GRPCAttributes
	}{
		{
			name: "gRPC request with valid path",
			path: "/UserService/GetUser",
			headers: map[string]string{
				"content-type": "application/grpc",
			},
			expectedGRPC: &GRPCAttributes{Service: "UserService", Method: "GetUser"},
		},
		{
			name: "gRPC+proto request with packaged service",
			path: "/com.example.UserService/GetUser",
			headers: map[string]string{
				"content-type": "application/grpc+proto",
			},
			expectedGRPC: &GRPCAttributes{Service: "com.example.UserService", Method: "GetUser"},
		},
		{
			name: "gRPC request with malformed path",
			path: "/OnlyService",
			headers: map[string]string{
				"content-type": "application/grpc",
			},
			expectedGRPC: nil,
		},
		{
			name: "non-gRPC request",
			path: "/UserService/GetUser",
			headers: map[string]string{
				"content-type": "application/json",
			},
			expectedGRPC: nil,
		},
		{
			name:         "no content-type header",
			path:         "/UserService/GetUser",
			headers:      map[string]string{},
			expectedGRPC: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envoyAttrs := &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{
					Http: &envoyauth.AttributeContext_HttpRequest{
						Headers: tt.headers,
						Path:    tt.path,
						Method:  "POST",
					},
				},
				Source:      &envoyauth.AttributeContext_Peer{},
				Destination: &envoyauth.AttributeContext_Peer{},
			}

			wellKnownAttributes := NewWellKnownAttributes(envoyAttrs, nil)
			assert.Equal(t, tt.expectedGRPC, wellKnownAttributes.Request.GRPC)
		})
	}
}

func TestIsGRPCRequest(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "application/grpc content-type",
			headers:  map[string]string{"content-type": "application/grpc"},
			expected: true,
		},
		{
			name:     "application/grpc+proto content-type",
			headers:  map[string]string{"content-type": "application/grpc+proto"},
			expected: true,
		},
		{
			name:     "application/grpc+json content-type",
			headers:  map[string]string{"content-type": "application/grpc+json"},
			expected: true,
		},
		{
			name:     "application/json content-type",
			headers:  map[string]string{"content-type": "application/json"},
			expected: false,
		},
		{
			name:     "no content-type header",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name:     "empty content-type",
			headers:  map[string]string{"content-type": ""},
			expected: false,
		},
		{
			name:     "nil headers",
			headers:  nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isGRPCRequest(tt.headers))
		})
	}
}

func TestParseGRPCPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected *GRPCAttributes
	}{
		{
			name:     "standard gRPC path",
			path:     "/UserService/GetUser",
			expected: &GRPCAttributes{Service: "UserService", Method: "GetUser"},
		},
		{
			name:     "packaged service name",
			path:     "/com.example.UserService/GetUser",
			expected: &GRPCAttributes{Service: "com.example.UserService", Method: "GetUser"},
		},
		{
			name:     "single segment path",
			path:     "/OnlyService",
			expected: nil,
		},
		{
			name:     "root path",
			path:     "/",
			expected: nil,
		},
		{
			name:     "empty path",
			path:     "",
			expected: nil,
		},
		{
			name:     "too many segments",
			path:     "/a/b/c",
			expected: nil,
		},
		{
			name:     "no leading slash",
			path:     "Service/Method",
			expected: nil,
		},
		{
			name:     "empty service",
			path:     "//Method",
			expected: nil,
		},
		{
			name:     "empty method",
			path:     "/Service/",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseGRPCPath(tt.path))
		})
	}
}
