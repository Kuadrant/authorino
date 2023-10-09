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
}
