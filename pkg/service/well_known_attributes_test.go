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

	wellKnownAttributes := NewWellKnownAttributes(envoyAttrs)

	assert.Equal(t, wellKnownAttributes.Request.Path, "/force")
	assert.Equal(t, wellKnownAttributes.Request.Referer, "www.kuadrant.io")
	assert.Equal(t, wellKnownAttributes.Request.UserAgent, "best browser ever")
	assert.Equal(t, wellKnownAttributes.Source.Service, "svc.rebels.local")
	assert.Equal(t, wellKnownAttributes.Destination.Labels, map[string]string{"squad": "rogue"})
}
