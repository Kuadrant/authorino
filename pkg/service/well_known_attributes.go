/*
Copyright 2023 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package service

import (
	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyauth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang/protobuf/ptypes/timestamp"
	"net/url"
)

type WellKnownAttributes struct {
	// Dynamic request metadata
	Metadata *envoycore.Metadata `json:"metadata,omitempty"`
	// Request attributes
	Request *RequestAttributes `json:"request,omitempty"`
	// Source attributes
	Source *SourceAttributes `json:"source,omitempty"`
	// Destination attributes
	Destination *DestinationAttributes `json:"destination,omitempty"`
}

type RequestAttributes struct {
	// Request ID corresponding to x-request-id header value
	Id string `json:"id,omitempty"`
	// Time of the first byte received
	Time *timestamp.Timestamp `json:"time,omitempty"`
	// Request protocol (“HTTP/1.0”, “HTTP/1.1”, “HTTP/2”, or “HTTP/3”)
	Protocol string `json:"protocol,omitempty"`
	// The scheme portion of the URL e.g. “http”
	Scheme string `json:"scheme,omitempty"`
	// The host portion of the URL e.g. “example.com”
	Host string `json:"host,omitempty"`
	// Request method e.g. “GET”
	Method string `json:"method,omitempty"`
	// The path portion of the URL e.g. “/foo?bar=baz”
	Path string `json:"path,omitempty"`
	// The path portion of the URL without the query string e.g. “/foo”
	URLPath string `json:"url_path,omitempty"`
	// The query portion of the URL in the format of “name1=value1&name2=value2”
	Query string `json:"query,omitempty"`
	// All request headers indexed by the lower-cased header name e.g. “accept-encoding”: “gzip”
	Headers map[string]string `json:"headers,omitempty"`
	// Referer request header e.g. “https://www.kuadrant.io/”
	Referer string `json:"referer,omitempty"`
	// User agent request header e.g. “Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/…”
	UserAgent string `json:"user_agent,omitempty"`
	// The HTTP request size in bytes. If unknown, it must be -1 e.g. 1234
	Size int64 `json:"size,omitempty"`
	// The HTTP request body. (Disabled by default. Requires additional proxy configuration to enabled it.) e.g. “…”
	Body string `json:"body,omitempty"`
	// The HTTP request body in bytes. This is sometimes used instead of body depending on the proxy configuration. e.g. 1234
	RawBody []byte `json:"raw_body,omitempty"`
	// This is analogous to request.headers, however these contents are not sent to the upstream server. It provides an
	// extension mechanism for sending additional information to the auth service without modifying the proto definition.
	// It maps to the internal opaque context in the proxy filter chain. (Requires additional configuration in the proxy.)
	ContextExtensions map[string]string `json:"context_extensions,omitempty"`
}

type SourceAttributes struct {
	// Downstream connection remote address
	Address string `json:"address,omitempty"`
	// Downstream connection remote port e.g. 8080
	Port int32 `json:"port,omitempty"`
	// The canonical service name of the peer e.g. “foo.default.svc.cluster.local”
	Service string `json:"service,omitempty"`
	// The labels associated with the peer. These could be pod labels for Kubernetes or tags for VMs. The source of the
	// labels could be an X.509 certificate or other configuration.
	Labels map[string]string `json:"labels,omitempty"`
	// The authenticated identity of this peer. If an X.509 certificate is used to assert the identity in the proxy, this
	// field is sourced from "URI Subject Alternative Names", "DNS Subject Alternate Names" or "Subject" in that order.
	// The format is issuer specific – e.g. SPIFFE format is spiffe://trust-domain/path, Google account format is https://accounts.google.com/{userid}.
	Principal string `json:"principal,omitempty"`
	// The X.509 certificate used to authenticate the identity of this peer. When present, the certificate contents are encoded in URL and PEM format.
	Certificate string `json:"certificate,omitempty"`
}

type DestinationAttributes struct {
	// Downstream connection local address
	Address string `json:"address,omitempty"`
	// Downstream connection local port e.g. 9090
	Port int32 `json:"port,omitempty"`
	// The canonical service name of the peer e.g. “foo.default.svc.cluster.local”
	Service string `json:"service,omitempty"`
	// The labels associated with the peer. These could be pod labels for Kubernetes or tags for VMs. The source of the
	// labels could be an X.509 certificate or other configuration.
	Labels map[string]string `json:"labels,omitempty"`
	// The authenticated identity of this peer. If an X.509 certificate is used to assert the identity in the proxy, this
	// field is sourced from "URI Subject Alternative Names", "DNS Subject Alternate Names" or "Subject" in that order.
	// The format is issuer specific – e.g. SPIFFE format is spiffe://trust-domain/path, Google account format is https://accounts.google.com/{userid}.
	Principal string `json:"principal,omitempty"`
	// The X.509 certificate used to authenticate the identity of this peer. When present, the certificate contents are encoded in URL and PEM format.
	Certificate string `json:"certificate,omitempty"`
}

type AuthAttributes struct {
	// Single resolved identity object, post-identity verification
	Identity any `json:"identity,omitempty"`
	// External metadata fetched
	Metadata map[string]any `json:"metadata,omitempty"`
	// Authorization results resolved by each authorization rule, access granted only
	Authorization map[string]any `json:"authorization,omitempty"`
	// Response objects exported by the auth service post-access granted
	Response map[string]any `json:"response,omitempty"`
	// Response objects returned by the callback requests issued by the auth service
	Callbacks map[string]any `json:"callbacks,omitempty"`
}

// NewWellKnownAttributes creates a new WellKnownAttributes object from an envoyauth.AttributeContext
func NewWellKnownAttributes(attributes *envoyauth.AttributeContext) *WellKnownAttributes {
	return &WellKnownAttributes{
		Metadata:    attributes.MetadataContext,
		Request:     newRequestAttributes(attributes),
		Source:      newSourceAttributes(attributes),
		Destination: newDestinationAttributes(attributes),
	}
}

func newRequestAttributes(attributes *envoyauth.AttributeContext) *RequestAttributes {
	request := attributes.GetRequest()
	httpRequest := request.GetHttp()
	urlParsed, _ := url.Parse(httpRequest.Path)
	headers := httpRequest.GetHeaders()
	return &RequestAttributes{
		Id:                httpRequest.Id,
		Time:              request.Time,
		Protocol:          httpRequest.Protocol,
		Scheme:            httpRequest.GetScheme(),
		Host:              httpRequest.GetHost(),
		Method:            httpRequest.GetMethod(),
		Path:              httpRequest.GetPath(),
		URLPath:           urlParsed.Path,
		Query:             urlParsed.RawQuery,
		Headers:           headers,
		Referer:           headers["referer"],
		UserAgent:         headers["user-agent"],
		Size:              httpRequest.GetSize(),
		Body:              httpRequest.GetBody(),
		RawBody:           httpRequest.GetRawBody(),
		ContextExtensions: attributes.GetContextExtensions(),
	}
}

func newSourceAttributes(attributes *envoyauth.AttributeContext) *SourceAttributes {
	source := attributes.Source
	socketAddress := source.GetAddress().GetSocketAddress()
	return &SourceAttributes{
		Address:   socketAddress.GetAddress(),
		Port:      int32(socketAddress.GetPortValue()),
		Service:   source.GetService(),
		Labels:    source.GetLabels(),
		Principal: source.GetPrincipal(),
	}
}

func newDestinationAttributes(attributes *envoyauth.AttributeContext) *DestinationAttributes {
	destination := attributes.Destination
	socketAddress := destination.GetAddress().GetSocketAddress()
	return &DestinationAttributes{
		Address:   socketAddress.GetAddress(),
		Port:      int32(socketAddress.GetPortValue()),
		Service:   destination.GetService(),
		Labels:    destination.GetLabels(),
		Principal: destination.GetPrincipal(),
	}
}
