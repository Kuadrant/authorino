package trace

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

type Config struct {
	Endpoint string
	Insecure bool
	Tags     []string
	Version  string
}

func CreateTraceProvider(config Config) (*trace.TracerProvider, error) {
	exporter, err := newExporter(config)
	if err != nil {
		return nil, err
	}

	resource, err := newResource(config.Version, config.Tags)
	if err != nil {
		return nil, err
	}

	return trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(resource),
	), nil
}

func newExporter(config Config) (trace.SpanExporter, error) {
	url, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, err
	}

	var client otlptrace.Client

	switch url.Scheme {
	case "rpc":
		opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(url.Host)}
		if authHeader := buildAuthHeader(url); authHeader != nil {
			opts = append(opts, otlptracegrpc.WithHeaders(authHeader))
		}
		if config.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		client = otlptracegrpc.NewClient(opts...)

	case "http":
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(url.Host)}
		if path := url.Path; path != "" {
			opts = append(opts, otlptracehttp.WithURLPath(path))
		}
		if authHeader := buildAuthHeader(url); authHeader != nil {
			opts = append(opts, otlptracehttp.WithHeaders(authHeader))
		}
		if config.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		client = otlptracehttp.NewClient(opts...)

	default:
		return nil, fmt.Errorf("unsupported protocol")
	}

	return otlptrace.New(context.Background(), client)
}

func newResource(version string, tags []string) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String("authorino"),
		semconv.ServiceVersionKey.String(version),
	}
	for _, tag := range tags {
		parts := strings.SplitN(strings.TrimSpace(tag), "=", 2)
		if len(parts) < 2 {
			continue
		}
		attrs = append(attrs, attribute.String(parts[0], strings.Join(parts[1:], "=")))
	}
	return resource.Merge(resource.Default(), resource.NewWithAttributes(semconv.SchemaURL, attrs...))
}

func buildAuthHeader(url *url.URL) map[string]string {
	userInfo := url.User
	if userInfo == nil {
		return nil
	}
	var authHeader string
	if passwd, passSet := userInfo.Password(); passSet {
		if user := userInfo.Username(); user != "" {
			authHeader = fmt.Sprintf("Basic %s", encodeBasicAuthCreds(user, passwd))
		} else {
			authHeader = fmt.Sprintf("Bearer %s", passwd)
		}
		// TODO(guicassolato): oauth2 authentication – implement an otlptrace.Client proxy that: (i) recovers/obtains the access token by client_credentials grant; (ii) delegates to an actual gRPC/HTTP client with the updated authorization header
	}
	return map[string]string{"Authorization": authHeader}
}

func encodeBasicAuthCreds(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
