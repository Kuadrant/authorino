package trace

import (
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

// NewExporter returns a Jaeger Exporter
func newExporter(url string) (*jaeger.Exporter, error) {
	endpoint := jaeger.WithEndpoint(url)
	collector := jaeger.WithCollectorEndpoint(endpoint)
	return jaeger.New(collector)
}

func newResource(version, tags string) *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String("authorino"),
		semconv.ServiceVersionKey.String(version),
	}
	for _, tag := range strings.Split(tags, ",") {
		parts := strings.Split(strings.TrimSpace(tag), "=")
		if len(parts) < 2 {
			continue
		}
		attrs = append(attrs, attribute.String(parts[0], strings.Join(parts[1:], "=")))
	}
	res := resource.NewWithAttributes(semconv.SchemaURL, attrs...)
	r, _ := resource.Merge(resource.Default(), res)
	return r
}

func CreateTraceProvider(url, version, tags string) (*trace.TracerProvider, error) {
	exp, err := newExporter(url)
	if err != nil {
		return nil, err
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(newResource(version, tags)),
	)
	return tp, nil
}
