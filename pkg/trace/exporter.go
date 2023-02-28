package trace

import (
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

func newResource(version, seed string) *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String("authorino"),
		semconv.ServiceVersionKey.String(version),
	}
	if seed != "" {
		attrs = append(attrs, attribute.String("seed", seed))

	}
	res := resource.NewWithAttributes(semconv.SchemaURL, attrs...)
	r, _ := resource.Merge(resource.Default(), res)
	return r
}

func CreateTraceProvider(url, version, seed string) (*trace.TracerProvider, error) {
	exp, err := newExporter(url)
	if err != nil {
		return nil, err
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(newResource(version, seed)),
	)
	return tp, nil
}
