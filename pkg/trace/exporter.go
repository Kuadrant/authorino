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
	jagerEndpoint, err := jaeger.New(collector)
	return jagerEndpoint, err
}

func newResource(version string) *resource.Resource {
	r, _ := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("authorino"),
			semconv.ServiceVersionKey.String(version),
			attribute.String("environment", "demo"),
		),
	)
	return r
}

func CreateTraceProvider(url string, version string) (*trace.TracerProvider, error) {
	exp, err := newExporter(url)
	if err != nil {
		return nil, err
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(newResource(version)),
	)
	return tp, nil
}
