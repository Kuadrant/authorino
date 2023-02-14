package trace

import (
	"fmt"
	"os"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

// NewExporter returns a Jaeger Exporter
func newExporter(url string) (*jaeger.Exporter, error) {
	endPoint := jaeger.WithEndpoint(url)
	collector := jaeger.WithCollectorEndpoint(endPoint)
	jagerEndpoint, err := jaeger.New(collector)
	return jagerEndpoint, err
}

func newResource() *resource.Resource {
	r, _ := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("authorino"),
			semconv.ServiceVersionKey.String("v0.1.0"),
			attribute.String("environment", "demo"),
		),
	)
	return r
}

func createTraceProvider(address string) *trace.TracerProvider {
	exp, err := newExporter(address)
	if err != nil {
		fmt.Println("error: ", err)
		os.Exit(1)
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(newResource()),
	)
	return tp
}
