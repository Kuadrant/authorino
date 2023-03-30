package trace

import (
	"context"

	"go.opentelemetry.io/otel"
	otel_attr "go.opentelemetry.io/otel/attribute"
	otel_trace "go.opentelemetry.io/otel/trace"
)

const (
	AuthorinoRequestIdAttr   = "authorino.request_id"
	PropagationRequestIdAttr = "guid:x-request-id"
)

func NewSpan(parentContext context.Context, tracerName, spanName string, options ...otel_trace.SpanStartOption) (context.Context, otel_trace.Span) {
	return otel.Tracer(tracerName).Start(parentContext, spanName, options...)
}

func NewAuthorizationRequestSpan(parentContext context.Context, tracerName, spanName, requestId, propagationRequestId string, options ...otel_trace.SpanStartOption) (context.Context, otel_trace.Span) {
	tracingAttrs := []otel_attr.KeyValue{otel_attr.String(AuthorinoRequestIdAttr, requestId)}
	if propagationRequestId != "" {
		tracingAttrs = append(tracingAttrs, otel_attr.String(PropagationRequestIdAttr, propagationRequestId))
	}
	return NewSpan(parentContext, tracerName, spanName, append(options, otel_trace.WithAttributes(tracingAttrs...))...)
}
