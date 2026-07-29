package trace

import (
	"errors"
	"testing"

	"go.opentelemetry.io/otel/sdk/resource"
)

func TestNewResourceSchemaURLConsistency(t *testing.T) {
	// newResource merges our semconv attributes with resource.Default() via
	// resource.Merge, which returns ErrSchemaURLConflict if the schema URLs
	// differ. This catches the case where the SDK's semconv version drifts
	// from the one imported in exporter.go (e.g. via a dependabot bump).
	_, err := newResource("test", nil)
	if errors.Is(err, resource.ErrSchemaURLConflict) {
		t.Fatalf("semconv schema URL in exporter.go conflicts with the SDK's resource.Default(): %v", err)
	}
	if err != nil {
		t.Fatalf("unexpected error creating resource: %v", err)
	}
}
