package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

//func TestRegistry(t *testing.T) {
//	registry := NewMetricRegistry()
//
//	labels := map[string]string{"key": "value"}
//	// Create a metric with one label
//	metric1 := registry.GetAuthServerAuthConfigTotalMetric(slices.Collect(maps.Keys(labels)))
//	metric1.With(labels).Inc()
//
//	if got := testutil.ToFloat64(metric1.With(labels)); got != 1 {
//		t.Errorf("expected 1, got %v", got)
//	}
//
//	// Create another metric with two labels (different schema)
//	labels2 := map[string]string{"key1": "value1", "key2": "value2"}
//	metric2 := registry.GetAuthServerAuthConfigTotalMetric(slices.Collect(maps.Keys(labels2)))
//	metric2.With(labels2).Inc()
//
//	if got := testutil.ToFloat64(metric2.With(labels2)); got != 1 {
//		t.Errorf("expected 1, got %v", got)
//	}
//
//	if len(registry.metrics) != 2 {
//		t.Errorf("expected 2 metrics, got %v", len(registry.metrics))
//	}
//
//	// Get metric from registry by label
//	metric3 := registry.GetAuthServerAuthConfigTotalMetric(slices.Collect(maps.Keys(labels)))
//
//	if got := testutil.ToFloat64(metric3.With(labels)); got != 1 {
//		t.Errorf("expected 1, got %v", got)
//	}
//	metric3.With(labels).Inc()
//	if got := testutil.ToFloat64(metric1.With(labels)); got != 2 {
//		t.Errorf("expected 2, got %v", got)
//	}
//	if got := testutil.ToFloat64(metric3.With(labels)); got != 2 {
//		t.Errorf("expected 2, got %v", got)
//	}
//}

func TestRegistry(t *testing.T) {
	registry := NewMetricRegistry()

	dc := registry.GetAuthServerAuthConfigTotalMetric()

	// Case 1: increment with one label
	dc.Inc(map[string]string{"key": "value"})

	if got := testutil.ToFloat64(dc.metrics[`map[key:value]`]); got != 1 {
		t.Errorf("expected 1, got %v", got)
	}

	// Case 2: increment with two labels
	dc.Inc(map[string]string{"key1": "value1", "key2": "value2"})

	if got := testutil.ToFloat64(dc.metrics[`map[key1:value1 key2:value2]`]); got != 1 {
		t.Errorf("expected 1, got %v", got)
	}

	// Case 3: increment again with one label
	dc.Inc(map[string]string{"key": "value"})

	if got := testutil.ToFloat64(dc.metrics[`map[key:value]`]); got != 2 {
		t.Errorf("expected 2, got %v", got)
	}
}
