package service

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRegistry(t *testing.T) {
	registry := NewMetricRegistry()

	dc := registry.GetAuthServerAuthConfigTotalMetric()

	// Case 1: increment with one label
	dc.Inc(map[string]string{"key": "value"})

	if got := testutil.ToFloat64(dc.Counters()[`map[key:value]`]); got != 1 {
		t.Errorf("expected 1, got %v", got)
	}

	// Case 2: increment with two labels
	dc.Inc(map[string]string{"key1": "value1", "key2": "value2"})

	if got := testutil.ToFloat64(dc.Counters()[`map[key1:value1 key2:value2]`]); got != 1 {
		t.Errorf("expected 1, got %v", got)
	}

	// Case 3: increment again with one label
	dc.Inc(map[string]string{"key": "value"})

	if got := testutil.ToFloat64(dc.Counters()[`map[key:value]`]); got != 2 {
		t.Errorf("expected 2, got %v", got)
	}
}
