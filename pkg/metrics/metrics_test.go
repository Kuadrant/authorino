package metrics

import (
	"maps"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/mock/gomock"
	"gotest.tools/assert"

	mock_metrics "github.com/kuadrant/authorino/pkg/metrics/mocks"
)

func TestReportMetric(t *testing.T) {
	metric := NewDynamicCounter("foo", "Foo metric")
	ReportMetric(metric, map[string]string{})
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
}

func TestReportMetricWithStatus(t *testing.T) {
	metric := NewDynamicCounter("foo", "Foo metric")
	ReportMetricWithStatus(metric, "OK", map[string]string{})
	assert.Equal(t, float64(1), testutil.ToFloat64(metric))
}

func TestReportMetricWithObject(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	metric := NewDynamicCounter("foo", "Foo metric")

	object := mock_metrics.NewMockObject(ctrl)
	object.EXPECT().GetType().Return("AUTHZ_X")
	object.EXPECT().GetName().Return("foo")

	object.EXPECT().MetricsEnabled().Return(true)
	ReportMetricWithObject(metric, object, map[string]string{"type": "AUTHZ_X", "name": "foo"})
	assert.Equal(t, float64(1), testutil.ToFloat64(metric))

	object.EXPECT().MetricsEnabled().Return(false)
	ReportMetricWithObject(metric, object, map[string]string{})
	assert.Equal(t, float64(1), testutil.ToFloat64(metric))

	ReportMetricWithObject(metric, nil, map[string]string{})
	assert.Equal(t, float64(1), testutil.ToFloat64(metric))
}

func TestReportTimedMetric(t *testing.T) {
	metric := NewDynamicHistogram("foo", "Foo metric")
	var invoked bool
	f := func() {
		invoked = true
	}
	ReportTimedMetric(metric, f, map[string]string{})
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
	assert.Check(t, invoked)
}

func TestReportTimedMetricWithStatus(t *testing.T) {
	metric := NewDynamicHistogram("foo", "Foo metric")
	var invoked bool
	f := func() {
		invoked = true
	}
	ReportTimedMetricWithStatus(metric, f, "OK", map[string]string{})
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
	assert.Check(t, invoked)
}

func TestReportTimedMetricWithObject(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	metric := NewDynamicHistogram("foo", "Foo metric")

	var invoked bool
	f := func() {
		invoked = true
	}
	object := mock_metrics.NewMockObject(ctrl)
	object.EXPECT().GetType().Return("AUTHZ_X")
	object.EXPECT().GetName().Return("foo")

	object.EXPECT().MetricsEnabled().Return(true)
	ReportTimedMetricWithObject(metric, f, object, map[string]string{"type": "AUTHZ_X", "name": "foo"})
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
	assert.Check(t, invoked)

	invoked = false
	object.EXPECT().MetricsEnabled().Return(false)
	ReportTimedMetricWithObject(metric, f, object, map[string]string{})
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
	assert.Check(t, invoked)
}

func TestDeepMetricsEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	metric := NewDynamicCounter("foo", "Foo metric")

	object := mock_metrics.NewMockObject(ctrl)
	object.EXPECT().GetType().Return("AUTHZ_X").AnyTimes()
	object.EXPECT().GetName().Return("foo").AnyTimes()

	DeepMetricsEnabled = true
	object.EXPECT().MetricsEnabled().Return(false)
	ReportMetricWithObject(metric, object, map[string]string{"type": "AUTHZ_X", "name": "foo"})
	assert.Equal(t, 1, testutil.CollectAndCount(metric))

	DeepMetricsEnabled = false
	object.EXPECT().MetricsEnabled().Return(false)
	ReportMetricWithObject(metric, object, map[string]string{})
	assert.Equal(t, 1, testutil.CollectAndCount(metric)) // does not change
}

func TestDynamicCounterWithMultipleLabelSets(t *testing.T) {
	metric := NewDynamicCounter("foo", "Foo metric")

	labels1 := map[string]string{"key": "value"}
	labels2 := map[string]string{"key1": "value1", "key2": "value2"}

	// Increment with labels1
	metric.Inc(labels1)
	metric.Inc(labels2)
	metric.Inc(labels1)

	// Helper to find the counter entry by exact labels
	findCounter := func(labelSet map[string]string) prometheus.Counter {
		for _, entry := range metric.counters[hashLabels(labelSet)] {
			if maps.Equal(entry.labels, labelSet) {
				return entry.counter
			}
		}
		return nil
	}

	// Assert labels1 counter is 2
	c1 := findCounter(labels1)
	if c1 == nil {
		t.Fatal("counter for labels1 not found")
	}
	if got := testutil.ToFloat64(c1); got != 2 {
		t.Errorf("expected 2, got %v", got)
	}

	// Assert labels2 counter is 1
	c2 := findCounter(labels2)
	if c2 == nil {
		t.Fatal("counter for labels2 not found")
	}
	if got := testutil.ToFloat64(c2); got != 1 {
		t.Errorf("expected 1, got %v", got)
	}
}

func TestDynamicHistogramWithMultipleLabelSets(t *testing.T) {
	metric := NewDynamicHistogram("foo", "Foo metric")

	labels1 := map[string]string{"key": "value"}
	labels2 := map[string]string{"key1": "value1", "key2": "value2"}

	// Observe values
	metric.Observe(labels1, 1.0)
	metric.Observe(labels2, 1.0)
	metric.Observe(labels1, 1.0)

	// Helper to find histogram by exact labels
	findHistogram := func(labelSet map[string]string) prometheus.Histogram {
		for _, entry := range metric.histograms[hashLabels(labelSet)] {
			if maps.Equal(entry.labels, labelSet) {
				return entry.histogram
			}
		}
		return nil
	}

	h1 := findHistogram(labels1)
	if h1 == nil {
		t.Fatal("histogram for labels1 not found")
	}

	h2 := findHistogram(labels2)
	if h2 == nil {
		t.Fatal("histogram for labels2 not found")
	}

	// Check sums (sample_sum) and counts
	metric1 := testutil.CollectAndCount(h1)
	if metric1 != 1 {
		t.Errorf("expected 1 sample for labels1 histogram, got %v", metric1)
	}

	metric2 := testutil.CollectAndCount(h2)
	if metric2 != 1 {
		t.Errorf("expected 1 sample for labels2 histogram, got %v", metric2)
	}
}
