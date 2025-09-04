package metrics

import (
	"testing"

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
	//assert.Equal(t, float64(0), testutil.ToFloat64(metric.WithLabelValues("NOK")))
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
