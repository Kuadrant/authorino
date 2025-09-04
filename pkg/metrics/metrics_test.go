package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"gotest.tools/assert"
)

func TestReportMetric(t *testing.T) {
	metric := NewDynamicCounter("foo", "Foo metric")
	ReportMetric(metric, map[string]string{})
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
}

//func TestReportMetricWithStatus(t *testing.T) {
//	metric := NewCounterMetric("foo", "Foo metric", "status")
//	ReportMetricWithStatus(metric, "OK", "")
//	assert.Equal(t, float64(1), testutil.ToFloat64(metric.WithLabelValues("OK")))
//	assert.Equal(t, float64(0), testutil.ToFloat64(metric.WithLabelValues("NOK")))
//}
//
//func TestReportMetricWithObject(t *testing.T) {
//	ctrl := gomock.NewController(t)
//	defer ctrl.Finish()
//
//	metric := NewCounterMetric("foo", "Foo metric", "type", "name")
//
//	object := mock_metrics.NewMockObject(ctrl)
//	object.EXPECT().GetType().Return("AUTHZ_X")
//	object.EXPECT().GetName().Return("foo")
//
//	object.EXPECT().MetricsEnabled().Return(true)
//	ReportMetricWithObject(metric, object, "")
//	assert.Equal(t, float64(1), testutil.ToFloat64(metric))
//	assert.Equal(t, float64(1), testutil.ToFloat64(metric.WithLabelValues("AUTHZ_X", "foo")))
//
//	object.EXPECT().MetricsEnabled().Return(false)
//	ReportMetricWithObject(metric, object, "")
//	assert.Equal(t, float64(1), testutil.ToFloat64(metric))
//
//	ReportMetricWithObject(metric, nil, "")
//	assert.Equal(t, float64(1), testutil.ToFloat64(metric))
//}
//
//func TestReportTimedMetric(t *testing.T) {
//	metric := NewDurationMetric("foo", "Foo metric")
//	var invoked bool
//	f := func() {
//		invoked = true
//	}
//	ReportTimedMetric(metric, f, "")
//	assert.Equal(t, 1, testutil.CollectAndCount(metric))
//	assert.Check(t, invoked)
//}
//
//func TestReportTimedMetricWithStatus(t *testing.T) {
//	metric := NewDurationMetric("foo", "Foo metric", "status")
//	var invoked bool
//	f := func() {
//		invoked = true
//	}
//	ReportTimedMetricWithStatus(metric, f, "OK", "")
//	assert.Equal(t, 1, testutil.CollectAndCount(metric))
//	assert.Check(t, invoked)
//}
//
//func TestReportTimedMetricWithObject(t *testing.T) {
//	ctrl := gomock.NewController(t)
//	defer ctrl.Finish()
//
//	metric := NewDurationMetric("foo", "Foo metric", "type", "name")
//
//	var invoked bool
//	f := func() {
//		invoked = true
//	}
//	object := mock_metrics.NewMockObject(ctrl)
//	object.EXPECT().GetType().Return("AUTHZ_X")
//	object.EXPECT().GetName().Return("foo")
//
//	object.EXPECT().MetricsEnabled().Return(true)
//	ReportTimedMetricWithObject(metric, f, object, "")
//	assert.Equal(t, 1, testutil.CollectAndCount(metric))
//	assert.Check(t, invoked)
//
//	invoked = false
//	object.EXPECT().MetricsEnabled().Return(false)
//	ReportTimedMetricWithObject(metric, f, object, "")
//	assert.Equal(t, 1, testutil.CollectAndCount(metric))
//	assert.Check(t, invoked)
//}
//
//func TestDeepMetricsEnabled(t *testing.T) {
//	ctrl := gomock.NewController(t)
//	defer ctrl.Finish()
//
//	metric := NewCounterMetric("foo", "Foo metric", "type", "name")
//
//	object := mock_metrics.NewMockObject(ctrl)
//	object.EXPECT().GetType().Return("AUTHZ_X").AnyTimes()
//	object.EXPECT().GetName().Return("foo").AnyTimes()
//
//	DeepMetricsEnabled = true
//	object.EXPECT().MetricsEnabled().Return(false)
//	ReportMetricWithObject(metric, object, "")
//	assert.Equal(t, 1, testutil.CollectAndCount(metric))
//
//	DeepMetricsEnabled = false
//	object.EXPECT().MetricsEnabled().Return(false)
//	ReportMetricWithObject(metric, object, "")
//	assert.Equal(t, 1, testutil.CollectAndCount(metric)) // does not change
//}
