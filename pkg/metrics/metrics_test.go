package metrics

import (
	"context"
	"testing"

	"github.com/kuadrant/authorino/pkg/common"
	mock_common "github.com/kuadrant/authorino/pkg/common/mocks"

	"github.com/golang/mock/gomock"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"gotest.tools/assert"
)

type testMetricsSimpleEvaluator struct{}

func (e *testMetricsSimpleEvaluator) Call(_ common.AuthPipeline, _ context.Context) (interface{}, error) {
	return nil, nil
}

type testMetricsMonitorableEvaluator struct {
	monitorable common.Monitorable
}

func (e *testMetricsMonitorableEvaluator) Call(_ common.AuthPipeline, _ context.Context) (interface{}, error) {
	return nil, nil
}

func (e *testMetricsMonitorableEvaluator) GetType() string {
	return e.monitorable.GetType()
}

func (e *testMetricsMonitorableEvaluator) GetName() string {
	return e.monitorable.GetName()
}

func (e *testMetricsMonitorableEvaluator) Measured() bool {
	return e.monitorable.Measured()
}

func TestReportMetric(t *testing.T) {
	metric := NewCounterMetric("foo", "Foo metric")
	ReportMetric(metric)
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
}

func TestReportMetricWithStatus(t *testing.T) {
	metric := NewCounterMetric("foo", "Foo metric", "status")
	ReportMetricWithStatus(metric, "OK")
	assert.Equal(t, float64(1), testutil.ToFloat64(metric.WithLabelValues("OK")))
	assert.Equal(t, float64(0), testutil.ToFloat64(metric.WithLabelValues("NOK")))
}

func TestReportMetricWithEvaluator(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	metric := NewCounterMetric("foo", "Foo metric", "type", "name")

	// evaluator is not a monitorable
	ReportMetricWithEvaluator(metric, &testMetricsSimpleEvaluator{})
	assert.Equal(t, 0, testutil.CollectAndCount(metric))

	monitorable := mock_common.NewMockMonitorable(ctrl)
	monitorable.EXPECT().GetType().Return("AUTHZ_X")
	monitorable.EXPECT().GetName().Return("foo")
	evaluator := &testMetricsMonitorableEvaluator{monitorable: monitorable}

	// metrics are disabled for the evaluator
	monitorable.EXPECT().Measured().Return(false)
	ReportMetricWithEvaluator(metric, evaluator)
	assert.Equal(t, 0, testutil.CollectAndCount(metric))

	// metrics are enabled for the evaluator
	monitorable.EXPECT().Measured().Return(true)
	ReportMetricWithEvaluator(metric, evaluator)
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
	assert.Equal(t, 1, testutil.CollectAndCount(metric.WithLabelValues("AUTHZ_X", "foo")))
}

func TestReportTimedMetric(t *testing.T) {
	metric := NewDurationMetric("foo", "Foo metric")
	var invoked bool
	f := func() {
		invoked = true
	}
	ReportTimedMetric(metric, f)
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
	assert.Check(t, invoked)
}

func TestReportTimedMetricWithStatus(t *testing.T) {
	metric := NewDurationMetric("foo", "Foo metric", "status")
	var invoked bool
	f := func() {
		invoked = true
	}
	ReportTimedMetricWithStatus(metric, f, "OK")
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
	assert.Check(t, invoked)
}

func TestReportTimedMetricWithEvaluator(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	metric := NewDurationMetric("foo", "Foo metric", "type", "name")

	var invoked bool
	f := func() {
		invoked = true
	}

	// evaluator is not a monitorable
	ReportTimedMetricWithEvaluator(metric, f, &testMetricsSimpleEvaluator{})
	assert.Equal(t, 0, testutil.CollectAndCount(metric))
	assert.Check(t, invoked)

	monitorable := mock_common.NewMockMonitorable(ctrl)
	monitorable.EXPECT().GetType().Return("AUTHZ_X")
	monitorable.EXPECT().GetName().Return("foo")
	evaluator := &testMetricsMonitorableEvaluator{monitorable: monitorable}

	// metrics are disabled for the evaluator
	invoked = false
	monitorable.EXPECT().Measured().Return(false)
	ReportTimedMetricWithEvaluator(metric, f, evaluator)
	assert.Equal(t, 0, testutil.CollectAndCount(metric))
	assert.Check(t, invoked)

	// metrics are enabled for the evaluator
	invoked = false
	monitorable.EXPECT().Measured().Return(true)
	ReportTimedMetricWithEvaluator(metric, f, evaluator)
	assert.Equal(t, 1, testutil.CollectAndCount(metric))
	assert.Check(t, invoked)
}
