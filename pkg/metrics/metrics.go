package metrics

import (
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"

	"github.com/prometheus/client_golang/prometheus"
)

func Register(metrics ...prometheus.Collector) {
	prometheus.MustRegister(metrics...)
}

func NewCounterMetric(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: name,
			Help: help,
		},
		labels,
	)
}

func NewAuthConfigCounterMetric(name, help string, extraLabels ...string) *prometheus.CounterVec {
	return NewCounterMetric(name, help, extendedAuthConfigMetricLabels(extraLabels...)...)
}

func NewDurationMetric(name, help string, labels ...string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    name,
			Help:    help,
			Buckets: prometheus.LinearBuckets(0.001, 0.05, 20),
		},
		labels,
	)
}

func NewAuthConfigDurationMetric(name, help string, extraLabels ...string) *prometheus.HistogramVec {
	return NewDurationMetric(name, help, extendedAuthConfigMetricLabels(extraLabels...)...)
}

func ReportMetric(metric *prometheus.CounterVec, labels ...string) {
	metric.WithLabelValues(labels...).Inc()
}

func ReportMetricWithStatus(metric *prometheus.CounterVec, status string, labels ...string) {
	ReportMetric(metric, extendLabelValuesWithStatus(status, labels...)...)
}

func ReportMetricWithEvaluator(metric *prometheus.CounterVec, evaluator common.AuthConfigEvaluator, labels ...string) {
	if labels, err := extendLabelValuesWithEvaluator(evaluator, labels...); err == nil {
		ReportMetric(metric, labels...)
	}
}

func ReportTimedMetric(metric *prometheus.HistogramVec, f func(), labels ...string) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(value float64) {
		metric.WithLabelValues(labels...).Observe(value)
	}))

	defer func() {
		timer.ObserveDuration()
	}()

	f()
}

func ReportTimedMetricWithStatus(metric *prometheus.HistogramVec, f func(), status string, labels ...string) {
	ReportTimedMetric(metric, f, extendLabelValuesWithStatus(status, labels...)...)
}

func ReportTimedMetricWithEvaluator(metric *prometheus.HistogramVec, f func(), evaluator common.AuthConfigEvaluator, labels ...string) {
	if labels, err := extendLabelValuesWithEvaluator(evaluator, labels...); err == nil {
		ReportTimedMetric(metric, f, labels...)
	} else {
		f()
	}
}

func extendedAuthConfigMetricLabels(extraLabels ...string) []string {
	labels := []string{"namespace", "authconfig"}
	labels = append(labels, extraLabels[:]...)
	return labels
}

func extendLabelValuesWithStatus(status string, baseLabels ...string) []string {
	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)
	labels = append(labels, status)
	return labels
}

func extendLabelValuesWithEvaluator(evaluator common.AuthConfigEvaluator, baseLabels ...string) ([]string, error) {
	if ev, ok := evaluator.(common.Monitorable); ok {
		if !ev.Measured() {
			return nil, fmt.Errorf("metrics are disabled for the evaluator")
		}

		labels := make([]string, len(baseLabels))
		copy(labels, baseLabels)
		labels = append(labels, ev.GetType(), ev.GetName())
		return labels, nil
	} else {
		return baseLabels, fmt.Errorf("cannot cast evaluator to monitorable")
	}
}
