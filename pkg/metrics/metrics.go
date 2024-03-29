package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

var DeepMetricsEnabled = false

type Object interface {
	GetType() string
	GetName() string
	MetricsEnabled() bool
}

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

func ReportMetric(metric *prometheus.CounterVec, labels ...string) {
	metric.WithLabelValues(labels...).Inc()
}

func ReportMetricWithStatus(metric *prometheus.CounterVec, status string, labels ...string) {
	ReportMetric(metric, extendLabelValuesWithStatus(status, labels...)...)
}

func ReportMetricWithObject(metric *prometheus.CounterVec, obj Object, labels ...string) {
	if labels, err := extendLabelValuesWithObject(obj, labels...); err == nil {
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

func ReportTimedMetricWithObject(metric *prometheus.HistogramVec, f func(), obj Object, labels ...string) {
	if labels, err := extendLabelValuesWithObject(obj, labels...); err == nil {
		ReportTimedMetric(metric, f, labels...)
	} else {
		f()
	}
}

func extendLabelValuesWithStatus(status string, baseLabels ...string) []string {
	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)
	labels = append(labels, status)
	return labels
}

func extendLabelValuesWithObject(obj Object, baseLabels ...string) ([]string, error) {
	if obj == nil || (!obj.MetricsEnabled() && !DeepMetricsEnabled) {
		return nil, fmt.Errorf("metrics are disabled")
	}

	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)
	labels = append(labels, obj.GetType(), obj.GetName())
	return labels, nil
}
