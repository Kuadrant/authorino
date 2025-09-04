package metrics

import (
	"fmt"
	"maps"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	DeepMetricsEnabled = false
)

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

func ReportMetric(metric *DynamicCounter, labels map[string]string) {
	metric.Inc(labels)
}

func ReportMetricWithStatus(metric *DynamicCounter, status string, labels map[string]string) {
	labels["status"] = status

	ReportMetric(metric, labels)
}

func ReportMetricWithObject(metric *DynamicCounter, obj Object, labels map[string]string) {
	if extendedLabels, err := extendLabelValuesWithObject(obj, labels); err == nil {
		ReportMetric(metric, extendedLabels)
	}
}

func ReportTimedMetric(metric *DynamicHistogram, f func(), labels map[string]string) {
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(value float64) {
		metric.Observe(labels, value)
	}))

	defer func() {
		timer.ObserveDuration()
	}()

	f()
}

func ReportTimedMetricWithStatus(metric *DynamicHistogram, f func(), status string, labels map[string]string) {
	labels["status"] = status
	ReportTimedMetric(metric, f, labels)
}

func ReportTimedMetricWithObject(metric *DynamicHistogram, f func(), obj Object, labels map[string]string) {
	if extendedLabels, err := extendLabelValuesWithObject(obj, labels); err == nil {
		ReportTimedMetric(metric, f, extendedLabels)
	} else {
		f()
	}
}

func extendLabelValuesWithObject(obj Object, baseLabels map[string]string) (map[string]string, error) {
	if obj == nil || (!obj.MetricsEnabled() && !DeepMetricsEnabled) {
		return nil, fmt.Errorf("metrics are disabled")
	}

	labels := maps.Clone(baseLabels)
	labels["evaluator_type"] = obj.GetType()
	labels["evaluator_name"] = obj.GetName()

	return labels, nil
}
