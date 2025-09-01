package metrics

import (
	"fmt"

	"github.com/kuadrant/authorino/pkg/expressions/cel"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	DeepMetricsEnabled   = false
	CustomMetricLabels   map[string]*cel.Expression
	CustomMetricsEnabled = false
)

type Object interface {
	GetType() string
	GetName() string
	MetricsEnabled() bool
}

func Register(metrics ...prometheus.Collector) {
	prometheus.MustRegister(metrics...)
}

func InitCustomMetricLabels(labelsConfig map[string]string) error {
	CustomMetricLabels = make(map[string]*cel.Expression)

	for labelName, celExpr := range labelsConfig {
		if expr, err := cel.NewExpression(celExpr); err != nil {
			return fmt.Errorf("failed to compile CEL expression for label %s: %w", labelName, err)
		} else {
			CustomMetricLabels[labelName] = expr
		}
	}

	CustomMetricsEnabled = len(CustomMetricLabels) > 0
	return nil
}

func EvaluateCustomLabels(authJSON string) (map[string]string, error) {
	customLabels := make(map[string]string)

	for labelName, expr := range CustomMetricLabels {
		if value, err := expr.ResolveFor(authJSON); err != nil {
			// Log error but don't fail the whole metric - use empty value
			customLabels[labelName] = ""
		} else if strValue, ok := value.(string); ok {
			customLabels[labelName] = strValue
		} else {
			customLabels[labelName] = fmt.Sprintf("%v", value)
		}
	}

	return customLabels, nil
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

func ReportMetricWithCustomLabels(metric *prometheus.CounterVec, authJSON string, baseLabels ...string) {
	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)

	if customLabels, err := EvaluateCustomLabels(authJSON); err == nil {
		// Append custom label values in the same order as they appear in CustomMetricLabels
		for labelName := range CustomMetricLabels {
			if value, exists := customLabels[labelName]; exists {
				labels = append(labels, value)
			} else {
				labels = append(labels, "")
			}
		}
	} else {
		// Append empty values for all custom labels if evaluation fails
		for range CustomMetricLabels {
			labels = append(labels, "")
		}
	}

	metric.WithLabelValues(labels...).Inc()
}

func ReportTimedMetricWithCustomLabels(metric *prometheus.HistogramVec, f func(), authJSON string, baseLabels ...string) {
	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)

	if customLabels, err := EvaluateCustomLabels(authJSON); err == nil {
		for labelName := range CustomMetricLabels {
			if value, exists := customLabels[labelName]; exists {
				labels = append(labels, value)
			} else {
				labels = append(labels, "")
			}
		}
	} else {
		for range CustomMetricLabels {
			labels = append(labels, "")
		}
	}

	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(value float64) {
		metric.WithLabelValues(labels...).Observe(value)
	}))

	defer timer.ObserveDuration()
	f()
}

func ReportMetricWithStatusAndCustomLabels(metric *prometheus.CounterVec, status string, authJSON string, baseLabels ...string) {
	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)
	labels = append(labels, status) // Add status to base labels

	if customLabels, err := EvaluateCustomLabels(authJSON); err == nil {
		for labelName := range CustomMetricLabels {
			if value, exists := customLabels[labelName]; exists {
				labels = append(labels, value)
			} else {
				labels = append(labels, "")
			}
		}
	} else {
		for range CustomMetricLabels {
			labels = append(labels, "")
		}
	}

	metric.WithLabelValues(labels...).Inc()
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
