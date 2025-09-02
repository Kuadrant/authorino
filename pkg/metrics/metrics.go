package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/kuadrant/authorino/pkg/expressions/cel"
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

// buildFinalLabels constructs the final label values by combining base labels with custom labels
func buildFinalLabels(authJSON string, baseLabels ...string) []string {
	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)

	// If custom metrics are enabled, append custom label values
	if CustomMetricsEnabled && len(CustomMetricLabels) > 0 && authJSON != "" {
		if customLabels, err := EvaluateCustomLabels(authJSON); err == nil {
			// Append custom label values in consistent order
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
	}

	return labels
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

func ReportMetric(metric *prometheus.CounterVec, authJSON string, labels ...string) {
	finalLabels := buildFinalLabels(authJSON, labels...)
	metric.WithLabelValues(finalLabels...).Inc()
}

func ReportMetricWithStatus(metric *prometheus.CounterVec, status string, authJSON string, labels ...string) {
	baseLabels := extendLabelValuesWithStatus(status, labels...)
	ReportMetric(metric, authJSON, baseLabels...)
}

func ReportMetricWithObject(metric *prometheus.CounterVec, obj Object, authJSON string, labels ...string) {
	if extendedLabels, err := extendLabelValuesWithObject(obj, labels...); err == nil {
		ReportMetric(metric, authJSON, extendedLabels...)
	}
}

func ReportTimedMetric(metric *prometheus.HistogramVec, f func(), authJSON string, labels ...string) {
	finalLabels := buildFinalLabels(authJSON, labels...)

	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(value float64) {
		metric.WithLabelValues(finalLabels...).Observe(value)
	}))

	defer func() {
		timer.ObserveDuration()
	}()

	f()
}

func ReportTimedMetricWithStatus(metric *prometheus.HistogramVec, f func(), status string, authJSON string, labels ...string) {
	baseLabels := extendLabelValuesWithStatus(status, labels...)
	ReportTimedMetric(metric, f, authJSON, baseLabels...)
}

func ReportTimedMetricWithObject(metric *prometheus.HistogramVec, f func(), obj Object, authJSON string, labels ...string) {
	if extendedLabels, err := extendLabelValuesWithObject(obj, labels...); err == nil {
		ReportTimedMetric(metric, f, authJSON, extendedLabels...)
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
