package metrics

import "github.com/prometheus/client_golang/prometheus"

func NewAuthConfigCounterMetric(name, help string, extraLabels ...string) *prometheus.CounterVec {
	if CustomMetricsEnabled {
		return NewCounterMetric(name, help, extendedAuthConfigMetricLabelsWithCustom(extraLabels...)...)
	}
	return NewCounterMetric(name, help, extendedAuthConfigMetricLabels(extraLabels...)...)
}

func NewAuthConfigDurationMetric(name, help string, extraLabels ...string) *prometheus.HistogramVec {
	if CustomMetricsEnabled {
		return NewDurationMetric(name, help, extendedAuthConfigMetricLabelsWithCustom(extraLabels...)...)
	}
	return NewDurationMetric(name, help, extendedAuthConfigMetricLabels(extraLabels...)...)
}

func extendedAuthConfigMetricLabels(extraLabels ...string) []string {
	labels := []string{"namespace", "authconfig"}
	labels = append(labels, extraLabels[:]...)
	return labels
}

func extendedAuthConfigMetricLabelsWithCustom(extraLabels ...string) []string {
	labels := []string{"namespace", "authconfig"}
	labels = append(labels, extraLabels[:]...)

	// Add custom label names in a consistent order
	for labelName := range CustomMetricLabels {
		labels = append(labels, labelName)
	}

	return labels
}
