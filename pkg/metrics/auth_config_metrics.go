package metrics

import "github.com/prometheus/client_golang/prometheus"

func NewAuthConfigCounterMetric(name, help string, extraLabels ...string) *prometheus.CounterVec {
	return NewCounterMetric(name, help, buildAuthConfigLabels(extraLabels...)...)
}

func NewAuthConfigDurationMetric(name, help string, extraLabels ...string) *prometheus.HistogramVec {
	return NewDurationMetric(name, help, buildAuthConfigLabels(extraLabels...)...)
}

func buildAuthConfigLabels(extraLabels ...string) []string {
	labels := []string{"namespace", "authconfig"}
	labels = append(labels, extraLabels...)

	// Add custom label names if custom metrics are enabled
	if CustomMetricsEnabled {
		for labelName := range CustomMetricLabels {
			labels = append(labels, labelName)
		}
	}

	return labels
}
