package metrics

import "github.com/prometheus/client_golang/prometheus"

func NewAuthConfigCounterMetric(name, help string, extraLabels ...string) *prometheus.CounterVec {
	return NewCounterMetric(name, help, extendedAuthConfigMetricLabels(extraLabels...)...)
}

func NewAuthConfigDurationMetric(name, help string, extraLabels ...string) *prometheus.HistogramVec {
	return NewDurationMetric(name, help, extendedAuthConfigMetricLabels(extraLabels...)...)
}

func extendedAuthConfigMetricLabels(extraLabels ...string) []string {
	labels := []string{"namespace", "authconfig"}
	labels = append(labels, extraLabels[:]...)
	return labels
}
