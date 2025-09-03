package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// A registry that can create new metrics with different label sets
type MetricRegistry struct {
	metrics map[string]prometheus.Collector
}

func NewMetricRegistry() *MetricRegistry {
	return &MetricRegistry{
		metrics: make(map[string]prometheus.Collector),
	}
}

func (r *MetricRegistry) GetOrCreateCounterVec(name, help string, labels []string) *prometheus.CounterVec {
	key := fmt.Sprintf("%s|%v", name, labels) // unique key based on name + label set
	if m, ok := r.metrics[key]; ok {
		return m.(*prometheus.CounterVec)
	}
	m := NewCounterMetric(name, help, labels...)
	r.metrics[key] = m
	return m
}

func (r *MetricRegistry) GetAuthServerAuthConfigTotalMetric(labels []string) *prometheus.CounterVec {
	return r.GetOrCreateCounterVec("auth_server_authconfig_total", "Total number of authconfigs enforced by the auth server, partitioned by authconfig.", labels)
}

var Registry = NewMetricRegistry()
