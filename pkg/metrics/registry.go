package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// A registry that can create dynamic metrics that allow different label sets
type MetricRegistry struct {
	counters   map[string]*DynamicCounter
	histograms map[string]*DynamicHistogram
}

func NewMetricRegistry() *MetricRegistry {
	return &MetricRegistry{
		counters:   make(map[string]*DynamicCounter),
		histograms: make(map[string]*DynamicHistogram),
	}
}

// Dynamic counters

func (r *MetricRegistry) GetOrCreateDynamicCounter(name, help string) *DynamicCounter {
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := NewDynamicCounter(name, help)
	prometheus.MustRegister(c)
	r.counters[name] = c
	return c
}

// Dynamic histograms

func (r *MetricRegistry) GetOrCreateDynamicHistogram(name, help string) *DynamicHistogram {
	if h, ok := r.histograms[name]; ok {
		return h
	}
	h := NewDynamicHistogram(name, help)
	prometheus.MustRegister(h)
	r.histograms[name] = h
	return h
}

// -----------------------------------------------------------------------------
// Authconfig metrics
// -----------------------------------------------------------------------------

func (r *MetricRegistry) GetAuthServerAuthConfigTotalMetric() *DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_authconfig_total",
		"Total number of authconfigs enforced by the auth server, partitioned by authconfig.",
	)
}

func (r *MetricRegistry) GetAuthServerAuthConfigResponseStatusMetric() *DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_authconfig_response_status",
		"Response status of authconfigs sent by the auth server, partitioned by authconfig.",
	)
}

func (r *MetricRegistry) GetAuthServerAuthConfigDurationMetric() *DynamicHistogram {
	return r.GetOrCreateDynamicHistogram(
		"auth_server_authconfig_duration_seconds",
		"Response latency of authconfig enforced by the auth server (in seconds).",
	)
}

// -----------------------------------------------------------------------------
// Evaluator metrics
// -----------------------------------------------------------------------------

func (r *MetricRegistry) GetAuthServerEvaluatorTotalMetric() *DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_evaluator_total",
		"Total number of evaluations of individual authconfig rule performed by the auth server.",
	)
}

func (r *MetricRegistry) GetAuthServerEvaluatorCancelledMetric() *DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_evaluator_cancelled",
		"Number of evaluations of individual authconfig rule cancelled by the auth server.",
	)
}

func (r *MetricRegistry) GetAuthServerEvaluatorIgnoredMetric() *DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_evaluator_ignored",
		"Number of evaluations of individual authconfig rule ignored by the auth server.",
	)
}

func (r *MetricRegistry) GetAuthServerEvaluatorDeniedMetric() *DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_evaluator_denied",
		"Number of denials from individual authconfig rule evaluated by the auth server.",
	)
}

func (r *MetricRegistry) GetAuthServerEvaluatorDurationMetric() *DynamicHistogram {
	return r.GetOrCreateDynamicHistogram(
		"auth_server_evaluator_duration_seconds",
		"Response latency of individual authconfig rule evaluated by the auth server (in seconds).",
	)
}

var Registry = NewMetricRegistry()
