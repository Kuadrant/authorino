package service

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/kuadrant/authorino/pkg/metrics"
)

// A registry that can create dynamic metrics that allow different label sets.
type MetricRegistry struct {
	mu         sync.RWMutex
	counters   map[string]*metrics.DynamicCounter
	histograms map[string]*metrics.DynamicHistogram
}

func NewMetricRegistry() *MetricRegistry {
	return &MetricRegistry{
		counters:   make(map[string]*metrics.DynamicCounter),
		histograms: make(map[string]*metrics.DynamicHistogram),
	}
}

// Dynamic counters

func (r *MetricRegistry) GetOrCreateDynamicCounter(name, help string) *metrics.DynamicCounter {
	r.mu.RLock()
	if c, ok := r.counters[name]; ok {
		r.mu.RUnlock()
		return c
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	if c, ok := r.counters[name]; ok {
		return c
	}

	c := metrics.NewDynamicCounter(name, help)
	prometheus.MustRegister(c)
	r.counters[name] = c
	return c
}

// -----------------------------------------------------------------------------
// Dynamic histograms
// -----------------------------------------------------------------------------

func (r *MetricRegistry) GetOrCreateDynamicHistogram(name, help string) *metrics.DynamicHistogram {
	r.mu.RLock()
	if h, ok := r.histograms[name]; ok {
		r.mu.RUnlock()
		return h
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	if h, ok := r.histograms[name]; ok {
		return h
	}

	h := metrics.NewDynamicHistogram(name, help)
	prometheus.MustRegister(h)
	r.histograms[name] = h
	return h
}

// -----------------------------------------------------------------------------
// Authconfig metrics
// -----------------------------------------------------------------------------

func (r *MetricRegistry) GetAuthServerAuthConfigTotalMetric() *metrics.DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_authconfig_total",
		"Total number of authconfigs enforced by the auth server, partitioned by authconfig.",
	)
}

func (r *MetricRegistry) GetAuthServerAuthConfigResponseStatusMetric() *metrics.DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_authconfig_response_status",
		"Response status of authconfigs sent by the auth server, partitioned by authconfig.",
	)
}

func (r *MetricRegistry) GetAuthServerAuthConfigDurationMetric() *metrics.DynamicHistogram {
	return r.GetOrCreateDynamicHistogram(
		"auth_server_authconfig_duration_seconds",
		"Response latency of authconfig enforced by the auth server (in seconds).",
	)
}

// -----------------------------------------------------------------------------
// Evaluator metrics
// -----------------------------------------------------------------------------

func (r *MetricRegistry) GetAuthServerEvaluatorTotalMetric() *metrics.DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_evaluator_total",
		"Total number of evaluations of individual authconfig rule performed by the auth server.",
	)
}

func (r *MetricRegistry) GetAuthServerEvaluatorCancelledMetric() *metrics.DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_evaluator_cancelled",
		"Number of evaluations of individual authconfig rule cancelled by the auth server.",
	)
}

func (r *MetricRegistry) GetAuthServerEvaluatorIgnoredMetric() *metrics.DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_evaluator_ignored",
		"Number of evaluations of individual authconfig rule ignored by the auth server.",
	)
}

func (r *MetricRegistry) GetAuthServerEvaluatorDeniedMetric() *metrics.DynamicCounter {
	return r.GetOrCreateDynamicCounter(
		"auth_server_evaluator_denied",
		"Number of denials from individual authconfig rule evaluated by the auth server.",
	)
}

func (r *MetricRegistry) GetAuthServerEvaluatorDurationMetric() *metrics.DynamicHistogram {
	return r.GetOrCreateDynamicHistogram(
		"auth_server_evaluator_duration_seconds",
		"Response latency of individual authconfig rule evaluated by the auth server (in seconds).",
	)
}

var Registry = NewMetricRegistry()
