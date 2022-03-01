package service

import (
	"fmt"

	"github.com/kuadrant/authorino/pkg/common"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// auth server
	authConfigMetricLabels          = []string{"namespace", "authconfig"}
	authConfigEvaluatorMetricLabels = []string{"evaluator_type", "evaluator_name"}

	authServerEvaluatorTotalMetric           = newAuthConfigCounterMetric("auth_server_evaluator_total", "Total number of evaluations of individual authconfig rule performed by the auth server.", authConfigEvaluatorMetricLabels...)
	authServerEvaluatorCancelledMetric       = newAuthConfigCounterMetric("auth_server_evaluator_cancelled", "Number of evaluations of individual authconfig rule cancelled by the auth server.", authConfigEvaluatorMetricLabels...)
	authServerEvaluatorIgnoredMetric         = newAuthConfigCounterMetric("auth_server_evaluator_ignored", "Number of evaluations of individual authconfig rule ignored by the auth server.", authConfigEvaluatorMetricLabels...)
	authServerEvaluatorDeniedMetric          = newAuthConfigCounterMetric("auth_server_evaluator_denied", "Number of denials from individual authconfig rule evaluated by the auth server.", authConfigEvaluatorMetricLabels...)
	authServerAuthConfigTotalMetric          = newAuthConfigCounterMetric("auth_server_authconfig_total", "Total number of authconfigs enforced by the auth server, partitioned by authconfig.")
	authServerAuthConfigResponseStatusMetric = newAuthConfigCounterMetric("auth_server_authconfig_response_status", "Response status of authconfigs sent by the auth server, partitioned by authconfig.", "status")
	authServerResponseStatusMetric           = newAuthCounterMetric("auth_server_response_status", "Response status of authconfigs sent by the auth server.", "status")

	authServerEvaluatorDurationMetric = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_server_evaluator_duration_seconds",
			Help:    "Response latency of individual authconfig rule evaluated by the auth server (in seconds).",
			Buckets: prometheus.LinearBuckets(0.001, 0.05, 20),
		},
		extendedAuthConfigMetricLabels(authConfigEvaluatorMetricLabels...),
	)

	authServerAuthConfigDurationMetric = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_server_authconfig_duration_seconds",
			Help:    "Response latency of authconfig enforced by the auth server (in seconds).",
			Buckets: prometheus.LinearBuckets(0.001, 0.05, 20),
		},
		authConfigMetricLabels,
	)

	// oidc server
	oidcServerTotalRequestsMetric  = newAuthConfigCounterMetric("oidc_server_requests_total", "Number of get requests received on the OIDC (Festival Wristband) server.", "wristband", "path")
	oidcServerResponseStatusMetric = newAuthCounterMetric("oidc_server_response_status", "Status of HTTP response sent by the OIDC (Festival Wristband) server.", "status")
)

func init() {
	prometheus.MustRegister(authServerEvaluatorTotalMetric)
	prometheus.MustRegister(authServerEvaluatorCancelledMetric)
	prometheus.MustRegister(authServerEvaluatorIgnoredMetric)
	prometheus.MustRegister(authServerEvaluatorDeniedMetric)
	prometheus.MustRegister(authServerEvaluatorDurationMetric)
	prometheus.MustRegister(authServerAuthConfigTotalMetric)
	prometheus.MustRegister(authServerAuthConfigResponseStatusMetric)
	prometheus.MustRegister(authServerAuthConfigDurationMetric)
	prometheus.MustRegister(authServerResponseStatusMetric)
	prometheus.MustRegister(oidcServerTotalRequestsMetric)
	prometheus.MustRegister(oidcServerResponseStatusMetric)
}

func newAuthCounterMetric(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: name,
			Help: help,
		},
		labels,
	)
}

func newAuthConfigCounterMetric(name, help string, extraLabels ...string) *prometheus.CounterVec {
	return newAuthCounterMetric(name, help, extendedAuthConfigMetricLabels(extraLabels...)...)
}

func extendedAuthConfigMetricLabels(extraLabels ...string) []string {
	labels := make([]string, len(authConfigMetricLabels))
	copy(labels, authConfigMetricLabels)
	labels = append(labels, extraLabels[:]...)
	return labels
}

func extendLabelValuesWithStatus(status string, baseLabels ...string) []string {
	labels := make([]string, len(baseLabels))
	copy(labels, baseLabels)
	labels = append(labels, status)
	return labels
}

func extendLabelValuesWithEvaluator(evaluator common.AuthConfigEvaluator, baseLabels ...string) ([]string, error) {
	if ev, ok := evaluator.(common.Monitorable); ok {
		if !ev.Measured() {
			return nil, fmt.Errorf("metrics are disabled for the evaluator")
		}

		labels := make([]string, len(baseLabels))
		copy(labels, baseLabels)
		labels = append(labels, ev.GetType(), ev.GetName())
		return labels, nil
	} else {
		return baseLabels, fmt.Errorf("cannot cast evaluator to monitorable")
	}
}

func ReportMetric(metric *prometheus.CounterVec, labels ...string) {
	metric.WithLabelValues(labels...).Inc()
}

func ReportMetricWithStatus(metric *prometheus.CounterVec, status string, labels ...string) {
	ReportMetric(metric, extendLabelValuesWithStatus(status, labels...)...)
}

func ReportMetricWithEvaluator(metric *prometheus.CounterVec, evaluator common.AuthConfigEvaluator, labels ...string) {
	if labels, err := extendLabelValuesWithEvaluator(evaluator, labels...); err == nil {
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

func ReportTimedMetricWithEvaluator(metric *prometheus.HistogramVec, f func(), evaluator common.AuthConfigEvaluator, labels ...string) {
	if labels, err := extendLabelValuesWithEvaluator(evaluator, labels...); err == nil {
		ReportTimedMetric(metric, f, labels...)
	} else {
		f()
	}
}
