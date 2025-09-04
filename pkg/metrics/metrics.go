package metrics

import (
	"fmt"
	"maps"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var DeepMetricsEnabled = false

type Object interface {
	GetType() string
	GetName() string
	MetricsEnabled() bool
}

func Register(metrics ...prometheus.Collector) {
	prometheus.MustRegister(metrics...)
}

type DynamicCounter struct {
	mu       sync.Mutex
	counters map[string]prometheus.Counter
	name     string
	help     string
}

func NewDynamicCounter(name, help string) *DynamicCounter {
	return &DynamicCounter{
		counters: make(map[string]prometheus.Counter),
		name:     name,
		help:     help,
	}
}

func (dc *DynamicCounter) Inc(labels map[string]string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	key := fmt.Sprintf("%v", labels)
	if c, ok := dc.counters[key]; ok {
		c.Inc()
		return
	}

	c := prometheus.NewCounter(prometheus.CounterOpts{
		Name:        dc.name,
		Help:        dc.help,
		ConstLabels: labels,
	})
	c.Inc()
	dc.counters[key] = c
}

func (dc *DynamicCounter) Describe(ch chan<- *prometheus.Desc) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	for _, c := range dc.counters {
		c.Describe(ch)
	}
}

func (dc *DynamicCounter) Collect(ch chan<- prometheus.Metric) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	for _, c := range dc.counters {
		c.Collect(ch)
	}
}

type DynamicHistogram struct {
	mu      sync.Mutex
	histos  map[string]prometheus.Histogram
	name    string
	help    string
	buckets []float64
}

func NewDynamicHistogram(name, help string) *DynamicHistogram {
	return &DynamicHistogram{
		histos:  make(map[string]prometheus.Histogram),
		name:    name,
		help:    help,
		buckets: prometheus.LinearBuckets(0.001, 0.05, 20),
	}
}

func (dh *DynamicHistogram) Observe(labels map[string]string, value float64) {
	dh.mu.Lock()
	defer dh.mu.Unlock()

	key := fmt.Sprintf("%v", labels)
	if h, ok := dh.histos[key]; ok {
		h.Observe(value)
		return
	}

	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        dh.name,
		Help:        dh.help,
		Buckets:     dh.buckets,
		ConstLabels: labels,
	})
	h.Observe(value)
	dh.histos[key] = h
}

func (dh *DynamicHistogram) Describe(ch chan<- *prometheus.Desc) {
	dh.mu.Lock()
	defer dh.mu.Unlock()
	for _, h := range dh.histos {
		h.Describe(ch)
	}
}

func (dh *DynamicHistogram) Collect(ch chan<- prometheus.Metric) {
	dh.mu.Lock()
	defer dh.mu.Unlock()
	for _, h := range dh.histos {
		h.Collect(ch)
	}
}

func ReportMetric(metric *DynamicCounter, labels map[string]string) {
	metric.Inc(labels)
}

func ReportMetricWithStatus(metric *DynamicCounter, status string, labels map[string]string) {
	if labels == nil {
		labels = make(map[string]string)
	}
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
	if labels == nil {
		labels = make(map[string]string)
	}
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
