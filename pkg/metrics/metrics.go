package metrics

import (
	"fmt"
	"hash/fnv"
	"maps"
	"slices"
	"sort"
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

type counterEntry struct {
	labels  map[string]string
	counter prometheus.Counter
}

type DynamicCounter struct {
	mu       sync.RWMutex
	counters map[uint64][]counterEntry
	name     string
	help     string
}

func NewDynamicCounter(name, help string) *DynamicCounter {
	return &DynamicCounter{
		counters: make(map[uint64][]counterEntry),
		name:     name,
		help:     help,
	}
}

func (dc *DynamicCounter) Inc(labels map[string]string) {
	key := hashLabels(labels)

	dc.mu.Lock()
	defer dc.mu.Unlock()

	entries := dc.counters[key]
	for _, entry := range entries {
		if maps.Equal(entry.labels, labels) {
			entry.counter.Inc()
			return
		}
	}

	c := prometheus.NewCounter(prometheus.CounterOpts{
		Name:        dc.name,
		Help:        dc.help,
		ConstLabels: labels,
	})
	dc.counters[key] = append(entries, counterEntry{labels: labels, counter: c})
	c.Inc()
}

func (dc *DynamicCounter) Describe(ch chan<- *prometheus.Desc) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	for _, entries := range dc.counters {
		for _, entry := range entries {
			entry.counter.Describe(ch)
		}
	}
}

func (dc *DynamicCounter) Collect(ch chan<- prometheus.Metric) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	for _, entries := range dc.counters {
		for _, entry := range entries {
			entry.counter.Collect(ch)
		}
	}
}

type histogramEntry struct {
	labels    map[string]string
	histogram prometheus.Histogram
}

type DynamicHistogram struct {
	mu         sync.RWMutex
	histograms map[uint64][]histogramEntry
	name       string
	help       string
	buckets    []float64
}

func NewDynamicHistogram(name, help string) *DynamicHistogram {
	return &DynamicHistogram{
		histograms: make(map[uint64][]histogramEntry),
		name:       name,
		help:       help,
		buckets:    prometheus.LinearBuckets(0.001, 0.05, 20),
	}
}

func (dh *DynamicHistogram) Observe(labels map[string]string, value float64) {
	key := hashLabels(labels)

	dh.mu.Lock()
	defer dh.mu.Unlock()

	entries := dh.histograms[key]
	for _, entry := range entries {
		if maps.Equal(entry.labels, labels) {
			entry.histogram.Observe(value)
			return
		}
	}

	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        dh.name,
		Help:        dh.help,
		Buckets:     dh.buckets,
		ConstLabels: labels,
	})
	dh.histograms[key] = append(entries, histogramEntry{labels: labels, histogram: h})
	h.Observe(value)
}

func (dh *DynamicHistogram) Describe(ch chan<- *prometheus.Desc) {
	dh.mu.RLock()
	defer dh.mu.RUnlock()

	for _, entries := range dh.histograms {
		for _, entry := range entries {
			entry.histogram.Describe(ch)
		}
	}
}

func (dh *DynamicHistogram) Collect(ch chan<- prometheus.Metric) {
	dh.mu.RLock()
	defer dh.mu.RUnlock()

	for _, entries := range dh.histograms {
		for _, entry := range entries {
			entry.histogram.Collect(ch)
		}
	}
}

func hashLabels(labels map[string]string) uint64 {
	h := fnv.New64a()

	keys := slices.Collect(maps.Keys(labels))
	sort.Strings(keys)

	// Write in deterministic order
	for _, k := range keys {
		v := labels[k]
		// hash.Hash.Write never returns an error
		_, _ = h.Write([]byte(fmt.Sprintf("%s=%s,", k, v))) //nolint:staticcheck
	}

	return h.Sum64()
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
