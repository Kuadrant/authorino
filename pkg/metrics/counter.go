package metrics

import (
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

type DynamicCounter struct {
	mu      sync.Mutex
	metrics map[string]prometheus.Counter
	desc    *prometheus.Desc
	name    string
	help    string
}

func NewDynamicCounter(name, help string) *DynamicCounter {
	return &DynamicCounter{
		metrics: make(map[string]prometheus.Counter),
		name:    name,
		help:    help,
		desc: prometheus.NewDesc(
			name,
			help,
			nil, // no fixed variable labels
			nil, // no const labels
		),
	}
}

func (dc *DynamicCounter) Describe(ch chan<- *prometheus.Desc) {
	ch <- dc.desc
}

func (dc *DynamicCounter) Collect(ch chan<- prometheus.Metric) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	for _, m := range dc.metrics {
		ch <- m
	}
}

// Increment or create a counter with arbitrary labels
func (dc *DynamicCounter) Inc(labels map[string]string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Build a stable key for this label set
	key := fmt.Sprintf("%v", labels)

	if m, ok := dc.metrics[key]; ok {
		// Increment existing
		m.(prometheus.Counter).Inc()
		return
	}

	// Create new counter
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name:        dc.name,
		Help:        dc.help,
		ConstLabels: labels,
	})
	counter.Inc()

	dc.metrics[key] = counter
}

type DynamicHistogram struct {
	mu      sync.Mutex
	histos  map[string]prometheus.Histogram
	name    string
	help    string
	buckets []float64
	desc    *prometheus.Desc
}

// NewDynamicHistogram creates a dynamic histogram
// buckets can be nil to use default Prometheus buckets
func NewDynamicHistogram(name, help string) *DynamicHistogram {
	return &DynamicHistogram{
		histos:  make(map[string]prometheus.Histogram),
		name:    name,
		help:    help,
		buckets: prometheus.LinearBuckets(0.001, 0.05, 20),
		desc: prometheus.NewDesc(
			name,
			help,
			nil, // variable labels are dynamic
			nil, // no const labels
		),
	}
}

// Describe sends the descriptor for Prometheus
func (dh *DynamicHistogram) Describe(ch chan<- *prometheus.Desc) {
	ch <- dh.desc
}

// Collect sends all stored histograms
func (dh *DynamicHistogram) Collect(ch chan<- prometheus.Metric) {
	dh.mu.Lock()
	defer dh.mu.Unlock()
	for _, h := range dh.histos {
		ch <- h
	}
}

// Observe records a value for the given label set
func (dh *DynamicHistogram) Observe(labels map[string]string, value float64) {
	dh.mu.Lock()
	defer dh.mu.Unlock()

	key := fmt.Sprintf("%v", labels)
	if h, ok := dh.histos[key]; ok {
		h.Observe(value)
		return
	}

	// create a new histogram for this label set
	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        dh.name,
		Help:        dh.help,
		Buckets:     dh.buckets,
		ConstLabels: labels,
	})
	h.Observe(value)
	dh.histos[key] = h
}
