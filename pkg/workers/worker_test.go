package workers

import (
	"context"
	"sync"
	"testing"
	"time"

	"gotest.tools/assert"
)

func TestStartWorker(t *testing.T) {
	var mu sync.Mutex
	val := 0
	worker, err := StartWorker(context.TODO(), 2, func() {
		mu.Lock()
		val += 1
		mu.Unlock()
	})
	defer func(worker Worker) {
		_ = worker.Stop()
	}(worker)
	assert.NilError(t, err)

	mu.Lock()
	currentVal := val
	mu.Unlock()
	assert.Equal(t, currentVal, 0)

	time.Sleep(3 * time.Second)

	mu.Lock()
	currentVal = val
	mu.Unlock()
	assert.Equal(t, currentVal, 1)
}

func TestStopWorker(t *testing.T) {
	var mu sync.Mutex
	val := 0
	worker, err := StartWorker(context.TODO(), 2, func() {
		mu.Lock()
		val += 1
		mu.Unlock()
	})
	assert.NilError(t, err)

	mu.Lock()
	currentVal := val
	mu.Unlock()
	assert.Equal(t, currentVal, 0)

	err = worker.Stop()
	assert.NilError(t, err)

	time.Sleep(3 * time.Second)

	mu.Lock()
	currentVal = val
	mu.Unlock()
	assert.Equal(t, currentVal, 0)
}

func TestStopWorkerIsIdempotent(t *testing.T) {
	worker, err := StartWorker(context.TODO(), 60, func() {})
	assert.NilError(t, err)

	// the AuthConfig reconciler cleans up whatever config is currently in the index and cannot
	// know whether that same instance was already cleaned up by a previous (failed) reconcile
	assert.NilError(t, worker.Stop())
	assert.NilError(t, worker.Stop())
	assert.NilError(t, worker.Stop())
}

func TestStopWorkerNeverStarted(t *testing.T) {
	w := &worker{ctx: context.TODO(), f: func() {}}
	assert.NilError(t, w.Stop())
}

func TestRestartWorkerAfterStop(t *testing.T) {
	var mu sync.Mutex
	val := 0
	worker, err := StartWorker(context.TODO(), 2, func() {
		mu.Lock()
		val += 1
		mu.Unlock()
	})
	assert.NilError(t, err)
	assert.NilError(t, worker.Stop())

	assert.NilError(t, worker.Start(2))
	defer func() { _ = worker.Stop() }()

	time.Sleep(3 * time.Second)

	mu.Lock()
	currentVal := val
	mu.Unlock()
	assert.Equal(t, currentVal, 1)
}
