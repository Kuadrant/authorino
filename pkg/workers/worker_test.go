package workers

import (
	"context"
	"testing"
	"time"

	"gotest.tools/assert"
)

func TestStartWorker(t *testing.T) {
	val := 0
	worker, err := StartWorker(context.TODO(), 2, func() {
		val += 1
	})
	defer worker.Stop()
	assert.NilError(t, err)

	assert.Equal(t, val, 0)

	time.Sleep(3 * time.Second)

	assert.Equal(t, val, 1)
}

func TestStopWorker(t *testing.T) {
	val := 0
	worker, err := StartWorker(context.TODO(), 2, func() {
		val += 1
	})
	assert.NilError(t, err)

	assert.Equal(t, val, 0)

	err = worker.Stop()
	assert.NilError(t, err)

	time.Sleep(3 * time.Second)

	assert.Equal(t, val, 0)
}
