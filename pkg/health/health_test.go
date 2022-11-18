package health

import (
	"fmt"
	"testing"

	"gotest.tools/assert"
)

type FakeObservableHealthy struct{}

func (o *FakeObservableHealthy) Ready() error { return nil }

type FakeObservableUnhealthy struct{}

func (o *FakeObservableUnhealthy) Ready() error { return fmt.Errorf("unhealthy") }

func TestObserveHealthy(t *testing.T) {
	h := NewHandler(Observe(&FakeObservableHealthy{}))
	err := h.HandleReadyzCheck(nil)
	assert.NilError(t, err)
}

func TestObserveUnealthy(t *testing.T) {
	h := NewHandler(Observe(&FakeObservableUnhealthy{}))
	err := h.HandleReadyzCheck(nil)
	assert.ErrorContains(t, err, "unhealthy")
}

func TestObserveHeathyUnealthy(t *testing.T) {
	h := NewHandler(Observe(&FakeObservableHealthy{}, &FakeObservableUnhealthy{}))
	err := h.HandleReadyzCheck(nil)
	assert.ErrorContains(t, err, "unhealthy")
}
