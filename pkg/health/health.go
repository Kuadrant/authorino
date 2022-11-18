package health

import (
	"net/http"
	"sync"
)

type Observable interface {
	Ready() error
}

type HealthzHandler interface {
	Observe(...Observable)
	HandleReadyzCheck(*http.Request) error
}

type HandlerOption func(HealthzHandler)

func Observe(observables ...Observable) HandlerOption {
	return func(h HealthzHandler) {
		h.Observe(observables...)
	}
}

func NewHandler(options ...HandlerOption) HealthzHandler {
	h := &handler{}
	for _, o := range options {
		o(h)
	}
	return h
}

type handler struct {
	observables []Observable
	mu          sync.RWMutex
}

func (h *handler) Observe(observables ...Observable) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.observables = append(h.observables, observables...)
}

func (h *handler) HandleReadyzCheck(_ *http.Request) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, reconciler := range h.observables {
		if err := reconciler.Ready(); err != nil {
			return err
		}
	}
	return nil
}
