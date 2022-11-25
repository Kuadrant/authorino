package health

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type Observable interface {
	Ready(includes, excludes []string, verbose bool) error
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

func NewHandler(name string, options ...HandlerOption) HealthzHandler {
	h := &handler{name: name}
	for _, o := range options {
		o(h)
	}
	return h
}

type handler struct {
	name string

	observables []Observable
	mu          sync.RWMutex
}

func (h *handler) Observe(observables ...Observable) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.observables = append(h.observables, observables...)
}

func (h *handler) HandleReadyzCheck(req *http.Request) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	includes := req.URL.Query()["include"]
	excludes := req.URL.Query()["exclude"]

	// implicit include when requesting a specific check by name
	if strings.HasSuffix(req.URL.Path, fmt.Sprintf("/%s", h.name)) || strings.HasSuffix(req.URL.Path, fmt.Sprintf("/%s/", h.name)) {
		includes = append(includes, h.name)
	}

	// pass along the verbose parameter if present
	_, verbose := req.URL.Query()["verbose"]

	for _, reconciler := range h.observables {
		if err := reconciler.Ready(includes, excludes, verbose); err != nil {
			return err
		}
	}
	return nil
}
