package trace

import "github.com/go-logr/logr"

type ErrorHandler struct {
	logr.Logger
}

func (h *ErrorHandler) Handle(err error) {
	h.Error(err, "trace error")
}
