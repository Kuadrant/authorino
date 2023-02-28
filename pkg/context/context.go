package context

import (
	gocontext "context"
	"time"
)

const (
	kTimeout key = iota
	kCancelFunc
)

type key int

func (k key) String() string {
	return []string{"timeout", "cancel"}[k]
}

type options struct {
	parent  gocontext.Context
	timeout time.Duration
}

type option func(*options)

// WithParent returns an option to create a new context based on an existing parent context.
func WithParent(parent gocontext.Context) option {
	return func(opts *options) {
		opts.parent = parent
	}
}

// WithTimeout return an option to create a new context that cancels itself automatically after the timeout.
func WithTimeout(timeout time.Duration) option {
	return func(opts *options) {
		opts.timeout = timeout
	}
}

// New creates a new golang context with the provided options.
// If a parent context is provided, creates a copy of the parent with further options.
// If a timeout option is provided, creates a context that cancels itself automatically after the timeout.
func New(opts ...option) gocontext.Context {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	var ctx gocontext.Context
	if o.parent != nil {
		ctx = o.parent
	} else {
		ctx = gocontext.Background()
	}

	if o.timeout > 0 {
		ctxWithTimeout, cancel := gocontext.WithTimeout(ctx, o.timeout)
		return gocontext.WithValue(gocontext.WithValue(ctxWithTimeout, kTimeout, o.timeout), kCancelFunc, cancel)
	}

	return ctx
}

// CheckContext checks if a go context is still active or done
// When it's done, returns a generic error
//
//	func myFunc(ctx context.Context) error {
//	  if err := common.CheckContext(ctx); err != nil {
//	  	 return err
//	  } else {
//	    doSomething()
//	  }
//	}
func CheckContext(ctx gocontext.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// Cancels the context if a CancelFunc is stored in the context.
func Cancel(ctx gocontext.Context) {
	if cancel, ok := ctx.Value(kCancelFunc).(gocontext.CancelFunc); ok {
		cancel()
	}
}
