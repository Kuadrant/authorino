package workers

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// StartWorker returns a worker that executes a function repeatedly on a given interval (in seconds)
func StartWorker(ctx context.Context, interval int, f func()) (Worker, error) {
	w := &worker{
		ctx: ctx,
		f:   f,
	}

	if err := w.Start(interval); err != nil {
		return nil, err
	} else {
		return w, nil
	}
}

type Worker interface {
	Start(interval int) error
	Stop() error
}

type worker struct {
	ctx context.Context
	f   func()

	mu    sync.Mutex
	timer *time.Ticker
	done  chan bool
}

func (w *worker) Start(interval int) error {
	if interval <= 0 {
		return fmt.Errorf("interval must be greater than zero")
	}

	// ensure stop/restart is possible
	if err := w.Stop(); err != nil {
		return err
	}

	duration := time.Duration(interval) * time.Second

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.timer != nil {
		w.timer.Stop()
	}

	timer := time.NewTicker(duration)
	done := make(chan bool, 1)

	go func() {
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				w.f()
			case <-w.ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()

	w.timer = timer
	w.done = done

	return nil
}

// Stop is idempotent: stopping a worker that was never started, or that has already been
// stopped, is a no-op. Callers such as the AuthConfig reconciler clean up whatever config is
// currently in the index and cannot know whether that instance was cleaned up before.
func (w *worker) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.done != nil {
		close(w.done)
		w.done = nil
	}
	return nil
}
