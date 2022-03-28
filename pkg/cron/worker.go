package cron

import (
	"context"
	"fmt"
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
	ctx   context.Context
	f     func()
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

	if w.timer != nil {
		w.timer.Stop()
	}

	w.timer = time.NewTicker(duration)

	done := make(chan bool, 1)

	go func() {
		defer w.timer.Stop()
		for {
			select {
			case <-w.timer.C:
				w.f()
			case <-w.ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()

	w.done = done

	return nil
}

func (w *worker) Stop() error {
	if w.done != nil {
		close(w.done)
	}
	return nil
}
