package controllers

import (
	"sync"
	"time"
)

func NewReconciliationErrorsMap() *ReconciliationErrorsMap {
	return &ReconciliationErrorsMap{
		errors: make(map[string]ReconciliationError),
	}
}

type ReconciliationErrorsMap struct {
	errors map[string]ReconciliationError
	mu     sync.Mutex
}

func (m *ReconciliationErrorsMap) Get(id string) (err ReconciliationError, found bool) {
	err, found = m.errors[id]
	return
}

func (m *ReconciliationErrorsMap) Set(id, reason, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.errors[id] = ReconciliationError{
		Reason:        reason,
		Message:       message,
		LastUpdatedAt: time.Now(),
	}
}

func (m *ReconciliationErrorsMap) Clear(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.errors, id)
}

type ReconciliationError struct {
	Reason        string
	Message       string
	LastUpdatedAt time.Time
}
