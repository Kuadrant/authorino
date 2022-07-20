package controllers

import (
	"sync"
	"time"
)

func NewStatusReportMap() *StatusReportMap {
	return &StatusReportMap{
		statuses: make(map[string]StatusReport),
	}
}

type StatusReportMap struct {
	statuses map[string]StatusReport
	mu       sync.Mutex
}

func (m *StatusReportMap) Get(id string) (status StatusReport, found bool) {
	status, found = m.statuses[id]
	return
}

func (m *StatusReportMap) Set(id, reason, message string, hosts []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.statuses[id] = StatusReport{
		Reason:        reason,
		Message:       message,
		LinkedHosts:   hosts,
		LastUpdatedAt: time.Now(),
	}
}

func (m *StatusReportMap) Clear(id string) {
	delete(m.statuses, id)
}

type StatusReport struct {
	Reason        string
	Message       string
	LinkedHosts   []string
	LastUpdatedAt time.Time
}
