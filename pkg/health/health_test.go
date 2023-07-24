package health

import (
	"fmt"
	"net/http"
	neturl "net/url"
	"testing"

	"github.com/kuadrant/authorino/pkg/utils"

	"gotest.tools/assert"
)

type FakeObservableHealthy struct{}

func (o *FakeObservableHealthy) Ready(_, _ []string, _ bool) error { return nil }

type FakeObservableUnhealthy struct{}

func (o *FakeObservableUnhealthy) Ready(_, _ []string, _ bool) error { return fmt.Errorf("unhealthy") }

type FakeObservableFilterred struct {
	checked []string
}

func (o *FakeObservableFilterred) Ready(includes, excludes []string, _ bool) error {
	o.checked = includes

	if utils.SliceContains(includes, "opt-in-unhealthy") {
		return fmt.Errorf("opt-in-unhealthy not ready")
	}

	fmt.Println("includes: ", includes)
	fmt.Println("excludes: ", excludes)

	ready := utils.SliceContains(excludes, "opt-out-unhealthy")

	if !ready {
		o.checked = append(o.checked, "opt-out-unhealthy")
		return fmt.Errorf("opt-out-unhealthy not ready")
	}

	if !utils.SliceContains(excludes, "opt-out-healthy") {
		o.checked = append(o.checked, "opt-out-healthy")
	}

	return nil
}

func TestObserveHealthy(t *testing.T) {
	h := NewHandler("foo", Observe(&FakeObservableHealthy{}))
	err := h.HandleReadyzCheck(mockReq("http://localhost:8081/readyz"))
	assert.NilError(t, err)
}

func TestObserveUnhealthy(t *testing.T) {
	h := NewHandler("foo", Observe(&FakeObservableUnhealthy{}))
	err := h.HandleReadyzCheck(mockReq("http://localhost:8081/readyz"))
	assert.ErrorContains(t, err, "unhealthy")
}

func TestObserveHealthyUnhealthy(t *testing.T) {
	h := NewHandler("foo", Observe(&FakeObservableHealthy{}, &FakeObservableUnhealthy{}))
	err := h.HandleReadyzCheck(mockReq("http://localhost:8081/readyz"))
	assert.ErrorContains(t, err, "unhealthy")
}

func TestObserveIncludeExclude(t *testing.T) {
	o := &FakeObservableFilterred{checked: []string{}}
	h := NewHandler("foo", Observe(o))
	err := h.HandleReadyzCheck(mockReq("http://localhost:8081/readyz?include=opt-in-healthy&exclude=opt-out-unhealthy"))
	assert.NilError(t, err)
	assert.Equal(t, len(o.checked), 2)
	assert.Equal(t, o.checked[0], "opt-in-healthy")
	assert.Equal(t, o.checked[1], "opt-out-healthy")
}

func TestObserveIncludeUnhealthy(t *testing.T) {
	o := &FakeObservableFilterred{checked: []string{}}
	h := NewHandler("foo", Observe(o))
	err := h.HandleReadyzCheck(mockReq("http://localhost:8081/readyz?include=opt-in-unhealthy"))
	assert.ErrorContains(t, err, "opt-in-unhealthy not ready")
	assert.Equal(t, len(o.checked), 1)
	assert.Equal(t, o.checked[0], "opt-in-unhealthy")
}

func TestObserveExcludeUnhealthy(t *testing.T) {
	o := &FakeObservableFilterred{checked: []string{}}
	h := NewHandler("foo", Observe(o))
	err := h.HandleReadyzCheck(mockReq("http://localhost:8081/readyz?exclude=opt-out-unhealthy"))
	assert.NilError(t, err)
	assert.Equal(t, len(o.checked), 1)
	assert.Equal(t, o.checked[0], "opt-out-healthy")
}

func TestObserveIncludeImplicit(t *testing.T) {
	o := &FakeObservableFilterred{checked: []string{}}
	h := NewHandler("foo", Observe(o))
	err := h.HandleReadyzCheck(mockReq("http://localhost:8081/readyz/foo"))
	assert.ErrorContains(t, err, "opt-out-unhealthy not ready")
	assert.Equal(t, len(o.checked), 2)
	assert.Equal(t, o.checked[0], "foo")
	assert.Equal(t, o.checked[1], "opt-out-unhealthy")
}

func mockReq(url string) *http.Request {
	u, _ := neturl.Parse(url)
	return &http.Request{URL: u}
}
