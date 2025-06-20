// Code generated by MockGen. DO NOT EDIT.
// Source: controllers/builder/controller_builder.go

// Package mock_builder is a generated GoMock package.
package mock_builder

import (
	reflect "reflect"

	builder "github.com/kuadrant/authorino/controllers/builder"
	gomock "go.uber.org/mock/gomock"
	builder0 "sigs.k8s.io/controller-runtime/pkg/builder"
	client "sigs.k8s.io/controller-runtime/pkg/client"
	predicate "sigs.k8s.io/controller-runtime/pkg/predicate"
	reconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// MockControllerBuilder is a mock of ControllerBuilder interface.
type MockControllerBuilder struct {
	ctrl     *gomock.Controller
	recorder *MockControllerBuilderMockRecorder
}

// MockControllerBuilderMockRecorder is the mock recorder for MockControllerBuilder.
type MockControllerBuilderMockRecorder struct {
	mock *MockControllerBuilder
}

// NewMockControllerBuilder creates a new mock instance.
func NewMockControllerBuilder(ctrl *gomock.Controller) *MockControllerBuilder {
	mock := &MockControllerBuilder{ctrl: ctrl}
	mock.recorder = &MockControllerBuilderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockControllerBuilder) EXPECT() *MockControllerBuilderMockRecorder {
	return m.recorder
}

// Complete mocks base method.
func (m *MockControllerBuilder) Complete(arg0 reconcile.Reconciler) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Complete", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Complete indicates an expected call of Complete.
func (mr *MockControllerBuilderMockRecorder) Complete(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Complete", reflect.TypeOf((*MockControllerBuilder)(nil).Complete), arg0)
}

// For mocks base method.
func (m *MockControllerBuilder) For(arg0 client.Object, arg1 ...builder0.ForOption) builder.ControllerBuilder {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "For", varargs...)
	ret0, _ := ret[0].(builder.ControllerBuilder)
	return ret0
}

// For indicates an expected call of For.
func (mr *MockControllerBuilderMockRecorder) For(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "For", reflect.TypeOf((*MockControllerBuilder)(nil).For), varargs...)
}

// WithEventFilter mocks base method.
func (m *MockControllerBuilder) WithEventFilter(arg0 predicate.Predicate) builder.ControllerBuilder {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithEventFilter", arg0)
	ret0, _ := ret[0].(builder.ControllerBuilder)
	return ret0
}

// WithEventFilter indicates an expected call of WithEventFilter.
func (mr *MockControllerBuilderMockRecorder) WithEventFilter(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithEventFilter", reflect.TypeOf((*MockControllerBuilder)(nil).WithEventFilter), arg0)
}
