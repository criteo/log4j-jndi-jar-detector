// Code generated by MockGen. DO NOT EDIT.
// Source: reporter.go

// Package detector is a generated GoMock package.
package detector

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockReporter is a mock of Reporter interface.
type MockReporter struct {
	ctrl     *gomock.Controller
	recorder *MockReporterMockRecorder
}

// MockReporterMockRecorder is the mock recorder for MockReporter.
type MockReporterMockRecorder struct {
	mock *MockReporter
}

// NewMockReporter creates a new mock instance.
func NewMockReporter(ctrl *gomock.Controller) *MockReporter {
	mock := &MockReporter{ctrl: ctrl}
	mock.recorder = &MockReporterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockReporter) EXPECT() *MockReporterMockRecorder {
	return m.recorder
}

// ReportAssessment mocks base method.
func (m *MockReporter) ReportAssessment(hostAssessment HostAssessment, safeVersion Semver) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReportAssessment", hostAssessment, safeVersion)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReportAssessment indicates an expected call of ReportAssessment.
func (mr *MockReporterMockRecorder) ReportAssessment(hostAssessment, safeVersion interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportAssessment", reflect.TypeOf((*MockReporter)(nil).ReportAssessment), hostAssessment, safeVersion)
}

// ReportError mocks base method.
func (m *MockReporter) ReportError(fqdn string, anError error) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReportError", fqdn, anError)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReportError indicates an expected call of ReportError.
func (mr *MockReporterMockRecorder) ReportError(fqdn, anError interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportError", reflect.TypeOf((*MockReporter)(nil).ReportError), fqdn, anError)
}
