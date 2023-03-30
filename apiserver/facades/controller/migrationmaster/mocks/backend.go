// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/juju/juju/apiserver/facades/controller/migrationmaster (interfaces: Backend)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	description "github.com/juju/description/v4"
	controller "github.com/juju/juju/controller"
	network "github.com/juju/juju/core/network"
	state "github.com/juju/juju/state"
	names "github.com/juju/names/v4"
	version "github.com/juju/version/v2"
)

// MockBackend is a mock of Backend interface.
type MockBackend struct {
	ctrl     *gomock.Controller
	recorder *MockBackendMockRecorder
}

// MockBackendMockRecorder is the mock recorder for MockBackend.
type MockBackendMockRecorder struct {
	mock *MockBackend
}

// NewMockBackend creates a new mock instance.
func NewMockBackend(ctrl *gomock.Controller) *MockBackend {
	mock := &MockBackend{ctrl: ctrl}
	mock.recorder = &MockBackendMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBackend) EXPECT() *MockBackendMockRecorder {
	return m.recorder
}

// APIHostPortsForClients mocks base method.
func (m *MockBackend) APIHostPortsForClients() ([]network.SpaceHostPorts, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "APIHostPortsForClients")
	ret0, _ := ret[0].([]network.SpaceHostPorts)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// APIHostPortsForClients indicates an expected call of APIHostPortsForClients.
func (mr *MockBackendMockRecorder) APIHostPortsForClients() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "APIHostPortsForClients", reflect.TypeOf((*MockBackend)(nil).APIHostPortsForClients))
}

// AgentVersion mocks base method.
func (m *MockBackend) AgentVersion() (version.Number, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AgentVersion")
	ret0, _ := ret[0].(version.Number)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AgentVersion indicates an expected call of AgentVersion.
func (mr *MockBackendMockRecorder) AgentVersion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AgentVersion", reflect.TypeOf((*MockBackend)(nil).AgentVersion))
}

// AllLocalRelatedModels mocks base method.
func (m *MockBackend) AllLocalRelatedModels() ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AllLocalRelatedModels")
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AllLocalRelatedModels indicates an expected call of AllLocalRelatedModels.
func (mr *MockBackendMockRecorder) AllLocalRelatedModels() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AllLocalRelatedModels", reflect.TypeOf((*MockBackend)(nil).AllLocalRelatedModels))
}

// ControllerConfig mocks base method.
func (m *MockBackend) ControllerConfig() (controller.Config, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ControllerConfig")
	ret0, _ := ret[0].(controller.Config)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ControllerConfig indicates an expected call of ControllerConfig.
func (mr *MockBackendMockRecorder) ControllerConfig() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ControllerConfig", reflect.TypeOf((*MockBackend)(nil).ControllerConfig))
}

// Export mocks base method.
func (m *MockBackend) Export(arg0 map[string]string) (description.Model, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Export", arg0)
	ret0, _ := ret[0].(description.Model)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Export indicates an expected call of Export.
func (mr *MockBackendMockRecorder) Export(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Export", reflect.TypeOf((*MockBackend)(nil).Export), arg0)
}

// LatestMigration mocks base method.
func (m *MockBackend) LatestMigration() (state.ModelMigration, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LatestMigration")
	ret0, _ := ret[0].(state.ModelMigration)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LatestMigration indicates an expected call of LatestMigration.
func (mr *MockBackendMockRecorder) LatestMigration() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LatestMigration", reflect.TypeOf((*MockBackend)(nil).LatestMigration))
}

// ModelName mocks base method.
func (m *MockBackend) ModelName() (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ModelName")
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ModelName indicates an expected call of ModelName.
func (mr *MockBackendMockRecorder) ModelName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ModelName", reflect.TypeOf((*MockBackend)(nil).ModelName))
}

// ModelOwner mocks base method.
func (m *MockBackend) ModelOwner() (names.UserTag, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ModelOwner")
	ret0, _ := ret[0].(names.UserTag)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ModelOwner indicates an expected call of ModelOwner.
func (mr *MockBackendMockRecorder) ModelOwner() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ModelOwner", reflect.TypeOf((*MockBackend)(nil).ModelOwner))
}

// ModelUUID mocks base method.
func (m *MockBackend) ModelUUID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ModelUUID")
	ret0, _ := ret[0].(string)
	return ret0
}

// ModelUUID indicates an expected call of ModelUUID.
func (mr *MockBackendMockRecorder) ModelUUID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ModelUUID", reflect.TypeOf((*MockBackend)(nil).ModelUUID))
}

// RemoveExportingModelDocs mocks base method.
func (m *MockBackend) RemoveExportingModelDocs() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RemoveExportingModelDocs")
	ret0, _ := ret[0].(error)
	return ret0
}

// RemoveExportingModelDocs indicates an expected call of RemoveExportingModelDocs.
func (mr *MockBackendMockRecorder) RemoveExportingModelDocs() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveExportingModelDocs", reflect.TypeOf((*MockBackend)(nil).RemoveExportingModelDocs))
}

// WatchForMigration mocks base method.
func (m *MockBackend) WatchForMigration() state.NotifyWatcher {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WatchForMigration")
	ret0, _ := ret[0].(state.NotifyWatcher)
	return ret0
}

// WatchForMigration indicates an expected call of WatchForMigration.
func (mr *MockBackendMockRecorder) WatchForMigration() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WatchForMigration", reflect.TypeOf((*MockBackend)(nil).WatchForMigration))
}
