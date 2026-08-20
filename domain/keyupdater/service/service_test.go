// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package service

import (
	"slices"
	"testing"

	"github.com/canonical/gomock/gomock"
	"github.com/juju/tc"

	coremachine "github.com/juju/juju/core/machine"
	machineerrors "github.com/juju/juju/domain/machine/errors"
	"github.com/juju/juju/internal/errors"
)

type serviceSuite struct {
	controllerKeyProvider *MockControllerKeyProvider
	state                 *MockState
	controllerState       *MockControllerState
}

func TestServiceSuite(t *testing.T) {
	tc.Run(t, &serviceSuite{})
}

var (
	controllerKeys = []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN8h8XBpjS9aBUG5cdoSWubs7wT2Lc/BEZIUQCqoaOZR juju-client-key",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN8h8XBpjS9aBUG5cdoSWubs7wT2Lc/BEZIUQCqoaOZR juju-system-key",
	}
)

func (s *serviceSuite) SetUpTest(c *tc.C) {
}

func (s *serviceSuite) setupMocks(c *tc.C) *gomock.Controller {
	ctrl := gomock.NewController(c)
	s.controllerKeyProvider = NewMockControllerKeyProvider(ctrl)
	s.state = NewMockState(ctrl)
	s.controllerState = NewMockControllerState(ctrl)
	return ctrl
}

// TestAuthorisedKeysForMachine is testing the happy path of
// [Service.AuthorisedKeysForMachine].
func (s *serviceSuite) TestAuthorisedKeysForMachine(c *tc.C) {
	defer s.setupMocks(c).Finish()

	s.state.EXPECT().CheckMachineExists(gomock.Any(), coremachine.Name("0")).Return(nil)
	s.controllerKeyProvider.EXPECT().ControllerAuthorisedKeys(gomock.Any()).Return(controllerKeys, nil)

	keys, err := NewService(s.controllerKeyProvider, s.controllerState, s.state).GetAuthorisedKeysForMachine(
		c.Context(),
		coremachine.Name("0"),
	)
	c.Check(err, tc.ErrorIsNil)

	slices.Sort(keys)
	c.Check(keys, tc.DeepEquals, controllerKeys)
}

// TestAuthorisedKeysForMachineNoControllerKeys is asserting that if no
// controller keys are available we still succeed with no errors.
func (s *serviceSuite) TestAuthorisedKeysForMachineNoControllerKeys(c *tc.C) {
	defer s.setupMocks(c).Finish()

	s.state.EXPECT().CheckMachineExists(gomock.Any(), coremachine.Name("0")).Return(nil)
	s.controllerKeyProvider.EXPECT().ControllerAuthorisedKeys(gomock.Any()).Return(nil, nil)

	keys, err := NewService(s.controllerKeyProvider, s.controllerState, s.state).GetAuthorisedKeysForMachine(
		c.Context(),
		coremachine.Name("0"),
	)
	c.Check(err, tc.ErrorIsNil)

	slices.Sort(keys)
	c.Check(keys, tc.DeepEquals, []string(nil))
}

// TestAuthorisedKeysForMachineNotFound is asserting that if we ask for
// authorised keys for a machine that doesn't exist we get back a
// [machineerrors.MachineNotFound] error.
func (s *serviceSuite) TestAuthorisedKeysForMachineNotFound(c *tc.C) {
	defer s.setupMocks(c).Finish()

	s.state.EXPECT().CheckMachineExists(gomock.Any(), coremachine.Name("0")).Return(machineerrors.MachineNotFound)

	_, err := NewService(s.controllerKeyProvider, s.controllerState, s.state).GetAuthorisedKeysForMachine(
		c.Context(),
		coremachine.Name("0"),
	)
	c.Check(err, tc.ErrorIs, machineerrors.MachineNotFound)
}

// TestGetInitialAuthorisedKeysForContainerSuccess tests the happy path for
// Service.GetInitialAuthorisedKeysForContainer.
func (s *serviceSuite) TestGetInitialAuthorisedKeysForContainerSuccess(c *tc.C) {
	defer s.setupMocks(c).Finish()

	s.controllerKeyProvider.EXPECT().ControllerAuthorisedKeys(gomock.Any()).Return(controllerKeys, nil)

	keys, err := NewService(s.controllerKeyProvider, s.controllerState, s.state).
		GetInitialAuthorisedKeysForContainer(c.Context())
	c.Assert(err, tc.ErrorIsNil)
	c.Check(keys, tc.DeepEquals, controllerKeys)
}

// TestGetInitialAuthorisedKeysForContainerSuccess checks that
// Service.GetInitialAuthorisedKeysForContainer surfaces errors from state.
func (s *serviceSuite) TestGetInitialAuthorisedKeysForContainerFailure(c *tc.C) {
	defer s.setupMocks(c).Finish()

	boom := errors.New("boom")

	s.controllerKeyProvider.EXPECT().ControllerAuthorisedKeys(gomock.Any()).Return(nil, boom)

	_, err := NewService(s.controllerKeyProvider, s.controllerState, s.state).
		GetInitialAuthorisedKeysForContainer(c.Context())
	c.Check(err, tc.ErrorIs, boom)
}
