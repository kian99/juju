// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package state_test

import (
	"github.com/juju/errors"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/state"
)

// ipAddressesStateSuite contains white-box tests for IP addresses of link-layer
// devices, which include access to mongo.
type ipAddressesStateSuite struct {
	ConnSuite

	machine *state.Machine
}

var _ = gc.Suite(&ipAddressesStateSuite{})

func (s *ipAddressesStateSuite) SetUpTest(c *gc.C) {
	s.ConnSuite.SetUpTest(c)

	var err error
	s.machine, err = s.State.AddMachine("quantal", state.JobHostUnits)
	c.Assert(err, jc.ErrorIsNil)

	// Add the few subnets used by the tests.
	_, err = s.State.AddSubnet(state.SubnetInfo{
		CIDR: "0.1.2.0/24",
	})
	_, err = s.State.AddSubnet(state.SubnetInfo{
		CIDR: "fc00::/64",
	})
	_, err = s.State.AddSubnet(state.SubnetInfo{
		CIDR: "10.20.0.0/16",
	})
}

func (s *ipAddressesStateSuite) TestMachineMethodReturnsMachine(c *gc.C) {
	_, addresses := s.addNamedDeviceWithAddresses(c, "eth0", "0.1.2.3/24")

	result, err := addresses[0].Machine()
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(result, jc.DeepEquals, s.machine)
}

func (s *ipAddressesStateSuite) addNamedDeviceWithAddresses(c *gc.C, name string, addresses ...string) (*state.LinkLayerDevice, []*state.Address) {
	deviceArgs := state.LinkLayerDeviceArgs{
		Name: name,
		Type: state.EthernetDevice,
	}
	err := s.machine.AddLinkLayerDevices(deviceArgs)
	c.Assert(err, jc.ErrorIsNil)
	device, err := s.machine.LinkLayerDevice(name)
	c.Assert(err, jc.ErrorIsNil)

	addressesArgs := make([]state.LinkLayerDeviceAddress, len(addresses))
	for i, address := range addresses {
		addressesArgs[i] = state.LinkLayerDeviceAddress{
			DeviceName:   name,
			ConfigMethod: state.StaticAddress,
			CIDRAddress:  address,
		}
	}
	err = s.machine.SetDevicesAddresses(addressesArgs...)
	c.Assert(err, jc.ErrorIsNil)
	deviceAddresses, err := device.Addresses()
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(deviceAddresses, gc.HasLen, len(addresses))
	return device, deviceAddresses
}

func (s *ipAddressesStateSuite) TestMachineMethodReturnsNotFoundErrorWhenMissing(c *gc.C) {
	_, addresses := s.addNamedDeviceWithAddresses(c, "eth0", "0.1.2.3/24")
	s.ensureMachineDeadAndRemove(c, s.machine)

	result, err := addresses[0].Machine()
	c.Assert(err, gc.ErrorMatches, "machine 0 not found")
	c.Assert(err, jc.Satisfies, errors.IsNotFound)
	c.Assert(result, gc.IsNil)
}

func (s *ipAddressesStateSuite) ensureMachineDeadAndRemove(c *gc.C, machine *state.Machine) {
	s.ensureEntityDeadAndRemoved(c, machine)
}

type ensureDeaderRemover interface {
	state.EnsureDeader
	state.Remover
}

func (s *ipAddressesStateSuite) ensureEntityDeadAndRemoved(c *gc.C, entity ensureDeaderRemover) {
	err := entity.EnsureDead()
	c.Assert(err, jc.ErrorIsNil)
	err = entity.Remove()
	c.Assert(err, jc.ErrorIsNil)
}

func (s *ipAddressesStateSuite) TestDeviceMethodReturnsLinkLayerDevice(c *gc.C) {
	addedDevice, addresses := s.addNamedDeviceWithAddresses(c, "eth0", "0.1.2.3/24")

	returnedDevice, err := addresses[0].Device()
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(returnedDevice, jc.DeepEquals, addedDevice)
}

func (s *ipAddressesStateSuite) TestDeviceMethodReturnsNotFoundErrorWhenMissing(c *gc.C) {
	device, addresses := s.addNamedDeviceWithAddresses(c, "eth0", "0.1.2.3/24")
	err := device.Remove()
	c.Assert(err, jc.ErrorIsNil)

	result, err := addresses[0].Device()
	c.Assert(result, gc.IsNil)
	c.Assert(err, jc.Satisfies, errors.IsNotFound)
	c.Assert(err, gc.ErrorMatches, `device "eth0" on machine "0" not found`)
}

func (s *ipAddressesStateSuite) TestSubnetMethodReturnsSubnet(c *gc.C) {
	_, addresses := s.addNamedDeviceWithAddresses(c, "eth0", "10.20.30.41/16")

	result, err := addresses[0].Subnet()
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(result.CIDR(), gc.Equals, "10.20.0.0/16")
}

func (s *ipAddressesStateSuite) TestSubnetMethodReturnsNotFoundErrorWhenMissing(c *gc.C) {
	_, addresses := s.addNamedDeviceWithAddresses(c, "eth0", "10.20.30.41/16")
	subnet, err := s.State.Subnet("10.20.0.0/16")
	c.Assert(err, jc.ErrorIsNil)
	s.ensureEntityDeadAndRemoved(c, subnet)

	result, err := addresses[0].Subnet()
	c.Assert(err, jc.Satisfies, errors.IsNotFound)
	c.Assert(err, gc.ErrorMatches, `subnet "10.20.0.0/16" not found`)
	c.Assert(result, gc.IsNil)
}

func (s *ipAddressesStateSuite) TestSubnetMethodReturnsNoErrorWithEmptySubnetID(c *gc.C) {
	_, addresses := s.addNamedDeviceWithAddresses(c, "eth0", "127.0.1.1/8", "::1/128")

	result, err := addresses[0].Subnet()
	c.Assert(result, gc.IsNil)
	c.Assert(err, jc.ErrorIsNil)

	result, err = addresses[1].Subnet()
	c.Assert(result, gc.IsNil)
	c.Assert(err, jc.ErrorIsNil)
}

func (s *ipAddressesStateSuite) TestRemoveSuccess(c *gc.C) {
	_, existingAddresses := s.addNamedDeviceWithAddresses(c, "eth0", "0.1.2.3/24")

	s.removeAddressAndAssertSuccess(c, existingAddresses[0])
	s.assertNoAddressesOnMachine(c, s.machine)
}

func (s *ipAddressesStateSuite) removeAddressAndAssertSuccess(c *gc.C, givenAddress *state.Address) {
	err := givenAddress.Remove()
	c.Assert(err, jc.ErrorIsNil)
}

func (s *ipAddressesStateSuite) assertNoAddressesOnMachine(c *gc.C, machine *state.Machine) {
	s.assertAllAddressesOnMachineMatchCount(c, machine, 0)
}

func (s *ipAddressesStateSuite) assertAllAddressesOnMachineMatchCount(c *gc.C, machine *state.Machine, expectedCount int) {
	results, err := machine.AllAddresses()
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(results, gc.HasLen, expectedCount)
}

func (s *ipAddressesStateSuite) TestRemoveTwiceStillSucceeds(c *gc.C) {
	_, existingAddresses := s.addNamedDeviceWithAddresses(c, "eth0", "0.1.2.3/24")

	s.removeAddressAndAssertSuccess(c, existingAddresses[0])
	s.removeAddressAndAssertSuccess(c, existingAddresses[0])
	s.assertNoAddressesOnMachine(c, s.machine)
}

func (s *ipAddressesStateSuite) TestLinkLayerDeviceAddressesReturnsAllDeviceAddresses(c *gc.C) {
	device, addedAddresses := s.addNamedDeviceWithAddresses(c, "eth0", "0.1.2.3/24", "10.20.30.40/16", "fc00::/64")
	s.assertAllAddressesOnMachineMatchCount(c, s.machine, 3)

	resultAddresses, err := device.Addresses()
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(resultAddresses, jc.DeepEquals, addedAddresses)
}

func (s *ipAddressesStateSuite) TestLinkLayerDeviceRemoveAddressesSuccess(c *gc.C) {
	device, _ := s.addNamedDeviceWithAddresses(c, "eth0", "10.20.30.40/16", "fc00::/64")
	s.assertAllAddressesOnMachineMatchCount(c, s.machine, 2)

	s.removeDeviceAddressesAndAssertNoneRemainOnMacine(c, device)
}

func (s *ipAddressesStateSuite) removeDeviceAddressesAndAssertNoneRemainOnMacine(c *gc.C, device *state.LinkLayerDevice) {
	err := device.RemoveAddresses()
	c.Assert(err, jc.ErrorIsNil)
	s.assertNoAddressesOnMachine(c, s.machine)
}

func (s *ipAddressesStateSuite) TestLinkLayerDeviceRemoveAddressesTwiceStillSucceeds(c *gc.C) {
	device, _ := s.addNamedDeviceWithAddresses(c, "eth0", "10.20.30.40/16", "fc00::/64")
	s.assertAllAddressesOnMachineMatchCount(c, s.machine, 2)

	s.removeDeviceAddressesAndAssertNoneRemainOnMacine(c, device)
	s.removeDeviceAddressesAndAssertNoneRemainOnMacine(c, device)
}

func (s *ipAddressesStateSuite) TestMachineRemoveAllAddressesSuccess(c *gc.C) {
	s.addTwoDevicesWithTwoAddressesEach(c)
	s.removeAllAddressesOnMachineAndAssertNoneRemain(c)
}

func (s *ipAddressesStateSuite) addTwoDevicesWithTwoAddressesEach(c *gc.C) []*state.Address {
	_, device1Addresses := s.addNamedDeviceWithAddresses(c, "eth1", "10.20.0.1/16", "10.20.0.2/16")
	_, device2Addresses := s.addNamedDeviceWithAddresses(c, "eth0", "10.20.100.2/16", "fc00::/64")
	s.assertAllAddressesOnMachineMatchCount(c, s.machine, 4)
	return append(device1Addresses, device2Addresses...)
}

func (s *ipAddressesStateSuite) removeAllAddressesOnMachineAndAssertNoneRemain(c *gc.C) {
	err := s.machine.RemoveAllAddresses()
	c.Assert(err, jc.ErrorIsNil)
	s.assertNoAddressesOnMachine(c, s.machine)
}

func (s *ipAddressesStateSuite) TestMachineRemoveAllAddressesTwiceStillSucceeds(c *gc.C) {
	s.addTwoDevicesWithTwoAddressesEach(c)
	s.removeAllAddressesOnMachineAndAssertNoneRemain(c)
	s.removeAllAddressesOnMachineAndAssertNoneRemain(c)
}

func (s *ipAddressesStateSuite) TestMachineAllAddressesSuccess(c *gc.C) {
	addedAddresses := s.addTwoDevicesWithTwoAddressesEach(c)

	allAddresses, err := s.machine.AllAddresses()
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(allAddresses, jc.DeepEquals, addedAddresses)
}

func (s *ipAddressesStateSuite) TestLinkLayerDeviceRemoveAlsoRemovesDeviceAddresses(c *gc.C) {
	device, _ := s.addNamedDeviceWithAddresses(c, "eth0", "10.20.30.40/16", "fc00::/64")
	s.assertAllAddressesOnMachineMatchCount(c, s.machine, 2)

	err := device.Remove()
	c.Assert(err, jc.ErrorIsNil)
	s.assertNoAddressesOnMachine(c, s.machine)
}

func (s *ipAddressesStateSuite) TestMachineRemoveAlsoRemoveAllAddresses(c *gc.C) {
	s.addTwoDevicesWithTwoAddressesEach(c)
	s.ensureMachineDeadAndRemove(c, s.machine)

	s.assertNoAddressesOnMachine(c, s.machine)
}
