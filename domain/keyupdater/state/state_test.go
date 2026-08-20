// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package state

import (
	"context"
	"database/sql"
	"testing"

	"github.com/juju/tc"

	coremachine "github.com/juju/juju/core/machine"
	machineerrors "github.com/juju/juju/domain/machine/errors"
	schematesting "github.com/juju/juju/domain/schema/testing"
)

type stateSuite struct {
	schematesting.ModelSuite

	machineName coremachine.Name
}

func TestStateSuite(t *testing.T) {
	tc.Run(t, &stateSuite{})
}

// ensureNetNode inserts a row into the net_node table, mostly used as a foreign key for entries in
// other tables (e.g. machine)
func (s *stateSuite) ensureNetNode(c *tc.C, uuid string) {
	err := s.TxnRunner().StdTxn(c.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO net_node (uuid)
			VALUES (?)`, uuid)
		return err
	})
	c.Assert(err, tc.ErrorIsNil)
}

func (s *stateSuite) ensureMachine(c *tc.C, name coremachine.Name, uuid string) {
	s.ensureNetNode(c, "node2")
	err := s.TxnRunner().StdTxn(c.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
		INSERT INTO machine (uuid, net_node_uuid, name, life_id)
		VALUES (?, "node2", ?, "0")`, uuid, name)
		return err
	})
	c.Assert(err, tc.ErrorIsNil)
}

func (s *stateSuite) SetUpTest(c *tc.C) {
	s.ModelSuite.SetUpTest(c)

	s.machineName = coremachine.Name("0")
	s.ensureMachine(c, s.machineName, "123")
}

// TestCheckMachineExists is asserting the happy path of
// [State.CheckMachineExists] and that if a machine that exists is asked for no
// error is returned.
func (s *stateSuite) TestCheckMachineExists(c *tc.C) {
	err := NewState(s.TxnRunnerFactory()).CheckMachineExists(
		c.Context(),
		s.machineName,
	)
	c.Check(err, tc.ErrorIsNil)
}

// TestCheckMachineDoesNotExist is asserting the if we ask for a machine that
// doesn't exist we get back [machineerrors.MachineNotFound] error.
func (s *stateSuite) TestCheckMachineDoesNotExist(c *tc.C) {
	err := NewState(s.TxnRunnerFactory()).CheckMachineExists(
		c.Context(),
		coremachine.Name("100"),
	)
	c.Check(err, tc.ErrorIs, machineerrors.MachineNotFound)
}
