// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package state

import (
	"context"

	"github.com/canonical/sqlair"

	"github.com/juju/juju/core/database"
	coremachine "github.com/juju/juju/core/machine"
	"github.com/juju/juju/domain"
	machineerrors "github.com/juju/juju/domain/machine/errors"
	"github.com/juju/juju/internal/errors"
)

// State defines the access mechanism for interacting with authorized keys in
// the context of the model database.
type State struct {
	*domain.StateBase
}

// CheckMachineExists checks to see if the given machine exists in the model. If
// the machine does not exist an error satisfying
// [machineerrors.MachineNotFound] is returned.
func (s *State) CheckMachineExists(
	ctx context.Context,
	name coremachine.Name,
) error {
	db, err := s.DB(ctx)
	if err != nil {
		return errors.Errorf(
			"getting database to check if machine %q exists: %w",
			name, err,
		)
	}

	machineArg := machineName{name.String()}
	machineStmt, err := s.Prepare(`
SELECT &machineName.*
FROM machine
WHERE name = $machineName.name
`, machineArg)
	if err != nil {
		return errors.Errorf(
			"preparing statement for checking if machine %q exists: %w",
			name, err,
		)
	}

	err = db.Txn(ctx, func(ctx context.Context, tx *sqlair.TX) error {
		err := tx.Query(ctx, machineStmt, machineArg).Get(&machineArg)
		if errors.Is(err, sqlair.ErrNoRows) {
			return errors.Errorf(
				"machine %q does not exist", name,
			).Add(machineerrors.MachineNotFound)
		} else if err != nil {
			return errors.Errorf(
				"checking if machine %q exists: %w", name, err,
			)
		}
		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

// NewState constructs a new state for interacting with the underlying
// authorised keys of a model.
func NewState(factory database.TxnRunnerFactory) *State {
	return &State{
		StateBase: domain.NewStateBase(factory),
	}
}
