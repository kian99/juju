// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package state

import (
	"context"

	"github.com/canonical/sqlair"

	"github.com/juju/juju/core/database"
	"github.com/juju/juju/domain"
	"github.com/juju/juju/internal/errors"
)

// ControllerState provides a state access layer for accessing a controller's
// ssh keys via controller config.
type ControllerState struct {
	*domain.StateBase
}

// GetControllerConfigKeys returns the controller config key and values for the
// keys supplied. If one or more keys supplied do not exist in the controller's
// config they will be omitted from the final result.
func (st *ControllerState) GetControllerConfigKeys(
	ctx context.Context,
	keys []string,
) (map[string]string, error) {
	db, err := st.DB(ctx)
	if err != nil {
		return nil, errors.Errorf(
			"getting database when getting controller config keys: %w", err,
		)
	}

	sqlKeys := make(sqlair.S, 0, len(keys))
	for _, key := range keys {
		sqlKeys = append(sqlKeys, key)
	}

	stmt, err := st.Prepare(`
SELECT &keyValue.*
FROM v_controller_config
WHERE key IN ($S[:])
`, keyValue{}, sqlKeys)
	if err != nil {
		return nil, errors.Errorf(
			"preparing statement for getting keys from controller config: %w",
			err,
		)
	}

	keyValues := []keyValue{}
	err = db.Txn(ctx, func(ctx context.Context, tx *sqlair.TX) error {
		err := tx.Query(ctx, stmt, sqlKeys).GetAll(&keyValues)
		if err != nil && !errors.Is(err, sqlair.ErrNoRows) {
			return err
		}
		return nil
	})

	if err != nil {
		return nil, errors.Errorf(
			"getting controller config for keys %v: %w",
			keys, err,
		)
	}

	rval := make(map[string]string, len(keyValues))
	for _, kv := range keyValues {
		rval[kv.Key] = kv.Value
	}

	return rval, nil
}

// NamespaceForWatchControllerConfig returns the namespace used to monitor
// controller configuration changes.
func (*ControllerState) NamespaceForWatchControllerConfig() string {
	return "controller_config"
}

// NewControllerState constructs a new state for interacting with the
// underlying authorised keys of a controller via controller config.
func NewControllerState(factory database.TxnRunnerFactory) *ControllerState {
	return &ControllerState{
		StateBase: domain.NewStateBase(factory),
	}
}
