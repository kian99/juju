// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package state

import (
	"context"
	"database/sql"
	"testing"

	"github.com/juju/tc"

	"github.com/juju/juju/controller"
	schematesting "github.com/juju/juju/domain/schema/testing"
)

type controllerStateSuite struct {
	schematesting.ControllerSuite
}

func TestControllerStateSuite(t *testing.T) {
	tc.Run(t, &controllerStateSuite{})
}

var (
	controllerSSHKeys = `
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN8h8XBpjS9aBUG5cdoSWubs7wT2Lc/BEZIUQCqoaOZR juju-client-key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN8h8XBpjS9aBUG5cdoSWubs7wT2Lc/BEZIUQCqoaOZR juju-system-key`
)

// ensureControllerConfigSSHKeys is responsible for injecting ssh keys into a
// controllers config with the key defined in [controller.SystemSSHKeys].
func (s *controllerStateSuite) ensureControllerConfigSSHKeys(c *tc.C, keys string) {
	stmt := `
INSERT INTO controller_config (key, value) VALUES(?, ?)
`

	err := s.TxnRunner().StdTxn(c.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, stmt, controller.SystemSSHKeys, keys)
		return err
	})
	c.Assert(err, tc.ErrorIsNil)
}

func (s *controllerStateSuite) SetUpTest(c *tc.C) {
	s.ControllerSuite.SetUpTest(c)
	s.SeedControllerUUID(c)

}

// TestControllerConfigKeysEmpty ensures that if we ask for keys that do not
// exist in controller config no errors are returned an empty map is returned.
func (s *controllerStateSuite) TestControllerConfigKeysEmpty(c *tc.C) {
	kv, err := NewControllerState(s.TxnRunnerFactory()).GetControllerConfigKeys(
		c.Context(),
		[]string{"does-not-exist"},
	)
	c.Check(err, tc.ErrorIsNil)
	c.Check(len(kv), tc.Equals, 0)
}

// TestControllerConfigKeys is asserting the happy path that we can extract the
// system ssh keys from controller config when they exist.
func (s *controllerStateSuite) TestControllerConfigKeys(c *tc.C) {
	s.ensureControllerConfigSSHKeys(c, controllerSSHKeys)
	kv, err := NewControllerState(s.TxnRunnerFactory()).GetControllerConfigKeys(
		c.Context(),
		[]string{controller.SystemSSHKeys},
	)
	c.Check(err, tc.ErrorIsNil)
	c.Check(len(kv), tc.Equals, 1)
	c.Check(kv[controller.SystemSSHKeys], tc.Equals, controllerSSHKeys)
}
