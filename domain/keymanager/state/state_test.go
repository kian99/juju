// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package state

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/juju/tc"

	"github.com/juju/juju/core/user"
	usertesting "github.com/juju/juju/core/user/testing"
	"github.com/juju/juju/domain/keymanager"
	keyerrors "github.com/juju/juju/domain/keymanager/errors"
	schematesting "github.com/juju/juju/domain/schema/testing"
	"github.com/juju/juju/internal/ssh"
)

type stateSuite struct {
	schematesting.ControllerSuite
	userID user.UUID
}

func TestStateSuite(t *testing.T) { tc.Run(t, &stateSuite{}) }

var testingPublicKeys = []string{
	"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN8h8XBpjS9aBUG5cdoSWubs7wT2Lc/BEZIUQCqoaOZR one@juju.is",
	"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJQJ9wv0uC3yytXM3d2sJJWvZLuISKo7ZHwafHVviwVe two@juju.is",
}

func generatePublicKeys(c *tc.C, values []string) []keymanager.PublicKey {
	result := make([]keymanager.PublicKey, 0, len(values))
	for _, value := range values {
		parsed, err := ssh.ParsePublicKey(value)
		c.Assert(err, tc.ErrorIsNil)
		result = append(result, keymanager.PublicKey{
			Comment: parsed.Comment, FingerprintHash: keymanager.FingerprintHashAlgorithmSHA256,
			Fingerprint: parsed.Fingerprint(), Key: value,
		})
	}
	return result
}

func (s *stateSuite) SetUpTest(c *tc.C) {
	s.ControllerSuite.SetUpTest(c)
	s.SeedControllerUUID(c)
	s.userID = usertesting.GenUserUUID(c)
	err := s.TxnRunner().StdTxn(c.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO user (uuid, name, display_name, external, removed, created_by_uuid, created_at) VALUES (?, ?, ?, false, false, ?, datetime('now'))`, s.userID, "key-user", "key-user", s.userID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO user_authentication (user_uuid, disabled) VALUES (?, false)`, s.userID)
		return err
	})
	c.Assert(err, tc.ErrorIsNil)
}

func (s *stateSuite) TestAddAndGetPublicKeysForUser(c *tc.C) {
	state := NewState(s.TxnRunnerFactory())
	keys := generatePublicKeys(c, testingPublicKeys)

	err := state.AddPublicKeysForUser(c.Context(), s.userID, keys)
	c.Assert(err, tc.ErrorIsNil)

	got, err := state.GetPublicKeysForUser(c.Context(), s.userID)
	c.Assert(err, tc.ErrorIsNil)
	gotKeys := make([]string, 0, len(got))
	for _, key := range got {
		gotKeys = append(gotKeys, key.Key)
	}
	slices.Sort(gotKeys)
	expected := append([]string(nil), testingPublicKeys...)
	slices.Sort(expected)
	c.Check(gotKeys, tc.DeepEquals, expected)
}

func (s *stateSuite) TestAddPublicKeysForUserAlreadyExists(c *tc.C) {
	state := NewState(s.TxnRunnerFactory())
	keys := generatePublicKeys(c, testingPublicKeys[:1])
	c.Assert(state.AddPublicKeysForUser(c.Context(), s.userID, keys), tc.ErrorIsNil)
	c.Check(state.AddPublicKeysForUser(c.Context(), s.userID, keys), tc.ErrorIs, keyerrors.PublicKeyAlreadyExists)
}

func (s *stateSuite) TestEnsurePublicKeysForUser(c *tc.C) {
	state := NewState(s.TxnRunnerFactory())
	keys := generatePublicKeys(c, testingPublicKeys)
	c.Assert(state.EnsurePublicKeysForUser(c.Context(), s.userID, keys), tc.ErrorIsNil)
	c.Check(state.EnsurePublicKeysForUser(c.Context(), s.userID, keys), tc.ErrorIsNil)
}

func (s *stateSuite) TestDeletePublicKeysForUser(c *tc.C) {
	state := NewState(s.TxnRunnerFactory())
	keys := generatePublicKeys(c, testingPublicKeys)
	c.Assert(state.AddPublicKeysForUser(c.Context(), s.userID, keys), tc.ErrorIsNil)
	c.Assert(state.DeletePublicKeysForUser(c.Context(), s.userID, []string{keys[0].Comment}), tc.ErrorIsNil)
	got, err := state.GetPublicKeysForUser(c.Context(), s.userID)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(got, tc.HasLen, 1)
}

func (s *stateSuite) TestGetAllUsersPublicKeys(c *tc.C) {
	state := NewState(s.TxnRunnerFactory())
	keys := generatePublicKeys(c, testingPublicKeys)
	c.Assert(state.AddPublicKeysForUser(c.Context(), s.userID, keys), tc.ErrorIsNil)
	got, err := state.GetAllUsersPublicKeys(c.Context())
	c.Assert(err, tc.ErrorIsNil)
	c.Check(got, tc.HasLen, 1)
}
