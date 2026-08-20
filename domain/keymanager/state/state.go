// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package state

import (
	"context"

	"github.com/canonical/sqlair"

	"github.com/juju/juju/core/database"
	coressh "github.com/juju/juju/core/ssh"
	"github.com/juju/juju/core/user"
	"github.com/juju/juju/domain"
	accesserrors "github.com/juju/juju/domain/access/errors"
	"github.com/juju/juju/domain/keymanager"
	keyerrors "github.com/juju/juju/domain/keymanager/errors"
	"github.com/juju/juju/internal/errors"
)

// State represents a type for interacting with the underlying state of a
// user's public keys in the controller.
type State struct {
	*domain.StateBase
}

// NewState is responsible for constructing a new [State] that can be used with
// this domain's corresponding service.
func NewState(factory database.TxnRunnerFactory) *State {
	return &State{StateBase: domain.NewStateBase(factory)}
}

// checkUserExists checks that a user exists and is active.
func (s *State) checkUserExists(ctx context.Context, userUUID user.UUID, tx *sqlair.TX) error {
	userUUIDVal := userUUIDValue{UUID: userUUID.String()}
	stmt, err := s.Prepare(`
SELECT (uuid) AS (&userUUIDValue.user_uuid)
FROM v_user_auth
WHERE uuid = $userUUIDValue.user_uuid
AND removed = false
`, userUUIDVal)
	if err != nil {
		return errors.Errorf("creating user exists statement for user %q: %w", userUUID, err)
	}

	err = tx.Query(ctx, stmt, userUUIDVal).Get(&userUUIDVal)
	if errors.Is(err, sqlair.ErrNoRows) {
		return errors.Errorf("checking user %q exists, user not found", userUUID).
			Add(accesserrors.UserNotFound)
	}
	if err != nil {
		return errors.Errorf("checking user %q exists: %w", userUUID, err)
	}
	return nil
}

// AddPublicKeysForUser is responsible for adding one or more SSH public keys
// for a user to the controller. The following errors can be expected:
//   - [keyerrors.PublicKeyAlreadyExists] when one of the public keys being added
//     for a user already exists on the controller.
//   - [accesserrors.UserNotFound] when the user does not exist.
func (s *State) AddPublicKeysForUser(ctx context.Context, userUUID user.UUID, publicKeys []keymanager.PublicKey) error {
	db, err := s.DB(ctx)
	if err != nil {
		return errors.Errorf("getting database for adding public keys to user %q: %w", userUUID, err)
	}

	lookupStmt, err := s.Prepare(`
SELECT &userPublicKeyId.id
FROM user_public_ssh_key
WHERE user_uuid = $userPublicKeyInsert.user_uuid
AND fingerprint = $userPublicKeyInsert.fingerprint
`, userPublicKeyId{}, userPublicKeyInsert{})
	if err != nil {
		return errors.Errorf("preparing public key lookup statement: %w", err)
	}
	insertStmt, err := s.Prepare(`
INSERT INTO user_public_ssh_key (comment, fingerprint, public_key, user_uuid,
                                fingerprint_hash_algorithm_id)
SELECT $userPublicKeyInsert.comment,
       $userPublicKeyInsert.fingerprint,
       $userPublicKeyInsert.public_key,
       $userPublicKeyInsert.user_uuid,
       sha.id
FROM ssh_fingerprint_hash_algorithm AS sha
WHERE sha.algorithm = $userPublicKeyInsert.algorithm
`, userPublicKeyInsert{})
	if err != nil {
		return errors.Errorf("preparing public key insert statement: %w", err)
	}

	return db.Txn(ctx, func(ctx context.Context, tx *sqlair.TX) error {
		if err := s.checkUserExists(ctx, userUUID, tx); err != nil {
			return errors.Errorf("adding public keys for user %q: %w", userUUID, err)
		}

		for i, publicKey := range publicKeys {
			row := userPublicKeyInsert{
				Comment:                  publicKey.Comment,
				FingerprintHashAlgorithm: publicKey.FingerprintHash.String(),
				Fingerprint:              publicKey.Fingerprint,
				PublicKey:                publicKey.Key,
				UserId:                   userUUID.String(),
			}
			var existing userPublicKeyId
			err := tx.Query(ctx, lookupStmt, row).Get(&existing)
			if err == nil {
				return errors.Errorf("adding key %d for user %q, key already exists", i, userUUID).
					Add(keyerrors.PublicKeyAlreadyExists)
			}
			if !errors.Is(err, sqlair.ErrNoRows) {
				return errors.Errorf("checking key %d for user %q: %w", i, userUUID, err)
			}
			if err := tx.Query(ctx, insertStmt, row).Get(&sqlair.Outcome{}); err != nil {
				return errors.Errorf("adding key %d for user %q: %w", i, userUUID, err)
			}
		}
		return nil
	})
}

// EnsurePublicKeysForUser will attempt to add the given set of public keys for
// the user to the controller. If the user already has the public key it will be
// skipped and no [keyerrors.PublicKeyAlreadyExists] error will be returned.
// The following errors can be expected:
// - [accesserrors.UserNotFound] when the user does not exist.
func (s *State) EnsurePublicKeysForUser(ctx context.Context, userUUID user.UUID, publicKeys []keymanager.PublicKey) error {
	for _, publicKey := range publicKeys {
		err := s.AddPublicKeysForUser(ctx, userUUID, []keymanager.PublicKey{publicKey})
		if err != nil && !errors.Is(err, keyerrors.PublicKeyAlreadyExists) {
			return err
		}
	}
	return nil
}

// GetPublicKeysForUser is responsible for returning all of the public keys for
// the user UUID. The following errors can be expected:
// - [accesserrors.UserNotFound] when the user does not exist.
func (s *State) GetPublicKeysForUser(ctx context.Context, userUUID user.UUID) ([]coressh.PublicKey, error) {
	db, err := s.DB(ctx)
	if err != nil {
		return nil, err
	}
	arg := userUUIDValue{UUID: userUUID.String()}
	stmt, err := s.Prepare(`
SELECT &publicKey.*
FROM user_public_ssh_key AS upsk
WHERE upsk.user_uuid = $userUUIDValue.user_uuid
`, arg, publicKey{})
	if err != nil {
		return nil, errors.Errorf("preparing public key query for user %q: %w", userUUID, err)
	}

	rows := []publicKey{}
	err = db.Txn(ctx, func(ctx context.Context, tx *sqlair.TX) error {
		if err := s.checkUserExists(ctx, userUUID, tx); err != nil {
			return err
		}
		err := tx.Query(ctx, stmt, arg).GetAll(&rows)
		if err != nil && !errors.Is(err, sqlair.ErrNoRows) {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := make([]coressh.PublicKey, 0, len(rows))
	for _, row := range rows {
		result = append(result, coressh.PublicKey{Fingerprint: row.Fingerprint, Key: row.PublicKey})
	}
	return result, nil
}

// GetAllUsersPublicKeys returns all of the public keys in the controller for
// each user grouped by [user.Name]. This is useful for building a view during
// controller migration.
func (s *State) GetAllUsersPublicKeys(ctx context.Context) (map[user.Name][]string, error) {
	db, err := s.DB(ctx)
	if err != nil {
		return nil, err
	}
	stmt, err := s.Prepare(`
SELECT (u.name, upsk.public_key) AS (&userPublicKey.*)
FROM user_public_ssh_key AS upsk
JOIN user AS u ON u.uuid = upsk.user_uuid
JOIN user_authentication AS ua ON ua.user_uuid = u.uuid
WHERE u.removed = false
AND ua.disabled = false
`, userPublicKey{})
	if err != nil {
		return nil, errors.Errorf("preparing all public keys query: %w", err)
	}

	rows := []userPublicKey{}
	err = db.Txn(ctx, func(ctx context.Context, tx *sqlair.TX) error {
		err := tx.Query(ctx, stmt).GetAll(&rows)
		if err != nil && !errors.Is(err, sqlair.ErrNoRows) {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	result := map[user.Name][]string{}
	for _, row := range rows {
		name, err := user.NewName(row.UserName)
		if err != nil {
			return nil, errors.Errorf("making user name from %q: %w", row.UserName, err)
		}
		result[name] = append(result[name], row.PublicKey)
	}
	return result, nil
}

// DeletePublicKeysForUser is responsible for removing keys from the user's
// list of public keys. keyIDs represent a key fingerprint, public key data, or
// comment.
// The following errors can be expected:
// - [accesserrors.UserNotFound] when the user does not exist.
func (s *State) DeletePublicKeysForUser(ctx context.Context, userUUID user.UUID, keyIDs []string) error {
	db, err := s.DB(ctx)
	if err != nil {
		return err
	}
	arg := userUUIDValue{UUID: userUUID.String()}
	input := make(sqlair.S, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		input = append(input, keyID)
	}
	stmt, err := s.Prepare(`
DELETE FROM user_public_ssh_key
WHERE user_uuid = $userUUIDValue.user_uuid
AND (comment IN ($S[:])
  OR fingerprint IN ($S[:])
  OR public_key IN ($S[:]))
`, arg, input)
	if err != nil {
		return errors.Errorf("preparing public key delete statement for user %q: %w", userUUID, err)
	}

	return db.Txn(ctx, func(ctx context.Context, tx *sqlair.TX) error {
		if err := s.checkUserExists(ctx, userUUID, tx); err != nil {
			return err
		}
		return tx.Query(ctx, stmt, arg, input).Run()
	})
}
