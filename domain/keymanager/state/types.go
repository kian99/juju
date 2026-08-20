// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package state

import "database/sql/driver"

// publicKey represents a single row from the user public key table.
type publicKey struct {
	Fingerprint string `db:"fingerprint"`
	PublicKey   string `db:"public_key"`
}

// userPublicKey represents a single user public key within the controller.
type userPublicKey struct {
	UserName  string `db:"name"`
	PublicKey string `db:"public_key"`
}

// userPublicKeyId represents a single raw user public key id from the database.
type userPublicKeyId struct {
	Id int64 `db:"id"`
}

// userPublicKeyInsert describes the data input needed for inserting new public
// keys for a user.
type userPublicKeyInsert struct {
	Comment                  string `db:"comment"`
	FingerprintHashAlgorithm string `db:"algorithm"`
	Fingerprint              string `db:"fingerprint"`
	PublicKey                string `db:"public_key"`
	UserId                   string `db:"user_uuid"`
}

// userUUIDValue represents a user id for associating public keys with.
type userUUIDValue struct {
	UUID string `db:"user_uuid"`
}

// Value returns the user id implementing the [driver.Valuer] interface.
func (u userPublicKeyId) Value() (driver.Value, error) {
	return u.Id, nil
}
