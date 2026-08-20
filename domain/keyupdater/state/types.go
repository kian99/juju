// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package state

// keyValue represents a single row from the controllers config.
type keyValue struct {
	Key   string `db:"key"`
	Value string `db:"value"`
}

// machineName represents a single machine name
type machineName struct {
	Name string `db:"name"`
}
