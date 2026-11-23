// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package dbaccessor

import (
	"context"
	"database/sql"

	"github.com/juju/juju/core/database"
	"github.com/juju/juju/internal/errors"
)

const openFGADatabase = "openfga"

// OpenFGADBOpener opens a caller-owned handle to the dedicated OpenFGA
// database. It does not expose Juju's tracked controller or model handles.
type OpenFGADBOpener interface {
	OpenOpenFGADB(context.Context) (*sql.DB, error)
}

// OpenOpenFGADB opens a separate pool on the controller's Dqlite cluster.
func (w *dbWorker) OpenOpenFGADB(ctx context.Context) (*sql.DB, error) {
	ctx, cancel := context.WithTimeout(w.catacomb.Context(ctx), dbOpenTimeout)
	defer cancel()
	select {
	case <-w.dbReady:
	case <-w.catacomb.Dying():
		return nil, database.ErrDBAccessorDying
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	w.mu.RLock()
	dbApp := w.dbApp
	w.mu.RUnlock()
	if dbApp == nil {
		return nil, database.ErrDBAccessorDying
	}
	db, err := dbApp.Open(ctx, openFGADatabase)
	if err != nil {
		return nil, errors.Errorf("opening OpenFGA database: %w", err)
	}
	return db, nil
}
