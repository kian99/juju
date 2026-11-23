// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package openfga embeds the upstream OpenFGA server and SQLite datastore
// against a dedicated Dqlite database. OpenFGA owns the schema, handle and
// transactions; Juju's transaction retries do not apply. There is no network
// endpoint, connection to Juju permissions, or backup/restore integration.
package openfga

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"

	"github.com/mattn/go-sqlite3"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/assets"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage"
	"github.com/openfga/openfga/pkg/storage/sqlcommon"
	fgasqlite "github.com/openfga/openfga/pkg/storage/sqlite"
	"github.com/pressly/goose/v3"

	"github.com/juju/juju/internal/database/driver"
)

// NewServer applies the upstream SQLite migrations and starts the embedded
// server. It takes ownership of db even on failure. Call Close on success.
func NewServer(ctx context.Context, db *sql.DB) (_ *server.Server, err error) {
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()
	if err := migrate(ctx, db); err != nil {
		return nil, fmt.Errorf("migrating OpenFGA database: %w", err)
	}

	ds, err := fgasqlite.NewWithDB(db, sqlcommon.NewConfig(),
		fgasqlite.WithErrorHandler(translateError),
		fgasqlite.WithBusyErrorChecker(isBusy),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OpenFGA datastore: %w", err)
	}
	ready, err := ds.IsReady(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking OpenFGA datastore: %w", err)
	}
	if !ready.IsReady {
		return nil, fmt.Errorf("OpenFGA datastore is not ready: %s", ready.Message)
	}

	return server.NewServerWithOpts(
		server.WithContext(ctx),
		server.WithDatastore(ds),
		server.WithContextPropagationToDatastore(true),
		server.WithCheckQueryCacheEnabled(false),
		server.WithCheckIteratorCacheEnabled(false),
		server.WithListObjectsIteratorCacheEnabled(false),
		server.WithCacheControllerEnabled(false),
		server.WithSharedIteratorEnabled(false),
	)
}

func migrate(ctx context.Context, db *sql.DB) error {
	migrations, err := fs.Sub(assets.EmbedMigrations, assets.SqliteMigrationDir)
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}

// translateError mirrors OpenFGA's SQLite constraint handling for Dqlite
// errors, which the default modernc-based handler does not recognise.
func translateError(err error, args ...any) error {
	if code, ok := dqliteCode(err); ok && code == sqlite3.ErrConstraint {
		// The hook accepts a tuple key as optional context for a duplicate
		// tuple error. The pinned SQLite backend's batch insert passes no key
		// and relies on ErrCollision to report a concurrent write conflict.
		if len(args) > 0 {
			if key, ok := args[0].(*openfgav1.TupleKey); ok {
				return storage.InvalidWriteInputError(key, openfgav1.TupleOperation_TUPLE_OPERATION_WRITE)
			}
		}
		return fmt.Errorf("%w: %w", storage.ErrCollision, err)
	}
	// Keep the upstream mapping for sql.ErrNoRows and wrap other SQL errors
	// without losing their original cause.
	return fgasqlite.HandleSQLError(err, args...)
}

// isBusy classifies errors at OpenFGA's existing retry sites. It does not
// replay the enclosing transaction.
func isBusy(err error) bool {
	code, ok := dqliteCode(err)
	return ok && (code == sqlite3.ErrBusy || code == sqlite3.ErrLocked)
}

func dqliteCode(err error) (sqlite3.ErrNo, bool) {
	var dqliteErr driver.Error
	if !errors.As(err, &dqliteErr) {
		return 0, false
	}
	// SQLite stores the primary result code in the low byte. For example,
	// SQLITE_CONSTRAINT_UNIQUE and SQLITE_CONSTRAINT_PRIMARYKEY both reduce
	// to SQLITE_CONSTRAINT; the upper bits identify the specific violation.
	return sqlite3.ErrNo(dqliteErr.Code & 0xff), true
}
