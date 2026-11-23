//go:build dqlite && linux

// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package app

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
)

// OpenImmediate opens a caller-owned pool that reserves the writer slot at
// the start of each explicit transaction. Use it for write transactions only.
func (a *App) OpenImmediate(ctx context.Context, name string) (*sql.DB, error) {
	// App exposes the registered driver name, not the driver itself. sql.Open
	// obtains the driver without opening a network connection.
	db, err := sql.Open(a.Driver(), name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	dqliteDriver, ok := db.Driver().(driver.DriverContext)
	if !ok {
		return nil, fmt.Errorf("Dqlite driver %T does not support connectors", db.Driver())
	}
	connector, err := dqliteDriver.OpenConnector(name)
	if err != nil {
		return nil, err
	}
	immediate := sql.OpenDB(ImmediateTransactions(connector))
	if err := immediate.PingContext(ctx); err != nil {
		_ = immediate.Close()
		return nil, err
	}
	return immediate, nil
}

// ImmediateTransactions adapts a Dqlite connector to begin write transactions
// with BEGIN IMMEDIATE. Queries outside an explicit transaction are unchanged.
func ImmediateTransactions(connector driver.Connector) driver.Connector {
	return immediateConnector{Connector: connector}
}

type immediateConnector struct {
	driver.Connector
}

func (c immediateConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	dqliteConn, ok := conn.(contextConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("Dqlite connection %T lacks context-aware SQL methods", conn)
	}
	return immediateConn{contextConn: dqliteConn}, nil
}

type contextConn interface {
	driver.Conn
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
}

type immediateConn struct {
	contextConn
}

func (c immediateConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c immediateConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if opts.ReadOnly {
		return nil, fmt.Errorf("immediate Dqlite transactions do not support read-only mode")
	}
	// OpenFGA requests ReadCommitted; Dqlite's own BeginTx ignores the
	// isolation option. Keep Dqlite's isolation semantics for both modes.
	if opts.Isolation != driver.IsolationLevel(sql.LevelDefault) && opts.Isolation != driver.IsolationLevel(sql.LevelReadCommitted) {
		return nil, fmt.Errorf("unsupported Dqlite isolation level %d", opts.Isolation)
	}
	if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE", nil); err != nil {
		return nil, err
	}
	return immediateTx{conn: c.contextConn}, nil
}

// Finish on the same connection using the driver.Tx API, which has no context.
// Like the Dqlite driver, use a background context for rollback after the
// transaction context has been cancelled.
type immediateTx struct {
	conn driver.ExecerContext
}

func (tx immediateTx) Commit() error {
	_, err := tx.conn.ExecContext(context.Background(), "COMMIT", nil)
	return err
}

func (tx immediateTx) Rollback() error {
	_, err := tx.conn.ExecContext(context.Background(), "ROLLBACK", nil)
	return err
}
