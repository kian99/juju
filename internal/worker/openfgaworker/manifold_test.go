//go:build dqlite && linux

// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package openfgaworker_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	dqlitedriver "github.com/canonical/go-dqlite/v3/driver"
	"github.com/juju/tc"
	"github.com/juju/worker/v5"
	dt "github.com/juju/worker/v5/dependency/testing"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/typesystem"

	"github.com/juju/juju/internal/database/app"
	coretesting "github.com/juju/juju/internal/testing"
	"github.com/juju/juju/internal/uuid"
	"github.com/juju/juju/internal/worker/openfgaworker"
)

type openFGASuite struct {
	coretesting.BaseSuite
}

func TestOpenFGASuite(t *testing.T) {
	tc.Run(t, &openFGASuite{})
}

func (s *openFGASuite) TestGrantSurvivesRestart(c *tc.C) {
	dir := c.MkDir()
	address := "@" + uuid.MustNewUUID().String()
	node, w, srv := start(c, dir, address)

	ctx := c.Context()
	check := newGrantCheck(c, srv, "user:alice")
	result, err := srv.Check(ctx, check)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(result.GetAllowed(), tc.IsFalse)

	_, err = srv.Write(ctx, grantWrite(check, "user:alice"))
	c.Assert(err, tc.ErrorIsNil)
	result, err = srv.Check(ctx, check)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(result.GetAllowed(), tc.IsTrue)

	c.Assert(worker.Stop(w), tc.ErrorIsNil)
	c.Assert(node.Close(), tc.ErrorIsNil)
	_, _, srv = start(c, dir, address)

	result, err = srv.Check(ctx, check)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(result.GetAllowed(), tc.IsTrue)
	changes, err := srv.ReadChanges(ctx, &openfgav1.ReadChangesRequest{StoreId: check.GetStoreId(), Type: "document"})
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(changes.GetChanges(), tc.HasLen, 1)
	c.Check(changes.GetChanges()[0].GetTupleKey().GetUser(), tc.Equals, "user:alice")
	c.Check(changes.GetChanges()[0].GetOperation(), tc.Equals, openfgav1.TupleOperation_TUPLE_OPERATION_WRITE)
}

func (s *openFGASuite) TestGrantRetriesAtBeginWhenWriterSlotIsReserved(c *tc.C) {
	ctx := c.Context()
	node := startNode(c, c.MkDir(), "@"+uuid.MustNewUUID().String(), app.WithBusyTimeout(5*time.Millisecond))
	_, srv := startOpenFGA(c, openImmediate(node))
	check := newGrantCheck(c, srv, "user:alice")
	grant := grantWrite(check, "user:alice")

	holder, err := node.OpenImmediate(ctx, "openfga")
	c.Assert(err, tc.ErrorIsNil)
	defer holder.Close()
	tx, err := holder.BeginTx(ctx, nil)
	c.Assert(err, tc.ErrorIsNil)
	defer tx.Rollback()

	// The holder has not written anything. It already has the writer slot,
	// so the grant hits OpenFGA's begin retry rather than failing at INSERT.
	_, err = srv.Write(ctx, grant)
	var dqliteErr dqlitedriver.Error
	c.Assert(errors.As(err, &dqliteErr), tc.IsTrue, tc.Commentf("write error: %v", err))
	c.Check(dqliteErr.Code, tc.Equals, dqlitedriver.ErrBusy)
	c.Check(errors.Unwrap(err), tc.ErrorMatches, `.*sqlite busy error after [0-9]+ retries:.*`)
	checkGrantRows(c, tx, 0)

	c.Assert(tx.Rollback(), tc.ErrorIsNil)
	_, err = srv.Write(ctx, grant)
	c.Assert(err, tc.ErrorIsNil)
	checkGrantRows(c, holder, 1)
}

func (s *openFGASuite) TestBusyCommitLeavesTransactionOnPooledConnection(c *tc.C) {
	ctx := c.Context()
	node := startNode(c, c.MkDir(), "@"+uuid.MustNewUUID().String())
	observer, err := node.Open(ctx, "openfga")
	c.Assert(err, tc.ErrorIsNil)
	c.Cleanup(func() { c.Check(observer.Close(), tc.ErrorIsNil) })
	connector, err := observer.Driver().(driver.DriverContext).OpenConnector("openfga")
	c.Assert(err, tc.ErrorIsNil)
	fault := &busyCommitConnector{Connector: connector}
	db := sql.OpenDB(app.ImmediateTransactions(fault))
	db.SetMaxOpenConns(1)
	c.Cleanup(func() { c.Check(db.Close(), tc.ErrorIsNil) })
	_, srv := startOpenFGA(c, func(context.Context) (*sql.DB, error) { return db, nil })
	check := newGrantCheck(c, srv, "user:alice")
	aliceGrant := grantWrite(check, "user:alice")
	bobGrant := grantWrite(check, "user:bob")

	fault.failNextCommit.Store(true)
	_, err = srv.Write(ctx, aliceGrant)
	c.Assert(err, tc.ErrorIs, sql.ErrTxDone)
	c.Check(fault.failNextCommit.Load(), tc.IsFalse)

	// Compare a separate connection with the pool that attempted the grant.
	// Only the pooled connection should still see the uncommitted rows.
	checkGrantRows(c, observer, 0)
	checkGrantRows(c, db, 1)

	_, err = srv.Write(ctx, bobGrant)
	var dqliteErr dqlitedriver.Error
	c.Assert(errors.As(err, &dqliteErr), tc.IsTrue, tc.Commentf("write error: %v", err))
	c.Check(dqliteErr.Message, tc.Equals, "cannot start a transaction within a transaction")
	originalConnections := fault.connections.Load()

	// Recycle the connection and try the same write again.
	db.SetMaxIdleConns(0)
	db.SetMaxIdleConns(1)
	_, err = srv.Write(ctx, bobGrant)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(fault.connections.Load() > originalConnections, tc.IsTrue)
	checkGrantRows(c, observer, 1)
	result, err := srv.Check(ctx, check)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(result.GetAllowed(), tc.IsFalse)
}

func checkGrantRows(c *tc.C, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, want int) {
	var tuples, changes int
	err := db.QueryRowContext(c.Context(), `SELECT
		(SELECT COUNT(*) FROM tuple),
		(SELECT COUNT(*) FROM changelog)`).Scan(&tuples, &changes)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(tuples, tc.Equals, want, tc.Commentf("tuple rows"))
	c.Check(changes, tc.Equals, want, tc.Commentf("changelog rows"))
}

func newGrantCheck(c *tc.C, srv *server.Server, user string) *openfgav1.CheckRequest {
	ctx := c.Context()
	store, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "juju-prototype"})
	c.Assert(err, tc.ErrorIsNil)
	c.Check(store.GetCreatedAt().IsValid(), tc.IsTrue)
	model, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
		StoreId: store.GetId(), SchemaVersion: "1.1",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{Type: "user"},
			{
				Type:      "document",
				Relations: map[string]*openfgav1.Userset{"viewer": typesystem.This()},
				Metadata: &openfgav1.Metadata{Relations: map[string]*openfgav1.RelationMetadata{
					"viewer": {DirectlyRelatedUserTypes: []*openfgav1.RelationReference{typesystem.DirectRelationReference("user", "")}},
				}},
			},
		},
	})
	c.Assert(err, tc.ErrorIsNil)

	return &openfgav1.CheckRequest{
		StoreId:              store.GetId(),
		AuthorizationModelId: model.GetAuthorizationModelId(),
		TupleKey:             &openfgav1.CheckRequestTupleKey{User: user, Relation: "viewer", Object: "document:report"},
	}
}

func grantWrite(check *openfgav1.CheckRequest, user string) *openfgav1.WriteRequest {
	return &openfgav1.WriteRequest{
		StoreId:              check.GetStoreId(),
		AuthorizationModelId: check.GetAuthorizationModelId(),
		Writes: &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{
			{User: user, Relation: check.GetTupleKey().GetRelation(), Object: check.GetTupleKey().GetObject()},
		}},
	}
}

func start(c *tc.C, dir, address string) (*app.App, worker.Worker, *server.Server) {
	node := startNode(c, dir, address)
	w, srv := startOpenFGA(c, openImmediate(node))
	return node, w, srv
}

func openImmediate(node *app.App) dbOpener {
	return func(ctx context.Context) (*sql.DB, error) {
		return node.OpenImmediate(ctx, "openfga")
	}
}

func startNode(c *tc.C, dir, address string, opts ...app.Option) *app.App {
	node, err := app.New(dir, append(opts, app.WithAddress(address))...)
	c.Assert(err, tc.ErrorIsNil)
	c.Cleanup(func() { c.Check(node.Close(), tc.ErrorIsNil) })
	c.Assert(node.Ready(c.Context()), tc.ErrorIsNil)
	return node
}

func startOpenFGA(c *tc.C, opener dbOpener) (worker.Worker, *server.Server) {
	manifold := openfgaworker.Manifold("db-accessor")
	w, err := manifold.Start(c.Context(), dt.StubGetter(map[string]any{"db-accessor": opener}))
	c.Assert(err, tc.ErrorIsNil)
	c.Cleanup(func() { c.Check(worker.Stop(w), tc.ErrorIsNil) })
	var srv *server.Server
	c.Assert(manifold.Output(w, &srv), tc.ErrorIsNil)
	return w, srv
}

type dbOpener func(context.Context) (*sql.DB, error)

func (o dbOpener) OpenOpenFGADB(ctx context.Context) (*sql.DB, error) {
	return o(ctx)
}

type busyCommitConnector struct {
	driver.Connector
	failNextCommit atomic.Bool
	connections    atomic.Int32
}

func (c *busyCommitConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	c.connections.Add(1)
	return &busyCommitConn{Conn: conn.(*dqlitedriver.Conn), failNextCommit: &c.failNextCommit}, nil
}

type busyCommitConn struct {
	*dqlitedriver.Conn
	failNextCommit *atomic.Bool
}

func (c *busyCommitConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if query == "COMMIT" && c.failNextCommit.Swap(false) {
		// Simulate the gateway rejecting COMMIT before executing it. The
		// preceding SQL and the open transaction are real Dqlite state.
		return nil, dqlitedriver.Error{Code: dqlitedriver.ErrBusy, Message: "checkpoint in progress"}
	}
	return c.Conn.ExecContext(ctx, query, args)
}
