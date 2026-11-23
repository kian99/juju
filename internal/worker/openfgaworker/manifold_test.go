//go:build dqlite && linux

// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package openfgaworker_test

import (
	"context"
	"database/sql"
	"testing"

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

	check := &openfgav1.CheckRequest{
		StoreId:              store.GetId(),
		AuthorizationModelId: model.GetAuthorizationModelId(),
		TupleKey:             &openfgav1.CheckRequestTupleKey{User: "user:alice", Relation: "viewer", Object: "document:report"},
	}
	result, err := srv.Check(ctx, check)
	c.Assert(err, tc.ErrorIsNil)
	c.Check(result.GetAllowed(), tc.IsFalse)

	_, err = srv.Write(ctx, &openfgav1.WriteRequest{
		StoreId:              check.GetStoreId(),
		AuthorizationModelId: check.GetAuthorizationModelId(),
		Writes: &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{
			{User: check.GetTupleKey().GetUser(), Relation: check.GetTupleKey().GetRelation(), Object: check.GetTupleKey().GetObject()},
		}},
	})
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
	changes, err := srv.ReadChanges(ctx, &openfgav1.ReadChangesRequest{StoreId: store.GetId(), Type: "document"})
	c.Assert(err, tc.ErrorIsNil)
	c.Assert(changes.GetChanges(), tc.HasLen, 1)
	c.Check(changes.GetChanges()[0].GetTupleKey().GetUser(), tc.Equals, "user:alice")
	c.Check(changes.GetChanges()[0].GetOperation(), tc.Equals, openfgav1.TupleOperation_TUPLE_OPERATION_WRITE)
}

func start(c *tc.C, dir, address string) (*app.App, worker.Worker, *server.Server) {
	node, err := app.New(dir, app.WithAddress(address))
	c.Assert(err, tc.ErrorIsNil)
	c.Cleanup(func() { c.Check(node.Close(), tc.ErrorIsNil) })
	c.Assert(node.Ready(c.Context()), tc.ErrorIsNil)

	manifold := openfgaworker.Manifold("db-accessor")
	w, err := manifold.Start(c.Context(), dt.StubGetter(map[string]any{"db-accessor": dbOpener{node}}))
	c.Assert(err, tc.ErrorIsNil)
	c.Cleanup(func() { c.Check(worker.Stop(w), tc.ErrorIsNil) })
	var srv *server.Server
	c.Assert(manifold.Output(w, &srv), tc.ErrorIsNil)
	return node, w, srv
}

type dbOpener struct{ node *app.App }

func (o dbOpener) OpenOpenFGADB(ctx context.Context) (*sql.DB, error) {
	return o.node.Open(ctx, "openfga")
}
