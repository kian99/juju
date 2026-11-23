// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package openfgaworker manages the embedded OpenFGA prototype in Juju's
// controller. It does not expose an OpenFGA network endpoint.
package openfgaworker

import (
	"context"
	"fmt"

	"github.com/juju/worker/v5"
	"github.com/juju/worker/v5/catacomb"
	"github.com/juju/worker/v5/dependency"
	"github.com/openfga/openfga/pkg/server"

	"github.com/juju/juju/internal/database/dqlite"
	"github.com/juju/juju/internal/openfga"
	"github.com/juju/juju/internal/worker/dbaccessor"
)

// Manifold opens the dedicated OpenFGA database and manages the embedded server.
// The caller must restrict startup to the primary controller to serialize
// schema migrations.
func Manifold(dbAccessorName string) dependency.Manifold {
	return dependency.Manifold{
		Inputs: []string{dbAccessorName},
		Start: func(ctx context.Context, getter dependency.Getter) (worker.Worker, error) {
			if !dqlite.Enabled {
				return nil, dependency.ErrMissing
			}
			var opener dbaccessor.OpenFGADBOpener
			if err := getter.Get(dbAccessorName, &opener); err != nil {
				return nil, err
			}
			return start(ctx, opener)
		},
		Output: func(in worker.Worker, out any) error {
			w, ok := in.(*openFGAWorker)
			if !ok {
				return fmt.Errorf("expected OpenFGA worker, got %T", in)
			}
			target, ok := out.(**server.Server)
			if !ok {
				return fmt.Errorf("unsupported OpenFGA output type %T", out)
			}
			*target = w.server
			return nil
		},
	}
}

type openFGAWorker struct {
	catacomb catacomb.Catacomb
	server   *server.Server
}

func start(ctx context.Context, opener dbaccessor.OpenFGADBOpener) (worker.Worker, error) {
	db, err := opener.OpenOpenFGADB(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	srv, err := openfga.NewServer(ctx, db)
	if err != nil {
		cancel()
		return nil, err
	}
	w := &openFGAWorker{server: srv}
	if err := catacomb.Invoke(catacomb.Plan{
		Name: "openfga",
		Site: &w.catacomb,
		Work: func() error {
			<-w.catacomb.Dying()
			cancel()
			srv.Close()
			return w.catacomb.ErrDying()
		},
	}); err != nil {
		cancel()
		srv.Close()
		return nil, err
	}
	return w, nil
}

func (w *openFGAWorker) Kill()       { w.catacomb.Kill(nil) }
func (w *openFGAWorker) Wait() error { return w.catacomb.Wait() }

// Report identifies the database used by the running prototype.
func (w *openFGAWorker) Report(context.Context) map[string]any {
	return map[string]any{"storage": "dqlite"}
}
