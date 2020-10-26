// Copyright 2020 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package main

import (
	"time"

	"github.com/juju/cmd"
	"github.com/juju/errors"
	"github.com/juju/gnuflag"
	"github.com/juju/names/v4"

	"github.com/juju/juju/apiserver/params"
	jujucmd "github.com/juju/juju/cmd"
	"github.com/juju/juju/cmd/modelcmd"
	"github.com/juju/juju/cmd/plugins/juju-wait-for/api"
	"github.com/juju/juju/cmd/plugins/juju-wait-for/query"
	"github.com/juju/juju/core/life"
)

func newModelCommand() cmd.Command {
	cmd := &modelCommand{
		applications: make(map[string]*params.ApplicationInfo),
	}
	cmd.newWatchAllAPIFunc = func() (api.WatchAllAPI, error) {
		client, err := cmd.NewAPIClient()
		if err != nil {
			return nil, errors.Trace(err)
		}
		return watchAllAPIShim{
			Client: client,
		}, nil
	}
	return modelcmd.Wrap(cmd)
}

const modelCommandDoc = `
Wait for a given model to reach a goal state.

arguments:
name
   model name identifier

options:
--query (= 'life=="alive" && status=="available"')
   query represents the goal state of a given model
`

// modelCommand defines a command for waiting for models.
type modelCommand struct {
	waitForCommandBase

	name    string
	query   string
	timeout time.Duration
	found   bool

	applications map[string]*params.ApplicationInfo
}

// Info implements Command.Info.
func (c *modelCommand) Info() *cmd.Info {
	return jujucmd.Info(&cmd.Info{
		Name:    "model",
		Args:    "[<name>]",
		Purpose: "wait for an model to reach a goal state",
		Doc:     modelCommandDoc,
	})
}

// SetFlags implements Command.SetFlags.
func (c *modelCommand) SetFlags(f *gnuflag.FlagSet) {
	c.waitForCommandBase.SetFlags(f)
	f.StringVar(&c.query, "query", `life=="alive" && status=="available"`, "query the goal state")
	f.DurationVar(&c.timeout, "timeout", time.Minute*10, "how long to wait, before timing out")
}

// Init implements Command.Init.
func (c *modelCommand) Init(args []string) (err error) {
	if len(args) == 0 {
		return errors.New("model name must be supplied when waiting for an model")
	}
	if len(args) != 1 {
		return errors.New("only one model name can be supplied as an argument to this command")
	}
	if ok := names.IsValidModelName(args[0]); !ok {
		return errors.Errorf("%q is not valid model name", args[0])
	}
	c.name = args[0]

	return nil
}

func (c *modelCommand) Run(ctx *cmd.Context) error {
	strategy := &Strategy{
		ClientFn: c.newWatchAllAPIFunc,
		Timeout:  c.timeout,
	}
	strategy.Subscribe(func(event EventType) {
		switch event {
		case WatchAllStarted:
			// When a watch has started, we should prime all the local caches,
			// this means we should evict all items in the model and resync them
			// again.
		}
	})
	err := strategy.Run(c.name, c.query, c.waitFor)
	return errors.Trace(err)
}

func (c *modelCommand) waitFor(name string, deltas []params.Delta, q query.Query) (bool, error) {
	var modelUpdate *params.ModelUpdate
	for _, delta := range deltas {
		logger.Tracef("delta %T: %v", delta.Entity, delta.Entity)

		switch entityInfo := delta.Entity.(type) {
		case *params.ApplicationInfo:
			c.applications[entityInfo.Name] = entityInfo
		case *params.ModelUpdate:
			if entityInfo.Name == name {
				modelUpdate = entityInfo
				c.found = entityInfo.Life != life.Dead
			}
		}

		if modelUpdate != nil {
			scope := MakeModelScope(c, modelUpdate)
			if done, err := c.runModelQuery(q, scope); err != nil {
				return false, errors.Trace(err)
			} else if done {
				return true, nil
			}
		}
	}

	if !c.found {
		logger.Infof("model %q not found, waiting...", name)
		return false, nil
	}

	logger.Infof("model %q found, waiting...", name)
	return false, nil
}

func (c *modelCommand) runModelQuery(q query.Query, scope query.Scope) (bool, error) {
	fnScope := query.NewGlobalFuncScope(scope)
	fnScope.Add("applications", func(expr interface{}) (interface{}, error) {
		lambda, ok := expr.(*query.BoxLambda)
		if !ok {
			return nil, query.RuntimeErrorf("unexpected query %T", expr)
		}

		name := "applications"
		ord, err := scope.GetIdentValue(name)
		if err != nil {
			return nil, errors.Trace(err)
		}

		var (
			called bool
			result = true
		)
		ord.ForEach(func(value interface{}) bool {
			called = true

			newScope := scope.Clone()
			newScope.SetIdentValue(lambda.CallName(), value)

			var results []query.Box
			results, err = lambda.Call(newScope)
			if err != nil {
				return false
			}
			var lambdaResult bool
			for _, result := range results {
				lambdaResult = !result.IsZero()
			}
			result = result && lambdaResult
			return result
		})
		if err != nil {
			return nil, errors.Trace(err)
		}
		if !called {
			return false, nil
		}
		return result, nil
	})

	if res, err := q.Run(fnScope, scope); query.IsInvalidIdentifierErr(err) {
		return false, invalidIdentifierError(scope, err)
	} else if query.IsRuntimeError(err) {
		return false, errors.Trace(err)
	} else if res && err == nil {
		return true, nil
	} else if err != nil {
		logger.Errorf("%v", err)
	}
	return false, nil
}

// ModelScope allows the query to introspect a model entity.
type ModelScope struct {
	query.Scope
	ModelInfo *params.ModelUpdate
	Model     *modelCommand
}

// MakeModelScope creates an ModelScope from an ModelUpdate
func MakeModelScope(model *modelCommand, info *params.ModelUpdate) ModelScope {
	return ModelScope{
		Scope:     NewGenericScope(),
		ModelInfo: info,
		Model:     model,
	}
}

// GetIdents returns the identifiers with in a given scope.
func (m ModelScope) GetIdents() []string {
	return append(getIdents(m.ModelInfo), m.Scope.GetIdents()...)
}

// GetIdentValue returns the value of the identifier in a given scope.
func (m ModelScope) GetIdentValue(name string) (query.Box, error) {
	if box, err := m.Scope.GetIdentValue(name); err == nil {
		return box, nil
	}

	switch name {
	case "name":
		return query.NewString(m.ModelInfo.Name), nil
	case "life":
		return query.NewString(string(m.ModelInfo.Life)), nil
	case "is-controller":
		return query.NewBool(m.ModelInfo.IsController), nil
	case "status":
		return query.NewString(string(m.ModelInfo.Status.Current)), nil
	case "config":
		return query.NewMapStringInterface(m.ModelInfo.Config), nil
	case "applications":
		return NewApplications(m.Model.applications), nil
	}
	return nil, errors.Annotatef(query.ErrInvalidIdentifier(name), "Runtime Error: identifier %q not found on ModelInfo", name)
}

// Clone creates a new scope.
func (m ModelScope) Clone() query.Scope {
	x := m
	x.Scope = m.Scope.Clone()
	return x
}

// ApplicationsBox defines an ordered integer.
type ApplicationsBox struct {
	applications map[string]*params.ApplicationInfo
}

// NewApplications creates a new Box value
func NewApplications(applications map[string]*params.ApplicationInfo) *ApplicationsBox {
	return &ApplicationsBox{
		applications: applications,
	}
}

// Less checks if a ApplicationsBox is less than another ApplicationsBox.
func (o *ApplicationsBox) Less(other query.Box) bool {
	return false
}

// Equal checks if an ApplicationsBox is equal to another ApplicationsBox.
func (o *ApplicationsBox) Equal(other query.Box) bool {
	return false
}

// IsZero returns if the underlying value is zero.
func (o *ApplicationsBox) IsZero() bool {
	return len(o.applications) == 0
}

// Value defines the shadow type value of the Box.
func (o *ApplicationsBox) Value() interface{} {
	return o.applications
}

// ForEach iterates over each value in the box.
func (o *ApplicationsBox) ForEach(fn func(interface{}) bool) {
	for _, v := range o.applications {
		if !fn(v) {
			return
		}
	}
}
