// Copyright 2017 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package state_test

import (
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"

	"github.com/juju/errors"
	"github.com/juju/juju/state"
	"github.com/juju/juju/testing"
)

type offerConnectionsSuite struct {
	ConnSuite
}

var _ = gc.Suite(&offerConnectionsSuite{})

func (s *offerConnectionsSuite) TestAddOfferConnection(c *gc.C) {
	oc, err := s.State.AddOfferConnection(state.AddOfferConnectionParams{
		SourceModelUUID: testing.ModelTag.Id(),
		RelationId:      1,
		Username:        "fred",
		OfferName:       "mysql",
	})
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(oc.SourceModelUUID(), gc.Equals, testing.ModelTag.Id())
	c.Assert(oc.RelationId(), gc.Equals, 1)
	c.Assert(oc.OfferName(), gc.Equals, "mysql")
	c.Assert(oc.UserName(), gc.Equals, "fred")

	anotherState, err := s.State.ForModel(s.State.ModelTag())
	c.Assert(err, jc.ErrorIsNil)
	defer anotherState.Close()

	rc, err := anotherState.RemoteConnectionStatus("mysql")
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(rc.ConnectionCount(), gc.Equals, 1)

	all, err := anotherState.AllOfferConnections()
	c.Assert(err, jc.ErrorIsNil)
	c.Assert(all, gc.HasLen, 1)
	c.Assert(all[0].SourceModelUUID(), gc.Equals, testing.ModelTag.Id())
	c.Assert(all[0].RelationId(), gc.Equals, 1)
	c.Assert(all[0].OfferName(), gc.Equals, "mysql")
	c.Assert(all[0].UserName(), gc.Equals, "fred")
	c.Assert(all[0].String(), gc.Equals, `connection to "mysql" by "fred" for relation 1`)
}

func (s *offerConnectionsSuite) TestAddOfferConnectionTwice(c *gc.C) {
	_, err := s.State.AddOfferConnection(state.AddOfferConnectionParams{
		SourceModelUUID: testing.ModelTag.Id(),
		RelationId:      1,
		Username:        "fred",
		OfferName:       "mysql",
	})
	c.Assert(err, jc.ErrorIsNil)

	anotherState, err := s.State.ForModel(s.State.ModelTag())
	c.Assert(err, jc.ErrorIsNil)
	defer anotherState.Close()

	_, err = anotherState.AddOfferConnection(state.AddOfferConnectionParams{
		SourceModelUUID: testing.ModelTag.Id(),
		RelationId:      1,
		Username:        "fred",
		OfferName:       "mysql",
	})
	c.Assert(err, jc.Satisfies, errors.IsAlreadyExists)
}
