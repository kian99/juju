// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"testing"

	"github.com/gliderlabs/ssh"
	"github.com/juju/tc"

	loggertesting "github.com/juju/juju/internal/logger/testing"
)

type authenticationSuite struct{}

func TestAuthenticationSuite(t *testing.T) {
	tc.Run(t, &authenticationSuite{})
}

func (s *authenticationSuite) TestPasswordAuthenticationRejectsUnexpectedUser(c *tc.C) {
	ctx := &authenticationContext{user: "alice", values: map[any]any{}}
	auth := authenticator{
		logger:  loggertesting.WrapCheckLog(c),
		metrics: NewMetricsCollector(),
	}
	c.Check(auth.PasswordAuthentication(ctx, "not-a-token"), tc.IsFalse)
	c.Check(ctx.values[authenticatedViaPublicKey{}], tc.Equals, false)
}

func (s *authenticationSuite) TestPublicKeyAuthenticationMarksConnection(c *tc.C) {
	ctx := &authenticationContext{values: map[any]any{}}

	auth := authenticator{metrics: NewMetricsCollector()}
	c.Check(auth.PublicKeyAuthentication(ctx, nil), tc.IsTrue)
	c.Check(ctx.values[authenticatedViaPublicKey{}], tc.Equals, true)
}

type authenticationContext struct {
	ssh.Context
	user   string
	values map[any]any
}

func (c *authenticationContext) User() string {
	return c.user
}

func (c *authenticationContext) SetValue(key, value any) {
	c.values[key] = value
}

func (c *authenticationContext) Value(key any) any {
	return c.values[key]
}
