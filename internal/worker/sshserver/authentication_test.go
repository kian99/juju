// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/gliderlabs/ssh"
	"github.com/juju/tc"
	"github.com/lestrrat-go/jwx/v2/jwt"
	gossh "golang.org/x/crypto/ssh"

	"github.com/juju/juju/core/virtualhostname"
	loggertesting "github.com/juju/juju/internal/logger/testing"
)

type authenticationSuite struct{}

func TestAuthenticationSuite(t *testing.T) {
	tc.Run(t, &authenticationSuite{})
}

func (s *authenticationSuite) TestTerminatingAuthenticatorUsesJWTKey(c *tc.C) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, tc.ErrorIsNil)
	signer, err := gossh.NewSignerFromKey(privateKey)
	c.Assert(err, tc.ErrorIsNil)

	token, err := jwt.NewBuilder().Claim(
		"ssh_public_key", base64.StdEncoding.EncodeToString(signer.PublicKey().Marshal()),
	).Build()
	c.Assert(err, tc.ErrorIsNil)
	ctx := &authenticationContext{values: map[any]any{
		authenticatedViaPublicKey{}: false,
		userJWT{}:                   token,
	}}

	auth := authenticator{metrics: NewMetricsCollector()}
	terminating, err := auth.newTerminatingServerAuthenticator(ctx, virtualhostname.Info{})
	c.Assert(err, tc.ErrorIsNil)
	c.Check(terminating.publicKeyAuthentication(ctx, ssh.PublicKey(signer.PublicKey())), tc.IsTrue)
}

func (s *authenticationSuite) TestPasswordAuthenticationRejectsUnexpectedUser(c *tc.C) {
	ctx := &authenticationContext{user: "alice", values: map[any]any{}}
	auth := authenticator{
		logger:  loggertesting.WrapCheckLog(c),
		metrics: NewMetricsCollector(),
	}
	c.Check(auth.passwordAuthentication(ctx, "not-a-token"), tc.IsFalse)
	c.Check(ctx.values[authenticatedViaPublicKey{}], tc.Equals, false)
}

func (s *authenticationSuite) TestPublicKeyAuthenticationMarksConnection(c *tc.C) {
	ctx := &authenticationContext{values: map[any]any{}}

	auth := authenticator{metrics: NewMetricsCollector()}
	c.Check(auth.publicKeyAuthentication(ctx, nil), tc.IsTrue)
	c.Check(ctx.values[authenticatedViaPublicKey{}], tc.Equals, true)
}

func (s *authenticationSuite) TestTerminatingAuthenticatorRejectsUnknownKey(c *tc.C) {
	expectedPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, tc.ErrorIsNil)
	presentedPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, tc.ErrorIsNil)
	expected, err := gossh.NewSignerFromKey(expectedPrivateKey)
	c.Assert(err, tc.ErrorIsNil)
	presented, err := gossh.NewSignerFromKey(presentedPrivateKey)
	c.Assert(err, tc.ErrorIsNil)

	auth := terminatingServerAuthenticator{
		keysToVerify: []gossh.PublicKey{expected.PublicKey()},
		metrics:      NewMetricsCollector(),
	}
	c.Check(auth.publicKeyAuthentication(nil, ssh.PublicKey(presented.PublicKey())), tc.IsFalse)
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
