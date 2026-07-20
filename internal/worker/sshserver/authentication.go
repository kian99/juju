// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"context"

	"github.com/gliderlabs/ssh"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type authenticatedViaPublicKey struct{}

type userJWT struct{}
type tunnelIDKey struct{}

const jimmUser = "jimm"

// JWTParser parses JIMM's encoded JWT password authentication payload.
type JWTParser interface {
	Parse(context.Context, string) (jwt.Token, error)
}

// TunnelAuthenticator authenticates machine reverse-tunnel connections.
type TunnelAuthenticator interface {
	AuthenticateTunnel(username, password string) (string, error)
}

// Authenticator authenticates jump SSH connections.
type Authenticator interface {
	PublicKeyAuthentication(ssh.Context, ssh.PublicKey) bool
	PasswordAuthentication(ssh.Context, string) bool
}

type authenticator struct {
	logger        Logger
	jwtParser     JWTParser
	tunnelTracker TunnelAuthenticator
	metrics       *Collector
}

func (a authenticator) PublicKeyAuthentication(ctx ssh.Context, _ ssh.PublicKey) bool {
	ctx.SetValue(authenticatedViaPublicKey{}, true)
	return true
}

func (a authenticator) PasswordAuthentication(ctx ssh.Context, password string) bool {
	ctx.SetValue(authenticatedViaPublicKey{}, false)

	authMethod := "password"
	switch ctx.User() {
	case jimmUser:
		authMethod = "jwt"
		token, err := a.jwtParser.Parse(ctx, password)
		if err != nil {
			a.logger.Errorf(ctx, "parsing SSH JWT: %v", err)
			break
		}
		ctx.SetValue(userJWT{}, token)
		return true
	case reverseTunnelUser:
		authMethod = "tunnel"
		tunnelID, err := a.tunnelTracker.AuthenticateTunnel(ctx.User(), password)
		if err != nil {
			a.logger.Errorf(ctx, "authenticating reverse SSH tunnel: %v", err)
			break
		}
		ctx.SetValue(tunnelIDKey{}, tunnelID)
		return true
	}
	a.metrics.authenticationFailures.WithLabelValues(authMethod).Inc()
	return false
}

const reverseTunnelUser = "juju-reverse-tunnel"
