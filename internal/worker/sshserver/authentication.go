// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"context"
	"encoding/base64"

	"github.com/gliderlabs/ssh"
	"github.com/juju/errors"
	"github.com/lestrrat-go/jwx/v2/jwt"
	gossh "golang.org/x/crypto/ssh"

	"github.com/juju/juju/core/virtualhostname"
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

// AuthorizedKeyService resolves all authorized public keys for a target model.
type AuthorizedKeyService interface {
	AuthorizedKeys(context.Context, virtualhostname.Info) ([]gossh.PublicKey, error)
}

type authenticator struct {
	logger        Logger
	jwtParser     JWTParser
	keys          AuthorizedKeyService
	tunnelTracker TunnelAuthenticator
	metrics       *Collector
}

func (a authenticator) publicKeyAuthentication(ctx ssh.Context, _ ssh.PublicKey) bool {
	ctx.SetValue(authenticatedViaPublicKey{}, true)
	return true
}

func (a authenticator) passwordAuthentication(ctx ssh.Context, password string) bool {
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

func (a authenticator) newTerminatingServerAuthenticator(ctx ssh.Context, destination virtualhostname.Info) (terminatingServerAuthenticator, error) {
	publicKey, ok := ctx.Value(authenticatedViaPublicKey{}).(bool)
	if !ok {
		return terminatingServerAuthenticator{}, errors.New("SSH authentication method is missing from connection context")
	}

	result := terminatingServerAuthenticator{metrics: a.metrics}
	if publicKey {
		keys, err := a.keys.AuthorizedKeys(ctx, destination)
		if err != nil {
			return result, errors.Annotate(err, "getting model authorized keys")
		}
		result.keysToVerify = keys
		return result, nil
	}

	token, _ := ctx.Value(userJWT{}).(jwt.Token)
	if token == nil {
		return result, errors.New("SSH JWT is missing from connection context")
	}
	encodedKey, ok := token.PrivateClaims()["ssh_public_key"].(string)
	if !ok {
		return result, errors.New("SSH JWT does not contain an ssh_public_key claim")
	}
	keyData, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return result, errors.Annotate(err, "decoding SSH public key from JWT")
	}
	key, err := gossh.ParsePublicKey(keyData)
	if err != nil {
		return result, errors.Annotate(err, "parsing SSH public key from JWT")
	}
	result.keysToVerify = []gossh.PublicKey{key}
	return result, nil
}

type terminatingServerAuthenticator struct {
	keysToVerify []gossh.PublicKey
	metrics      *Collector
}

func (a terminatingServerAuthenticator) publicKeyAuthentication(_ ssh.Context, key ssh.PublicKey) bool {
	for _, expected := range a.keysToVerify {
		if ssh.KeysEqual(expected, key) {
			return true
		}
	}
	a.metrics.authenticationFailures.WithLabelValues("public_key").Inc()
	return false
}

const reverseTunnelUser = "juju-reverse-tunnel"
