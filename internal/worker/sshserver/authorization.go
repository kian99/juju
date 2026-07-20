// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"context"

	"github.com/gliderlabs/ssh"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/juju/juju/core/permission"
	"github.com/juju/juju/core/virtualhostname"
)

// AccessService checks local user access to an SSH target.
type AccessService interface {
	HasSSHAccess(context.Context, string, virtualhostname.Info) (bool, error)
}

// Authorizer checks whether an authenticated user may access a destination.
type Authorizer interface {
	Authorize(ssh.Context, virtualhostname.Info) bool
}

type authorizer struct {
	access AccessService
	logger Logger
}

func (a authorizer) Authorize(ctx ssh.Context, destination virtualhostname.Info) bool {
	publicKey, ok := ctx.Value(authenticatedViaPublicKey{}).(bool)
	if !ok {
		a.logger.Errorf(ctx, "SSH authentication method is missing from connection context")
		return false
	}
	if publicKey {
		ok, err := a.access.HasSSHAccess(ctx, ctx.User(), destination)
		if err != nil {
			a.logger.Errorf(ctx, "checking SSH access: %v", err)
			return false
		}
		return ok
	}

	token, _ := ctx.Value(userJWT{}).(jwt.Token)
	if token == nil {
		a.logger.Errorf(ctx, "SSH JWT is missing from connection context")
		return false
	}

	claims, ok := token.PrivateClaims()["access"].(map[string]any)
	if !ok {
		return false
	}
	access, _ := claims["model-"+destination.ModelUUID().String()].(string)
	return permission.Access(access).EqualOrGreaterModelAccessThan(permission.AdminAccess)
}
