// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

func DisableAuth() ServerOption {
	return func(b *ServerBuilder) {
		b.server.PublicKeyHandler = nil
		b.server.PasswordHandler = nil
	}
}
