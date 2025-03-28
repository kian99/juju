// Copyright 2025 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import "github.com/gliderlabs/ssh"

type ServerBuilder struct {
	server *ssh.Server
}

type ServerOption func(*ServerBuilder)

func NewServerBuilder(options ...ServerOption) *ServerBuilder {
	b := &ServerBuilder{
		server: &ssh.Server{
			ChannelHandlers: make(map[string]ssh.ChannelHandler),
		},
	}
	for _, option := range options {
		option(b)
	}
	return b
}

func WithConnCallback(callback ssh.ConnCallback) ServerOption {
	return func(b *ServerBuilder) {
		b.server.ConnCallback = callback
	}
}

func WithPublicKeyAuth(handler ssh.PublicKeyHandler) ServerOption {
	return func(b *ServerBuilder) {
		b.server.PublicKeyHandler = handler
	}
}

func WithPasswordAuth(handler ssh.PasswordHandler) ServerOption {
	return func(b *ServerBuilder) {
		b.server.PasswordHandler = handler
	}
}

func WithChannelHandler(name string, handler ssh.ChannelHandler) ServerOption {
	return func(b *ServerBuilder) {
		b.server.ChannelHandlers[name] = handler
	}
}

func (b *ServerBuilder) Build() *ssh.Server {
	return b.server
}
