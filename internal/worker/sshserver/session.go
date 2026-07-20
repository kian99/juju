// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"context"

	"github.com/gliderlabs/ssh"
	"github.com/juju/errors"
	gossh "golang.org/x/crypto/ssh"

	"github.com/juju/juju/core/model"
	"github.com/juju/juju/core/virtualhostname"
)

type connectionStartTime struct{}

// SessionHandler is the legacy, test-only seam for a terminating session
// handler. The production server uses ProxyFactory and target-specific
// handlers instead.
type SessionHandler interface {
	Handle(ssh.Session, virtualhostname.Info)
}

// stubSessionHandler is retained only for existing worker lifecycle tests.
// Production session handling is created by ProxyFactory.
type stubSessionHandler struct{}

func (*stubSessionHandler) Handle(ssh.Session, virtualhostname.Info) {}

type sessionHandlerProxy struct {
	handler     SessionHandler
	destination virtualhostname.Info
}

func (p sessionHandlerProxy) SessionHandler(session ssh.Session) {
	p.handler.Handle(session, p.destination)
}

func (sessionHandlerProxy) DirectTCPIPHandler() ssh.ChannelHandler {
	return func(_ *ssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, _ ssh.Context) {
		_ = newChan.Reject(gossh.Prohibited, "not implemented")
	}
}

func (sessionHandlerProxy) SFTPHandler() ssh.SubsystemHandler {
	return func(session ssh.Session) {
		_, _ = session.Stderr().Write([]byte("not implemented\n"))
		_ = session.Exit(1)
	}
}

// SSHConnector is retained for focused unit tests of the machine session
// bridge. Production proxying uses handlers/machine through ProxyFactory.
type SSHConnector interface {
	Connect(virtualhostname.Info) (*gossh.Client, error)
}

type sessionHandler struct {
	connector SSHConnector
	modelType model.ModelType
	logger    Logger
}

func (s *sessionHandler) Handle(session ssh.Session, destination virtualhostname.Info) {
	if s.modelType != model.IAAS {
		_, _ = session.Stderr().Write([]byte("unsupported model type\n"))
		_ = session.Exit(1)
		return
	}
	if err := s.machineSessionProxy(session, destination); err != nil {
		s.logger.Errorf(context.Background(), "machine session proxy failure: %v", err)
		_, _ = session.Stderr().Write([]byte("failed to proxy machine session: " + err.Error() + "\n"))
		_ = session.Exit(1)
	}
}

func (s *sessionHandler) machineSessionProxy(userSession ssh.Session, destination virtualhostname.Info) error {
	client, err := s.connector.Connect(destination)
	if err != nil {
		return err
	}
	defer client.Close()

	machineSession, err := client.NewSession()
	if err != nil {
		return err
	}
	defer machineSession.Close()
	machineSession.Stdin = userSession
	machineSession.Stdout = userSession
	machineSession.Stderr = userSession.Stderr()
	if err := setupLegacyShellOrCommand(userSession, machineSession); err != nil {
		return err
	}
	return machineSession.Wait()
}

func setupLegacyShellOrCommand(userSession ssh.Session, machineSession *gossh.Session) error {
	pty, windowChanges, hasPTY := userSession.Pty()
	if !hasPTY {
		return machineSession.Start(userSession.RawCommand())
	}
	if err := machineSession.RequestPty(pty.Term, pty.Window.Height, pty.Window.Width, gossh.TerminalModes{gossh.ECHO: 1}); err != nil {
		return errors.Trace(err)
	}
	if err := machineSession.Shell(); err != nil {
		return errors.Trace(err)
	}
	go func() {
		for window := range windowChanges {
			_ = machineSession.WindowChange(window.Height, window.Width)
		}
	}()
	return nil
}
