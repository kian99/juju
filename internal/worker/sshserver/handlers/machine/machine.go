// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package machine

import (
	"context"

	"github.com/gliderlabs/ssh"
	"github.com/juju/errors"
	gossh "golang.org/x/crypto/ssh"

	"github.com/juju/juju/core/virtualhostname"
)

// SSHConnector establishes SSH clients to routed machine targets.
type SSHConnector interface {
	Connect(context.Context, virtualhostname.Info) (*gossh.Client, error)
}

// Logger logs proxy failures.
type Logger interface {
	Errorf(context.Context, string, ...any)
}

// Handlers provides SSH channel handlers for a machine target.
type Handlers struct {
	connector   SSHConnector
	logger      Logger
	destination virtualhostname.Info
}

// NewHandlers returns handlers for a machine or machine-unit target.
func NewHandlers(destination virtualhostname.Info, connector SSHConnector, logger Logger) (*Handlers, error) {
	if connector == nil {
		return nil, errors.NotValidf("connector is required")
	}
	if logger == nil {
		return nil, errors.NotValidf("logger is required")
	}
	if destination.Target() != virtualhostname.MachineTarget &&
		destination.Target() != virtualhostname.UnitTarget {
		return nil, errors.NotValidf("destination must be a machine or unit target")
	}
	return &Handlers{
		connector:   connector,
		logger:      logger,
		destination: destination,
	}, nil
}

// SessionHandler proxies a shell or command session to the target machine.
func (h *Handlers) SessionHandler(session ssh.Session) {
	handleError := func(err error) {
		h.logger.Errorf(session.Context(), "machine session proxy failure: %v", err)
		_, _ = session.Stderr().Write([]byte(err.Error() + "\n"))
		_ = session.Exit(1)
	}

	client, err := h.connector.Connect(session.Context(), h.destination)
	if err != nil {
		handleError(errors.Annotate(err, "connecting to machine"))
		return
	}
	defer client.Close()

	machineSession, err := client.NewSession()
	if err != nil {
		handleError(errors.Annotate(err, "creating SSH session to machine"))
		return
	}
	defer machineSession.Close()

	machineSession.Stdin = session
	machineSession.Stdout = session
	machineSession.Stderr = session.Stderr()

	if err := setupShellOrCommand(session, machineSession); err != nil {
		handleError(err)
		return
	}
	if err := machineSession.Wait(); err != nil {
		handleError(errors.Annotate(err, "waiting for SSH session to machine"))
	}
}

func setupShellOrCommand(userSession ssh.Session, machineSession *gossh.Session) error {
	pty, windowChanges, hasPTY := userSession.Pty()
	if !hasPTY {
		return machineSession.Start(userSession.RawCommand())
	}

	if err := machineSession.RequestPty(pty.Term, pty.Window.Height, pty.Window.Width, gossh.TerminalModes{
		gossh.ECHO: 1,
	}); err != nil {
		return err
	}
	if err := machineSession.Shell(); err != nil {
		return err
	}

	go func() {
		for window := range windowChanges {
			_ = machineSession.WindowChange(window.Height, window.Width)
		}
	}()
	return nil
}
