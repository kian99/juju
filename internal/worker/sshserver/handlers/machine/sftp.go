// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package machine

import (
	"io"
	"sync"

	"github.com/gliderlabs/ssh"
	"github.com/juju/errors"
	gossh "golang.org/x/crypto/ssh"

	"github.com/juju/juju/core/logger"
)

// SFTPHandler proxies the SFTP subsystem to the target machine.
func (h *Handlers) SFTPHandler() ssh.SubsystemHandler {
	return func(session ssh.Session) {
		handleError := func(err error) {
			h.logger.Errorf(session.Context(), "SFTP proxy failure: %v", err)
			_, _ = session.Stderr().Write([]byte(err.Error() + "\n"))
			_ = session.Exit(1)
		}

		client, err := h.connector.Connect(session.Context(), h.destination)
		if err != nil {
			handleError(errors.Annotate(err, "connecting to machine"))
			return
		}
		defer client.Close()

		machineChannel, machineRequests, err := client.OpenChannel("session", nil)
		if err != nil {
			handleError(errors.Annotate(err, "opening machine session"))
			return
		}
		defer machineChannel.Close()
		go proxyRequests(session, machineRequests, h.logger)

		if err := requestSubsystem(machineChannel, "sftp"); err != nil {
			handleError(errors.Annotate(err, "requesting SFTP subsystem"))
			return
		}

		var wg sync.WaitGroup
		wg.Go(func() {
			defer machineChannel.Close()
			_, _ = io.Copy(machineChannel, session)
		})
		wg.Go(func() {
			defer machineChannel.Close()
			_, _ = io.Copy(session, machineChannel)
		})
		wg.Wait()
	}
}

func proxyRequests(session ssh.Session, requests <-chan *gossh.Request, logger logger.Logger) {
	for request := range requests {
		if request.WantReply {
			_ = request.Reply(false, nil)
			continue
		}
		if _, err := session.SendRequest(request.Type, false, request.Payload); err != nil {
			logger.Errorf(session.Context(), "sending SFTP request %q: %v", request.Type, err)
		}
	}
	_ = session.Close()
}

type subsystemRequest struct {
	Subsystem string
}

func requestSubsystem(channel gossh.Channel, subsystem string) error {
	ok, err := channel.SendRequest("subsystem", true, gossh.Marshal(&subsystemRequest{Subsystem: subsystem}))
	if err == nil && !ok {
		return errors.New("ssh: subsystem request failed")
	}
	return err
}
