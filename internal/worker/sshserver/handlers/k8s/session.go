// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package k8s

import (
	"io"
	"os"
	"sync"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/juju/errors"

	k8sexec "github.com/juju/juju/internal/provider/kubernetes/exec"
)

// SessionHandler proxies a user SSH session to a Kubernetes container.
func (h *Handlers) SessionHandler(session ssh.Session) {
	handleError := func(err error) {
		h.logger.Errorf(session.Context(), "Kubernetes session proxy failure: %v", err)
		_, _ = session.Stderr().Write([]byte(err.Error() + "\n"))
		_ = session.Exit(1)
	}

	namespace, podName, err := h.resolver.ResolveK8sExecInfo(session.Context(), h.destination)
	if err != nil {
		handleError(errors.Annotate(err, "resolving Kubernetes exec information"))
		return
	}
	executor, err := h.getExecutor(namespace)
	if err != nil {
		handleError(errors.Annotate(err, "getting Kubernetes executor"))
		return
	}
	container, _ := h.destination.Container()
	ptyRequest, windowChanges, hasPTY := session.Pty()

	var stdin io.Reader = session
	var stdout, stderr io.Writer = session, session.Stderr()
	var master, slave *os.File
	var wg sync.WaitGroup
	if hasPTY {
		master, slave, err = pty.Open()
		if err != nil {
			handleError(errors.Annotate(err, "opening pseudo-terminal"))
			return
		}
		defer master.Close()
		defer slave.Close()

		if err := pty.Setsize(master, &pty.Winsize{
			Rows: uint16(ptyRequest.Window.Height),
			Cols: uint16(ptyRequest.Window.Width),
		}); err != nil {
			handleError(errors.Annotate(err, "setting pseudo-terminal size"))
			return
		}
		go func() {
			for window := range windowChanges {
				_ = pty.Setsize(master, &pty.Winsize{Rows: uint16(window.Height), Cols: uint16(window.Width)})
			}
		}()

		wg.Go(func() {
			defer master.Close()
			_, _ = io.Copy(master, session)
		})
		wg.Go(func() {
			defer session.Close()
			_, _ = io.Copy(session, master)
		})
		stdin, stdout, stderr = slave, slave, slave
	}

	err = executor.Exec(session.Context(), k8sexec.ExecParams{
		PodName:       podName,
		ContainerName: container,
		Commands:      session.Command(),
		Stdout:        stdout,
		Stderr:        stderr,
		Stdin:         stdin,
		TTY:           hasPTY,
		Env:           session.Environ(),
	}, session.Context().Done())
	if slave != nil {
		_ = slave.Close()
		_, _ = master.WriteString("\n")
	}
	if err != nil {
		handleError(errors.Annotate(err, "executing command in Kubernetes pod"))
		return
	}
	if hasPTY {
		wg.Wait()
	}
}
