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
	var ptmx, tty *os.File
	var wg sync.WaitGroup
	// cleanupPTY waits for the PTY goroutines to finish and then closes
	// the PTY file descriptors. It is a no-op when no PTY was requested.
	cleanupPTY := func() {}
	// Defer eval of cleanupPTY since it may be set later.
	defer func() {
		cleanupPTY()
	}()

	// If pty is requested we need to simulate a terminal device, passing
	// the pty file descriptor to the executor and pipe it back to the session.
	// NOTE: It's unclear if this is strictly needed but the bare session is not enough
	// because the file descriptor is not a tty and when the executor checks for
	// it, it returns an error.
	if hasPTY {
		ptmx, tty, err = pty.Open()
		if err != nil {
			handleError(errors.Annotate(err, "opening pseudo-terminal"))
			return
		}
		// ptmx and tty are closed by cleanupPTY, which waits for the
		// goroutines below to finish first so that pty.Setsize never
		// races with ptmx.Close.
		cleanupPTY = func() {
			// Wait for the copy goroutines and the window-change
			// listener to finish before closing ptmx, so no goroutine
			// is left calling pty.Setsize on a closed file descriptor.
			wg.Wait()
			_ = tty.Close()
			// Send a new line to the session to end the master
			// side of the pty.
			_, _ = ptmx.WriteString("\n")
			_ = ptmx.Close()
		}

		if err := pty.Setsize(ptmx, &pty.Winsize{
			Rows: uint16(ptyRequest.Window.Height),
			Cols: uint16(ptyRequest.Window.Width),
		}); err != nil {
			handleError(errors.Annotate(err, "setting pseudo-terminal size"))
			return
		}

		// Listen for window size changes. The listener stops when the
		// session context is cancelled (which happens when the session
		// is closed) or when the windowChanges channel is closed.
		// cleanupPTY waits for this goroutine via wg.Wait() before
		// closing ptmx, so pty.Setsize never races with ptmx.Close.
		wg.Go(func() {
			ctx := session.Context()
			for {
				select {
				case <-ctx.Done():
					return
				case window, ok := <-windowChanges:
					if !ok {
						return
					}
					_ = pty.Setsize(ptmx, &pty.Winsize{
						Rows: uint16(window.Height),
						Cols: uint16(window.Width),
					})
				}
			}
		})
		wg.Go(func() {
			// If the user's session ends, close the tty so the
			// ptmx-to-session copy below unblocks and the session is
			// closed. ptmx itself is closed by cleanupPTY after
			// wg.Wait() to avoid racing with the window-change listener.
			defer tty.Close()
			_, _ = io.Copy(ptmx, session)
		})
		wg.Go(func() {
			// If the ptmx ends, close the session because
			// there is no more data to send.
			defer session.Close()
			_, _ = io.Copy(session, ptmx)
		})
		stdin, stdout, stderr = tty, tty, tty
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
	if err != nil {
		handleError(errors.Annotate(err, "executing command in Kubernetes pod"))
		return
	}
}
