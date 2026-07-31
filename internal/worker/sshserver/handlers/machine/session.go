// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package machine

import (
	"context"
	"io"
	"sync"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// SessionChannelHandler proxies a raw SSH session channel to the target
// machine. Requests are forwarded without interpreting their payloads so that
// the proxy preserves SSH features that are not represented by ssh.Session.
func (h *Handlers) SessionChannelHandler() ssh.ChannelHandler {
	return func(_ *ssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
		// Track when we accept the channel so that we can reject with a useful error.
		accepted := false
		handleProxy(h, ctx, proxyConfig[*sessionChannel]{
			createRemote: func(_ context.Context, client *gossh.Client) (*sessionChannel, error) {
				channel, requests, err := client.OpenChannel(newChan.ChannelType(), newChan.ExtraData())
				if err != nil {
					return nil, err
				}
				return &sessionChannel{Channel: channel, requests: requests}, nil
			},
			run: func(remote *sessionChannel) error {
				local, localRequests, err := newChan.Accept()
				if err != nil {
					return err
				}
				accepted = true
				defer local.Close()

				proxySession(local, localRequests, remote.Channel, remote.requests)
				return nil
			},
			onError: func(err error) {
				if !accepted {
					h.rejectChannel(ctx, newChan, err)
					return
				}
				h.logger.Errorf(ctx, "machine proxy failure: %v", err)
			},
		})
	}
}

// SessionHandler is not intended to be used for machine proxying.
// It is provided to satisfy the ProxyHandlers interface.
//
// Use SessionChannelHandler instead, which provides a lower level
// implementation for proxying SSH session channels.
func (h *Handlers) SessionHandler(session ssh.Session) {
	h.logger.Warningf(session.Context(), "unintended use of machine SessionHandler")
	session.Close()
}

type sessionChannel struct {
	gossh.Channel
	requests <-chan *gossh.Request
}

func (h *Handlers) rejectChannel(ctx context.Context, newChan gossh.NewChannel, err error) {
	h.logger.Errorf(ctx, "machine proxy failure: %v", err)
	if rejectErr := newChan.Reject(gossh.ConnectionFailed, err.Error()); rejectErr != nil {
		h.logger.Errorf(ctx, "failed to reject machine session channel: %v", rejectErr)
	}
}

func proxySession(local gossh.Channel, localRequests <-chan *gossh.Request, remote gossh.Channel, remoteRequests <-chan *gossh.Request) {
	// The teardown of an SSH session channel is ordering sensitive. The target
	// (remote) drives completion: it sends any remaining stdout/stderr, an
	// "exit-status" (or "exit-signal") request, and finally closes the channel.
	//
	// The client's ssh.Session.Wait only returns once its channel is fully
	// closed (its request loop ranges over incoming requests until the channel
	// close arrives), so we must issue a full Close on the client channel - a
	// half close (CloseWrite/EOF) is not sufficient and leaves the client
	// hanging. That full Close, however, must not happen until:
	//
	//   1. all of the target's output and its exit-status request have been
	//      forwarded to the client, and
	//   2. the reply to any in-flight client request (notably the "exec"
	//      request that ssh.Session.Start blocks on) has been written back to
	//      the client.
	//
	// A gossh channel marks itself closed on the first Close and silently drops
	// every subsequent write with io.EOF. If Close races ahead of the output,
	// the exit-status request or the reply to a client request, the client
	// observes an unexpected EOF instead of the command's exit status.
	//
	// clientWrites serialises everything written back to the client - the
	// replies to the client's own requests (notably the "exec" request that
	// ssh.Session.Start blocks on) and the final Close - so that Close can never
	// run while such a reply is being produced, and a reply is never lost to a
	// premature Close. The forwarder that handles the client's requests holds
	// clientWrites for the whole forward-and-reply of each WantReply request, so
	// once Close acquires the lock the reply is guaranteed to have already
	// reached the client.
	var clientWrites sync.Mutex

	// remote -> local: stdout, stderr and requests (including exit-status).
	// These drain once the target has finished and closed its channel, at which
	// point everything the client needs to see has been written to local.
	var remoteToLocal sync.WaitGroup
	remoteToLocal.Go(func() {
		_, _ = io.Copy(local, remote)
	})
	remoteToLocal.Go(func() {
		_, _ = io.Copy(local.Stderr(), remote.Stderr())
	})
	remoteToLocal.Go(func() {
		// Replies to remote requests are written to the remote channel, not the
		// client, so they need no serialisation against the client Close.
		forwardRequests(remoteRequests, local, nil)
	})

	// local -> remote: stdin and the client's requests (exec, shell, pty,
	// window-change, ...). Replies to these requests are written back to the
	// client, so this forwarder serialises them against Close via clientWrites.
	var localToRemote sync.WaitGroup
	localToRemote.Go(func() {
		_, _ = io.Copy(remote, local)
		closeWrite(remote)
	})
	localToRemote.Go(func() {
		forwardRequests(localRequests, remote, &clientWrites)
	})

	// The target drives completion. Once the remote -> local direction has
	// drained, the client has received all output plus the exit-status request.
	// Fully close the client channel so ssh.Session.Wait returns. Acquiring
	// clientWrites first guarantees any in-flight reply to a client request
	// (e.g. exec) has already been delivered before the channel is closed.
	remoteToLocal.Wait()
	clientWrites.Lock()
	_ = local.Close()
	clientWrites.Unlock()

	// Closing the remote channel unblocks the local -> remote goroutines (the
	// stdin copy and request forwarder), which we wait for before returning so
	// no goroutines are leaked.
	_ = remote.Close()
	localToRemote.Wait()
}

// forwardRequests forwards SSH channel requests from one channel to another. If
// a request expects a reply, the reply is written back to the request's source
// channel. When clientWrites is non-nil the reply is written to the client
// channel: the forward-and-reply is performed while holding clientWrites so it
// is serialised against the client channel Close and cannot be torn or lost by
// a concurrent close.
func forwardRequests(requests <-chan *gossh.Request, destination gossh.Channel, clientWrites *sync.Mutex) {
	for request := range requests {
		// When replies are written back to the client channel, hold clientWrites
		// across the whole forward-and-reply so the reply cannot be lost to (or
		// torn by) a concurrent close of the client channel.
		if request.WantReply && clientWrites != nil {
			clientWrites.Lock()
		}
		ok, err := destination.SendRequest(request.Type, request.WantReply, request.Payload)
		if request.WantReply {
			_ = request.Reply(err == nil && ok, nil)
		}
		if request.WantReply && clientWrites != nil {
			clientWrites.Unlock()
		}
		if err != nil {
			return
		}
	}
}
