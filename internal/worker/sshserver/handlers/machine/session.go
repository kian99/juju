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

// SessionChannelHandler proxies a raw SSH channel to the target machine.
func (h *Handlers) SessionChannelHandler() ssh.ChannelHandler {
	return func(_ *ssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
		// Reject the channel if accepting it fails.
		accepted := false
		handleProxy(h, ctx, proxyConfig[*sessionChannel]{
			createRemote: func(_ context.Context, client *gossh.Client) (*sessionChannel, error) {
				channelType := newChan.ChannelType()
				h.logger.Infof(ctx, "machine proxying channel type %q", channelType)
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
					h.logger.Errorf(ctx, "machine proxy failure: %v", err)
					_ = newChan.Reject(gossh.ConnectionFailed, err.Error())
					return
				}
				h.logger.Errorf(ctx, "machine proxy failure: %v", err)
			},
		})
	}
}

// SessionHandler is unsupported for machine proxying.
func (h *Handlers) SessionHandler(session ssh.Session) {
	h.logger.Warningf(session.Context(), "unintended use of machine SessionHandler")
	session.Close()
}

type sessionChannel struct {
	gossh.Channel
	requests <-chan *gossh.Request
}

func proxySession(local gossh.Channel, localRequests <-chan *gossh.Request, remote gossh.Channel, remoteRequests <-chan *gossh.Request) {
	// The remote channel controls teardown. Serialize client replies and close
	// so output, exit status, and request replies are delivered in order.
	var clientWrites sync.Mutex

	// Drain remote output and requests before closing the local channel.
	var remoteToLocal sync.WaitGroup

	// Copy output, then half-close the local channel after both streams finish.
	remoteToLocal.Go(func() {
		var data sync.WaitGroup
		data.Go(func() {
			_, _ = io.Copy(local, remote)
		})
		data.Go(func() {
			_, _ = io.Copy(local.Stderr(), remote.Stderr())
		})
		data.Wait()
		closeWrite(local)
	})
	remoteToLocal.Go(func() {
		forwardRequests(remoteRequests, local, nil)
	})

	// Forward local input and requests to the remote channel.
	var localToRemote sync.WaitGroup
	localToRemote.Go(func() {
		_, _ = io.Copy(remote, local)
		closeWrite(remote)
	})
	localToRemote.Go(func() {
		forwardRequests(localRequests, remote, &clientWrites)
	})

	// Close the local channel after remote output and requests have drained.
	remoteToLocal.Wait()
	clientWrites.Lock()
	_ = local.Close()
	clientWrites.Unlock()

	// Close the remote channel and wait for the remaining forwarders.
	_ = remote.Close()
	localToRemote.Wait()
}

// forwardRequests forwards SSH requests and their replies.
func forwardRequests(requests <-chan *gossh.Request, destination gossh.Channel, clientWrites *sync.Mutex) {
	for request := range requests {
		// Keep replies serialized with closing the client channel.
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
