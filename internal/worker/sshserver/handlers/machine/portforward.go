// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package machine

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type localForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// DirectTCPIPHandler returns a handler for the DirectTCPIP channel type.
// This handler is used for local port forwarding. While the handler is nearly
// identical to the default DirectTCPIPHandler, it first connects to the target
// machine and proxies the port forwarding request through the machine's SSH server.
func (h *Handlers) DirectTCPIPHandler() ssh.ChannelHandler {
	return func(_ *ssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
		data := localForwardChannelData{}
		if err := gossh.Unmarshal(newChan.ExtraData(), &data); err != nil {
			_ = newChan.Reject(gossh.ConnectionFailed, "parsing forward data: "+err.Error())
			return
		}

		client, err := h.connector.Connect(ctx, h.destination)
		if err != nil {
			_ = newChan.Reject(gossh.ConnectionFailed, fmt.Sprintf("connecting to machine: %v", err))
			return
		}
		defer client.Close()

		destination := net.JoinHostPort(data.DestAddr, strconv.FormatUint(uint64(data.DestPort), 10))
		connection, err := client.DialContext(ctx, "tcp", destination)
		if err != nil {
			_ = newChan.Reject(gossh.ConnectionFailed, fmt.Sprintf("dialling target: %v", err))
			return
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			_ = connection.Close()
			return
		}
		go gossh.DiscardRequests(requests)
		go proxy(channel, connection)
		go proxy(connection, channel)
	}
}

func proxy(dst io.WriteCloser, src io.Reader) {
	defer dst.Close()
	_, _ = io.Copy(dst, src)
}
