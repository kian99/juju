// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"context"

	"github.com/gliderlabs/ssh"
	"github.com/juju/errors"

	"github.com/juju/juju/core/logger"
	"github.com/juju/juju/core/virtualhostname"
	k8sexec "github.com/juju/juju/internal/provider/kubernetes/exec"
	"github.com/juju/juju/internal/worker/sshserver/handlers/k8s"
	"github.com/juju/juju/internal/worker/sshserver/handlers/machine"
)

// ProxyHandlers provide session, local forwarding, and SFTP handling for a target.
type ProxyHandlers interface {
	SessionHandler(ssh.Session)
	DirectTCPIPHandler() ssh.ChannelHandler
	SFTPHandler() ssh.SubsystemHandler
}

// ProxyFactory creates handlers for a routed SSH target.
type ProxyFactory interface {
	New(context.Context, virtualhostname.Info) (ProxyHandlers, error)
}

type proxyFactory struct {
	k8sResolver k8s.Resolver
	logger      logger.Logger
	connector   machine.SSHConnector
	getExecutor func(string) (k8sexec.Executor, error)
}

func (f proxyFactory) New(_ context.Context, destination virtualhostname.Info) (ProxyHandlers, error) {
	switch destination.Target() {
	case virtualhostname.ContainerTarget:
		return k8s.NewHandlers(destination, f.k8sResolver, f.logger, f.getExecutor)
	case virtualhostname.MachineTarget, virtualhostname.UnitTarget:
		return machine.NewHandlers(destination, f.connector, f.logger)
	default:
		return nil, errors.NotValidf("unknown virtual hostname target %d", destination.Target())
	}
}
