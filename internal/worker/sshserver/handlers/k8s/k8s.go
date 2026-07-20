// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package k8s

import (
	"context"

	"github.com/juju/errors"

	"github.com/juju/juju/core/virtualhostname"
	k8sexec "github.com/juju/juju/internal/provider/kubernetes/exec"
)

// Resolver resolves Kubernetes pod information for a routed destination.
type Resolver interface {
	ResolveK8sExecInfo(context.Context, virtualhostname.Info) (namespace, podName string, err error)
}

// Logger logs proxy failures.
type Logger interface {
	Errorf(context.Context, string, ...any)
}

// Handlers provides SSH channel handlers for a Kubernetes container target.
type Handlers struct {
	resolver    Resolver
	logger      Logger
	getExecutor func(string) (k8sexec.Executor, error)
	destination virtualhostname.Info
}

// NewHandlers returns handlers for a Kubernetes container target.
func NewHandlers(destination virtualhostname.Info, resolver Resolver, logger Logger, getExecutor func(string) (k8sexec.Executor, error)) (*Handlers, error) {
	if resolver == nil {
		return nil, errors.NotValidf("Kubernetes resolver is required")
	}
	if logger == nil {
		return nil, errors.NotValidf("logger is required")
	}
	if getExecutor == nil {
		return nil, errors.NotValidf("executor is required")
	}
	if destination.Target() != virtualhostname.ContainerTarget {
		return nil, errors.NotValidf("destination must be a container target")
	}
	return &Handlers{
		resolver:    resolver,
		logger:      logger,
		getExecutor: getExecutor,
		destination: destination,
	}, nil
}
