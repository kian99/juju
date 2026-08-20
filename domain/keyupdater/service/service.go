// Copyright 2024 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package service

import (
	"context"
	"fmt"

	"github.com/juju/juju/controller"
	"github.com/juju/juju/core/changestream"
	coremachine "github.com/juju/juju/core/machine"
	"github.com/juju/juju/core/trace"
	"github.com/juju/juju/core/watcher"
	"github.com/juju/juju/core/watcher/eventsource"
	machineerrors "github.com/juju/juju/domain/machine/errors"
	"github.com/juju/juju/internal/errors"
)

// ControllerKeyProvider is responsible for providing controller wide authorised
// keys that should be included as part of every machine.
type ControllerKeyProvider interface {
	// ControllerAuthorisedKeys returns controller wide authorised keys.
	ControllerAuthorisedKeys(context.Context) ([]string, error)
}

// Service provides the means for retrieving controller-authorised keys for a
// machine in a model.
type Service struct {
	// controllerKeyProvider is a reference to a [ControllerKeyProvider] that
	// can be used for fetching controller wide authorised keys.
	controllerKeyProvider ControllerKeyProvider

	// controllerSt is a reference to [ControllerState] for watching controller
	// authorized key information.
	controllerSt ControllerState

	// st is a reference to [State] for checking model machine information.
	st State
}

// WatcherFactory describes the methods required for creating new watchers
// for key updates.
type WatcherFactory interface {
	// NewNotifyWatcher returns a new watcher that filters changes from the
	// input base watcher's db/queue. Change-log events will be emitted only if
	// the filter accepts them, and dispatching the notifications via the
	// Changes channel. A filter option is required, though additional filter
	// options can be provided.
	NewNotifyWatcher(context.Context, string, eventsource.FilterOption, ...eventsource.FilterOption) (watcher.NotifyWatcher, error)
}

// WatchableService is a normal [Service] that can also be watched for updates
// to authorised key values.
type WatchableService struct {
	// Service is the inherited service to extend upon.
	Service

	// watcherFactory is the factory to use for generating new watchers for
	// authorised key changes.
	watcherFactory WatcherFactory
}

// State provides the access layer the [Service] needs for checking model
// machine information.
type State interface {
	// CheckMachineExists check to see if the given machine exists in the model. If
	// the machine does not exist an error satisfying
	// [github.com/juju/juju/domain/machine/errors.MachineNotFound] is returned.
	CheckMachineExists(context.Context, coremachine.Name) error
}

// ControllerState provides the access layer the [Service] needs for retrieving
// controller-scoped authorized key information.
type ControllerState interface {
	// NamespaceForWatchControllerConfig returns the namespace used to monitor
	// controller authorized key changes.
	NamespaceForWatchControllerConfig() string
}

// NewService constructs a new [Service] for retrieving controller-authorised
// keys for machines in a model.
func NewService(
	controllerKeyProvider ControllerKeyProvider,
	controllerState ControllerState,
	st State,
) *Service {
	return &Service{
		controllerSt:          controllerState,
		controllerKeyProvider: controllerKeyProvider,
		st:                    st,
	}
}

// NewWatchableService creates a new [WatchableService] for consuming changes in
// controller-authorised keys.
func NewWatchableService(
	controllerKeyProvider ControllerKeyProvider,
	controllerState ControllerState,
	st State,
	watcherFactory WatcherFactory,
) *WatchableService {
	return &WatchableService{
		Service:        *NewService(controllerKeyProvider, controllerState, st),
		watcherFactory: watcherFactory,
	}
}

// GetAuthorisedKeysForMachine is responsible for fetching the authorised keys
// that should be available on a machine. The following errors can be expected:
// - [github.com/juju/juju/core/errors.NotValid] if the machine id is not valid.
// - [github.com/juju/juju/domain/machine/errors.NotFound] if the machine does
// not exist.
func (s *Service) GetAuthorisedKeysForMachine(
	ctx context.Context,
	machineName coremachine.Name,
) ([]string, error) {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()

	if err := machineName.Validate(); err != nil {
		return nil, errors.Errorf(
			"validating machine name when getting authorized keys for machine: %w",
			err,
		)
	}

	if err := s.st.CheckMachineExists(ctx, machineName); errors.Is(err, machineerrors.MachineNotFound) {
		return nil, errors.Errorf(
			"machine %q does not exist", machineName,
		).Add(machineerrors.MachineNotFound)
	} else if err != nil {
		return nil, errors.Errorf(
			"determining if machine %q exists when getting authorized keys for machine: %w",
			machineName, err,
		)
	}

	controllerKeys, err := s.controllerKeyProvider.ControllerAuthorisedKeys(ctx)
	if err != nil {
		return nil, errors.Errorf(
			"getting controller authorised keys for machine %q: %w",
			machineName, err,
		)
	}

	return controllerKeys, nil
}

// WatchAuthorisedKeysForMachine will watch for authorised key changes for a
// give machine name. The following errors can be expected:
// - [github.com/juju/juju/core/errors.NotValid] if the machine id is not valid.
// - [machineerrors.MachineNotFound] if no machine exists for the provided name.
func (s *WatchableService) WatchAuthorisedKeysForMachine(
	ctx context.Context,
	machineName coremachine.Name,
) (watcher.NotifyWatcher, error) {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()

	if err := machineName.Validate(); err != nil {
		return nil, errors.Errorf(
			"validating machine name when getting authorized keys for machine: %w",
			err,
		)
	}

	if err := s.st.CheckMachineExists(ctx, machineName); errors.Is(err, machineerrors.MachineNotFound) {
		return nil, errors.Errorf(
			"watching authorized keys for machine %q, machine does not exist",
			machineName,
		).Add(machineerrors.MachineNotFound)
	}

	return s.watcherFactory.NewNotifyWatcher(
		ctx,
		fmt.Sprintf("authorized keys watcher for %q", machineName),
		eventsource.PredicateFilter(
			s.controllerSt.NamespaceForWatchControllerConfig(),
			changestream.All,
			eventsource.EqualsPredicate(controller.SystemSSHKeys),
		),
	)
}

// GetInitialAuthorisedKeysForContainer returns the controller-authorised keys
// to be used when provisioning a new container for the model.
func (s *Service) GetInitialAuthorisedKeysForContainer(ctx context.Context) ([]string, error) {
	ctx, span := trace.Start(ctx, trace.NameFromFunc())
	defer span.End()

	controllerKeys, err := s.controllerKeyProvider.ControllerAuthorisedKeys(ctx)
	if err != nil {
		return nil, errors.Errorf(
			"getting controller authorised keys for container: %w", err,
		)
	}

	return controllerKeys, nil
}
