// Copyright 2026 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package sshserver

import (
	"context"
	"time"

	"github.com/juju/errors"
	"github.com/juju/worker/v5"
	"github.com/juju/worker/v5/dependency"
	"github.com/prometheus/client_golang/prometheus"
	gossh "golang.org/x/crypto/ssh"

	coredependency "github.com/juju/juju/core/dependency"
	"github.com/juju/juju/core/logger"
	coremachine "github.com/juju/juju/core/machine"
	"github.com/juju/juju/core/model"
	"github.com/juju/juju/core/permission"
	coreunit "github.com/juju/juju/core/unit"
	"github.com/juju/juju/core/user"
	"github.com/juju/juju/core/virtualhostname"
	accesserrors "github.com/juju/juju/domain/access/errors"
	"github.com/juju/juju/internal/featureflag"
	"github.com/juju/juju/internal/jwtparser"
	"github.com/juju/juju/internal/provider/kubernetes"
	k8sexec "github.com/juju/juju/internal/provider/kubernetes/exec"
	"github.com/juju/juju/internal/services"
	internalTunneler "github.com/juju/juju/internal/sshtunneler"
	"github.com/juju/juju/internal/worker/common"
	workerTunneler "github.com/juju/juju/internal/worker/sshtunneler"
)

const machineConnectionTimeout = 60 * time.Second

// GetControllerConfigServiceFunc gets the controller configuration service from
// the manifold's domain-services dependency.
type GetControllerConfigServiceFunc = func(dependency.Getter, string) (ControllerConfigService, error)

// GetControllerSSHHostKeyServiceFunc gets the controller SSH host key service
// from the manifold's domain-services dependency.
type GetControllerSSHHostKeyServiceFunc = func(dependency.Getter, string) (ControllerSSHHostKeyService, error)

// GetDomainServicesGetterFunc gets the model domain service factory from the
// manifold's domain-services dependency.
type GetDomainServicesGetterFunc = func(dependency.Getter, string) (services.DomainServicesGetter, error)

// GetSSHServiceFunc gets the model-scoped SSH service for a model UUID.
type GetSSHServiceFunc = func(context.Context, services.DomainServicesGetter, model.UUID) (SSHModelService, error)

// GetControllerConfigService gets the controller configuration service from the
// controller domain services dependency.
func GetControllerConfigService(getter dependency.Getter, name string) (ControllerConfigService, error) {
	return coredependency.GetDependencyByName(getter, name, func(factory services.ControllerDomainServices) ControllerConfigService {
		return factory.ControllerConfig()
	})
}

// GetControllerSSHHostKeyService gets the controller SSH host key service from
// the controller domain services dependency.
func GetControllerSSHHostKeyService(getter dependency.Getter, name string) (ControllerSSHHostKeyService, error) {
	return coredependency.GetDependencyByName(getter, name, func(factory services.ControllerDomainServices) ControllerSSHHostKeyService {
		return factory.SSHServerHostKey()
	})
}

// GetDomainServicesGetter gets the model domain service factory from the domain
// services worker dependency.
func GetDomainServicesGetter(getter dependency.Getter, name string) (services.DomainServicesGetter, error) {
	return coredependency.GetDependencyByName(getter, name, func(factory services.DomainServicesGetter) services.DomainServicesGetter {
		return factory
	})
}

// GetSSHService gets the model SSH service for the requested model UUID.
func GetSSHService(ctx context.Context, getter services.DomainServicesGetter, modelUUID model.UUID) (SSHModelService, error) {
	domainServices, err := getter.ServicesForModel(ctx, modelUUID)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return domainServices.SSH(), nil
}

// ManifoldConfig configures the controller SSH server worker in a
// dependency.Engine.
type ManifoldConfig struct {
	DomainServicesName             string
	SSHTunnelerName                string
	JWTParserName                  string
	ControllerID                   string
	NewServerWrapperWorker         func(ServerWrapperWorkerConfig) (worker.Worker, error)
	NewServerWorker                func(ServerWorkerConfig) (worker.Worker, error)
	GetControllerConfigService     GetControllerConfigServiceFunc
	GetControllerSSHHostKeyService GetControllerSSHHostKeyServiceFunc
	GetDomainServicesGetter        GetDomainServicesGetterFunc
	GetSSHService                  GetSSHServiceFunc
	Logger                         logger.Logger
	PrometheusRegisterer           prometheus.Registerer
	NewMetricsCollector            func() *Collector
}

// Validate validates the manifold configuration.
func (config ManifoldConfig) Validate() error {
	if config.DomainServicesName == "" {
		return errors.NotValidf("empty DomainServicesName")
	}
	if config.NewServerWrapperWorker == nil {
		return errors.NotValidf("nil NewServerWrapperWorker")
	}
	if config.NewServerWorker == nil {
		return errors.NotValidf("nil NewServerWorker")
	}
	if config.GetControllerConfigService == nil {
		return errors.NotValidf("nil GetControllerConfigService")
	}
	if config.GetControllerSSHHostKeyService == nil {
		return errors.NotValidf("nil GetControllerSSHHostKeyService")
	}
	if config.GetDomainServicesGetter == nil {
		return errors.NotValidf("nil GetDomainServicesGetter")
	}
	if config.GetSSHService == nil {
		return errors.NotValidf("nil GetSSHService")
	}
	if config.Logger == nil {
		return errors.NotValidf("nil Logger")
	}
	return nil
}

// Manifold returns a dependency.Manifold that runs an embedded SSH server.
func Manifold(config ManifoldConfig) dependency.Manifold {
	inputs := []string{config.DomainServicesName}
	if config.SSHTunnelerName != "" {
		inputs = append(inputs, config.SSHTunnelerName)
	}
	if config.JWTParserName != "" {
		inputs = append(inputs, config.JWTParserName)
	}
	return dependency.Manifold{
		Inputs: inputs,
		Start:  config.startWrapperWorker,
	}
}

func (config ManifoldConfig) startWrapperWorker(ctx context.Context, getter dependency.Getter) (worker.Worker, error) {
	if !featureflag.Enabled(featureflag.SSHJump) {
		config.Logger.Debugf(ctx, "SSH jump server worker is not enabled")
		return nil, dependency.ErrUninstall
	}
	if err := config.Validate(); err != nil {
		return nil, errors.Trace(err)
	}
	if config.SSHTunnelerName == "" {
		return nil, errors.NotValidf("empty SSHTunnelerName")
	}
	if config.JWTParserName == "" {
		return nil, errors.NotValidf("empty JWTParserName")
	}
	if config.ControllerID == "" {
		return nil, errors.NotValidf("empty ControllerID")
	}
	if config.PrometheusRegisterer == nil {
		return nil, errors.NotValidf("nil PrometheusRegisterer")
	}
	if config.NewMetricsCollector == nil {
		return nil, errors.NotValidf("nil NewMetricsCollector")
	}

	controllerConfig, err := config.GetControllerConfigService(getter, config.DomainServicesName)
	if err != nil {
		return nil, errors.Trace(err)
	}
	hostKeyService, err := config.GetControllerSSHHostKeyService(getter, config.DomainServicesName)
	if err != nil {
		return nil, errors.Trace(err)
	}
	domainServicesGetter, err := config.GetDomainServicesGetter(getter, config.DomainServicesName)
	if err != nil {
		return nil, errors.Trace(err)
	}
	var tunnelTracker workerTunneler.TunnelTracker
	if err := getter.Get(config.SSHTunnelerName, &tunnelTracker); err != nil {
		return nil, errors.Trace(err)
	}
	var jwtParser *jwtparser.Parser
	if err := getter.Get(config.JWTParserName, &jwtParser); err != nil {
		return nil, errors.Trace(err)
	}

	metrics := config.NewMetricsCollector()
	if err := config.PrometheusRegisterer.Register(metrics); err != nil {
		return nil, errors.Trace(err)
	}

	routing := routingService{
		controllerSSHHostKeyService: hostKeyService,
		domainServicesGetter:        domainServicesGetter,
		getSSHService:               config.GetSSHService,
	}
	proxyFactory := proxyFactory{
		k8sResolver: routing,
		logger:      config.Logger,
		connector: tunnelConnector{
			tunnelTracker: tunnelTracker,
			controllerID:  config.ControllerID,
			resolver:      routing,
		},
		getExecutor: k8sexec.NewInCluster,
	}

	w, err := config.NewServerWrapperWorker(ServerWrapperWorkerConfig{
		ControllerConfigService: controllerConfig,
		SSHService:              routing,
		NewServerWorker:         config.NewServerWorker,
		Logger:                  config.Logger,
		Authenticator: authenticator{
			logger:        config.Logger,
			jwtParser:     jwtParser,
			tunnelTracker: tunnelTracker,
			metrics:       metrics,
		},
		Authorizer: authorizer{
			access: routing,
			logger: config.Logger,
		},
		ProxyFactory:  proxyFactory,
		TunnelTracker: tunnelTracker,
		Metrics:       metrics,
	})
	if err != nil {
		_ = config.PrometheusRegisterer.Unregister(metrics)
		return nil, errors.Trace(err)
	}
	return common.NewCleanupWorker(w, func() {
		_ = config.PrometheusRegisterer.Unregister(metrics)
	}), nil
}

// routingService adapts domain services to the controller's routed SSH needs.
// It keeps controller host-key lookups controller-scoped and resolves all
// target-specific operations through the model UUID in the virtual hostname.
type routingService struct {
	controllerSSHHostKeyService ControllerSSHHostKeyService
	domainServicesGetter        services.DomainServicesGetter
	getSSHService               GetSSHServiceFunc
}

// sshService is retained as an alias for tests of the domain-service routing
// adapter. New code should use routingService.
type sshService = routingService

func (s routingService) SSHServerHostKey(ctx context.Context) (string, error) {
	return s.controllerSSHHostKeyService.SSHServerHostKey(ctx)
}

func (s routingService) VirtualHostKey(ctx context.Context, info virtualhostname.Info) (string, error) {
	sshService, err := s.getSSHService(ctx, s.domainServicesGetter, info.ModelUUID())
	if err != nil {
		return "", errors.Trace(err)
	}
	return sshService.VirtualHostKey(ctx, info)
}

func (s routingService) domainServices(ctx context.Context, modelUUID model.UUID) (services.DomainServices, error) {
	domainServices, err := s.domainServicesGetter.ServicesForModel(ctx, modelUUID)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return domainServices, nil
}

// HasSSHAccess grants SSH access to model administrators and controller
// superusers. A controller superuser need not hold an explicit grant to every
// target model.
func (s routingService) HasSSHAccess(ctx context.Context, username string, destination virtualhostname.Info) (bool, error) {
	name, err := user.NewName(username)
	if err != nil {
		return false, errors.Trace(err)
	}
	domainServices, err := s.domainServices(ctx, destination.ModelUUID())
	if err != nil {
		return false, err
	}
	modelAccess, err := domainServices.Access().ReadUserAccessLevelForTarget(ctx, name, permission.ID{
		ObjectType: permission.Model,
		Key:        destination.ModelUUID().String(),
	})
	if err == nil && modelAccess.EqualOrGreaterModelAccessThan(permission.AdminAccess) {
		return true, nil
	}
	if err != nil && !errors.Is(err, accesserrors.AccessNotFound) && !errors.Is(err, accesserrors.UserNotFound) {
		return false, errors.Trace(err)
	}
	if err != nil {
		// Missing model access is expected when a controller administrator
		// connects to a model without an explicit grant.
		// Fall through to the controller access check below.
	}
	controllerInfo, err := domainServices.Controller().GetControllerInfo(ctx)
	if err != nil {
		return false, errors.Trace(err)
	}
	controllerAccess, err := domainServices.Access().ReadUserAccessLevelForTarget(ctx, name, permission.ID{
		ObjectType: permission.Controller,
		Key:        controllerInfo.UUID,
	})
	if err != nil {
		if errors.Is(err, accesserrors.AccessNotFound) || errors.Is(err, accesserrors.UserNotFound) {
			return false, nil
		}
		return false, errors.Trace(err)
	}
	return controllerAccess.EqualOrGreaterControllerAccessThan(permission.SuperuserAccess), nil
}

func (s routingService) ResolveK8sExecInfo(ctx context.Context, destination virtualhostname.Info) (string, string, error) {
	domainServices, err := s.domainServices(ctx, destination.ModelUUID())
	if err != nil {
		return "", "", err
	}
	modelInfo, err := domainServices.ModelInfo().GetModelType(ctx)
	if err != nil {
		return "", "", errors.Trace(err)
	}
	if modelInfo != model.CAAS {
		return "", "", errors.NotValidf("model %q is not a CAAS model", destination.ModelUUID())
	}
	unitName, ok := destination.Unit()
	if !ok {
		return "", "", errors.NotValidf("destination has no unit")
	}
	podInfo, err := domainServices.Application().GetUnitK8sPodInfo(ctx, coreunit.Name(unitName))
	if err != nil {
		return "", "", errors.Trace(err)
	}
	modelRecord, err := domainServices.Model().Model(ctx, destination.ModelUUID())
	if err != nil {
		return "", "", errors.Trace(err)
	}
	namespace, err := modelNamespace(ctx, domainServices, modelRecord)
	if err != nil {
		return "", "", err
	}
	return namespace, podInfo.ProviderID.String(), nil
}

// MachineForDestination resolves an IAAS machine or machine-backed unit to the
// machine name expected by the reverse tunnel tracker.
func (s routingService) MachineForDestination(ctx context.Context, destination virtualhostname.Info) (coremachine.Name, error) {
	domainServices, err := s.domainServices(ctx, destination.ModelUUID())
	if err != nil {
		return "", err
	}
	modelInfo, err := domainServices.ModelInfo().GetModelType(ctx)
	if err != nil {
		return "", errors.Trace(err)
	}
	if modelInfo != model.IAAS {
		return "", errors.NotValidf("destination model %q is not IAAS", destination.ModelUUID())
	}
	switch destination.Target() {
	case virtualhostname.MachineTarget:
		machineName, ok := destination.Machine()
		if !ok {
			return "", errors.NotValidf("destination has no machine")
		}
		if _, err := domainServices.Machine().GetMachineLife(ctx, machineName); err != nil {
			return "", errors.Trace(err)
		}
		return machineName, nil
	case virtualhostname.UnitTarget:
		unitName, ok := destination.Unit()
		if !ok {
			return "", errors.NotValidf("destination has no unit")
		}
		machineName, err := domainServices.Application().GetUnitMachineName(ctx, coreunit.Name(unitName))
		if err != nil {
			return "", errors.Trace(err)
		}
		return machineName, nil
	default:
		return "", errors.NotValidf("destination is not a machine target")
	}
}

func modelNamespace(ctx context.Context, domainServices services.DomainServices, modelRecord model.Model) (string, error) {
	if modelRecord.Name != model.ControllerModelName {
		return modelRecord.Name, nil
	}
	controllerConfig, err := domainServices.ControllerConfig().ControllerConfig(ctx)
	if err != nil {
		return "", errors.Trace(err)
	}
	return kubernetes.DecideControllerNamespace(controllerConfig.ControllerName()), nil
}

type tunnelConnector struct {
	tunnelTracker workerTunneler.TunnelTracker
	controllerID  string
	resolver      routingService
}

// Connect requests a one-shot reverse tunnel to the machine resolved from a
// routed SSH destination. The local controller node ID preserves HA affinity:
// the machine connects back to the controller handling the client session.
func (c tunnelConnector) Connect(ctx context.Context, destination virtualhostname.Info) (*gossh.Client, error) {
	machineName, err := c.resolver.MachineForDestination(ctx, destination)
	if err != nil {
		return nil, errors.Trace(err)
	}
	ctx, cancel := context.WithTimeout(ctx, machineConnectionTimeout)
	defer cancel()
	return c.tunnelTracker.RequestTunnel(ctx, internalTunneler.RequestArgs{
		MachineID:        machineName.String(),
		ModelUUID:        destination.ModelUUID().String(),
		ControllerNodeID: c.controllerID,
	})
}
