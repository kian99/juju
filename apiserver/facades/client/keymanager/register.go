// Copyright 2022 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package keymanager

import (
	"context"
	"fmt"
	"reflect"

	"github.com/juju/names/v6"

	"github.com/juju/juju/apiserver/common"
	apiservererrors "github.com/juju/juju/apiserver/errors"
	"github.com/juju/juju/apiserver/facade"
)

// Register is called to expose a package of facades onto a given registry.
func Register(registry facade.FacadeRegistry) {
	registry.MustRegisterForMultiModel("KeyManager", 1, func(stdCtx context.Context, ctx facade.MultiModelContext) (facade.Facade, error) {
		facade, err := makeFacadeV1(stdCtx, ctx)
		if err != nil {
			return nil, fmt.Errorf("cannot make keymanager facade: %w", err)
		}
		return facade, nil
	}, reflect.TypeFor[*KeyManagerAPI]())
}

func makeFacadeV1(stdCtx context.Context, ctx facade.MultiModelContext) (*KeyManagerAPI, error) {
	authorizer := ctx.Auth()
	if !authorizer.AuthClient() {
		return nil, apiservererrors.ErrPerm
	}

	domainServices := ctx.DomainServices()

	cfg, err := domainServices.ControllerConfig().ControllerConfig(stdCtx)
	if err != nil {
		return nil, fmt.Errorf("retrieving controller config: %w", err)
	}

	authedUser, ok := ctx.Auth().GetAuthTag().(names.UserTag)
	if !ok {
		return nil, fmt.Errorf("expected authed entity to be user, got %s", ctx.Auth().GetAuthTag())
	}

	return newKeyManagerAPI(
		domainServices.KeyManagerWithImporter(),
		domainServices.Access(),
		authorizer,
		common.NewBlockChecker(domainServices.BlockCommand()),
		cfg.ControllerUUID(),
		authedUser,
	), nil
}

func newKeyManagerAPI(
	keyManagerService KeyManagerService,
	userService UserService,
	authorizer facade.Authorizer,
	check BlockChecker,
	controllerUUID string,
	args ...any,
) *KeyManagerAPI {
	authedUser := args[len(args)-1].(names.UserTag)
	return &KeyManagerAPI{
		keyManagerService: keyManagerService,
		userService:       userService,
		authorizer:        authorizer,
		check:             check,
		controllerUUID:    controllerUUID,
		authedUser:        authedUser,
	}
}

type BlockChecker interface {
	ChangeAllowed(context.Context) error
	RemoveAllowed(context.Context) error
}
