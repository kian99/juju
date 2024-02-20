// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package api

import (
	"context"
	"net/url"
	"os"
	"runtime/debug"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery"
	"github.com/juju/errors"
	"github.com/juju/featureflag"
	"github.com/juju/names/v5"
	"github.com/juju/utils/v3"
	"github.com/juju/version/v2"
	"gopkg.in/macaroon.v2"

	"github.com/juju/juju/api/base"
	"github.com/juju/juju/feature"
	"github.com/juju/juju/rpc"
	"github.com/juju/juju/rpc/params"
	jujuversion "github.com/juju/juju/version"
)

var (
	loginDeviceAPICall = func(caller base.APICaller, request interface{}, response interface{}) error {
		return caller.APICall("Admin", 4, "", "LoginDevice", request, response)
	}
	getDeviceSessionTokenAPICall = func(caller base.APICaller, request interface{}, response interface{}) error {
		return caller.APICall("Admin", 4, "", "GetDeviceSessionToken", request, response)
	}
	loginWithSessionTokenAPICall = func(caller base.APICaller, request interface{}, response interface{}) error {
		return caller.APICall("Admin", 4, "", "LoginWithSessionToken", request, response)
	}
	loginWithClientCredentialsAPICall = func(caller base.APICaller, request interface{}, response interface{}) error {
		return caller.APICall("Admin", 4, "", "LoginWithClientCredentials", request, response)
	}
)

// NewSessionTokenLoginProvider returns a LoginProvider implementation that
// authenticates the entity with the session token.
func NewSessionTokenLoginProvider(
	token string,
	printOutputFunc func(string, ...any) error,
	updateAccountDetailsFunc func(string) error,
) *sessionTokenLoginProvider {
	return &sessionTokenLoginProvider{
		sessionToken:             token,
		printOutputFunc:          printOutputFunc,
		updateAccountDetailsFunc: updateAccountDetailsFunc,
	}
}

type sessionTokenLoginProvider struct {
	sessionToken string
	// printOutpuFunc is used by the login provider to print the user code
	// and verification URL.
	printOutputFunc func(string, ...any) error
	// updateAccountDetailsFunc function is used to update the session
	// token for the account details.
	updateAccountDetailsFunc func(string) error
}

// Login implements the LoginProvider.Login method.
//
// It authenticates as the entity using the specified session token.
// Subsequent requests on the state will act as that entity.
func (p *sessionTokenLoginProvider) Login(ctx context.Context, caller base.APICaller) (*LoginResultParams, error) {
	// First we try to log in using the session token we have.
	result, err := p.login(ctx, caller)
	if err == nil {
		return result, nil
	}

	if params.ErrCode(err) == params.CodeUnauthorized {
		// if we fail with an "unauthorized" error, we initiate a
		// new device login.
		if err := p.initiateDeviceLogin(ctx, caller); err != nil {
			return nil, errors.Trace(err)
		}
		// and retry the login using the obtained session token.
		return p.login(ctx, caller)
	}
	return nil, errors.Trace(err)
}

func (p *sessionTokenLoginProvider) initiateDeviceLogin(ctx context.Context, caller base.APICaller) error {
	if p.printOutputFunc == nil {
		return errors.New("cannot present login details")
	}

	type loginRequest struct{}

	type deviceResponse struct {
		UserCode        string `json:"user-code"`
		VerificationURL string `json:"verification-url"`
	}
	var deviceResult deviceResponse

	// The first call we make is to initiate the device login oauth2 flow. This will
	// return a user code and the verification URL - verification URL will point to the
	// configured IdP. These two will be presented to the user. User will have to
	// open a browser, visit the verification URL, enter the user code and log in.
	err := loginDeviceAPICall(caller, &loginRequest{}, &deviceResult)
	if err != nil {
		return errors.Trace(err)
	}

	// We print the verification URL and the user code.
	err = p.printOutputFunc("Please visit %s and enter code %s to log in.", deviceResult.VerificationURL, deviceResult.UserCode)
	if err != nil {
		return errors.Trace(err)
	}

	type loginResponse struct {
		SessionToken string `json:"session-token"`
	}
	var sessionTokenResult loginResponse
	// Then we make a blocking call to get the session token.
	err = getDeviceSessionTokenAPICall(caller, &loginRequest{}, &sessionTokenResult)
	if err != nil {
		return errors.Trace(err)
	}

	p.sessionToken = sessionTokenResult.SessionToken

	return p.updateAccountDetailsFunc(sessionTokenResult.SessionToken)
}

func (p *sessionTokenLoginProvider) login(ctx context.Context, caller base.APICaller) (*LoginResultParams, error) {
	var result params.LoginResult
	request := struct {
		SessionToken string `json:"session-token"`
	}{
		SessionToken: p.sessionToken,
	}

	err := loginWithSessionTokenAPICall(caller, request, &result)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var controllerAccess string
	var modelAccess string
	var tag names.Tag
	if result.UserInfo != nil {
		tag, err = names.ParseTag(result.UserInfo.Identity)
		if err != nil {
			return nil, errors.Trace(err)
		}
		controllerAccess = result.UserInfo.ControllerAccess
		modelAccess = result.UserInfo.ModelAccess
	}
	servers := params.ToMachineHostsPorts(result.Servers)
	serverVersion, err := version.Parse(result.ServerVersion)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &LoginResultParams{
		tag:              tag,
		modelTag:         result.ModelTag,
		controllerTag:    result.ControllerTag,
		servers:          servers,
		publicDNSName:    result.PublicDNSName,
		facades:          result.Facades,
		modelAccess:      modelAccess,
		controllerAccess: controllerAccess,
		serverVersion:    serverVersion,
	}, nil
}

// NewClientCredentialsLoginProvider returns a LoginProvider implementation that
// authenticates the entity with the given client credentials.
func NewClientCredentialsLoginProvider(clientID, clientSecret string) *clientCredentialsLoginProvider {
	return &clientCredentialsLoginProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

type clientCredentialsLoginProvider struct {
	clientID     string
	clientSecret string
}

// Login implements the LoginProvider.Login method.
//
// It authenticates as the entity using client credentials.
// Subsequent requests on the state will act as that entity.
func (p *clientCredentialsLoginProvider) Login(ctx context.Context, caller base.APICaller) (*LoginResultParams, error) {
	var result params.LoginResult
	request := struct {
		ClientID     string `json:"client-id"`
		ClientSecret string `json:"client-secret"`
	}{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
	}

	err := loginWithClientCredentialsAPICall(caller, request, &result)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var controllerAccess string
	var modelAccess string
	var tag names.Tag
	if result.UserInfo != nil {
		tag, err = names.ParseTag(result.UserInfo.Identity)
		if err != nil {
			return nil, errors.Trace(err)
		}
		controllerAccess = result.UserInfo.ControllerAccess
		modelAccess = result.UserInfo.ModelAccess
	}
	servers := params.ToMachineHostsPorts(result.Servers)
	serverVersion, err := version.Parse(result.ServerVersion)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &LoginResultParams{
		tag:              tag,
		modelTag:         result.ModelTag,
		controllerTag:    result.ControllerTag,
		servers:          servers,
		publicDNSName:    result.PublicDNSName,
		facades:          result.Facades,
		modelAccess:      modelAccess,
		controllerAccess: controllerAccess,
		serverVersion:    serverVersion,
	}, nil
}

// NewUserpassLoginProvider returns a LoginProvider implementation that
// authenticates the entity with the given name and password or macaroons. The nonce
// should be empty unless logging in as a machine agent.
func NewUserpassLoginProvider(
	tag names.Tag,
	password string,
	nonce string,
	macaroons []macaroon.Slice,
	bakeryClient *httpbakery.Client,
	cookieURL *url.URL,
) *userpassLoginProvider {
	return &userpassLoginProvider{
		tag:          tag,
		password:     password,
		nonce:        nonce,
		macaroons:    macaroons,
		bakeryClient: bakeryClient,
		cookieURL:    cookieURL,
	}
}

// userpassLoginProvider provides the default juju login provider that
// authenticates the entity with the given name and password or macaroons. The
// nonce should be empty unless logging in as a machine agent.
type userpassLoginProvider struct {
	tag          names.Tag
	password     string
	nonce        string
	macaroons    []macaroon.Slice
	bakeryClient *httpbakery.Client
	cookieURL    *url.URL
}

// Login implements the LoginProvider.Login method.
//
// It authenticates as the entity with the given name and password
// or macaroons. Subsequent requests on the state will act as that entity.
func (p *userpassLoginProvider) Login(ctx context.Context, caller base.APICaller) (*LoginResultParams, error) {
	var result params.LoginResult
	request := &params.LoginRequest{
		AuthTag:       tagToString(p.tag),
		Credentials:   p.password,
		Nonce:         p.nonce,
		Macaroons:     p.macaroons,
		BakeryVersion: bakery.LatestVersion,
		CLIArgs:       utils.CommandString(os.Args...),
		ClientVersion: jujuversion.Current.String(),
	}
	// If we are in developer mode, add the stack location as user data to the
	// login request. This will allow the apiserver to connect connection ids
	// to the particular place that initiated the connection.
	if featureflag.Enabled(feature.DeveloperMode) {
		request.UserData = string(debug.Stack())
	}

	if p.password == "" {
		// Add any macaroons from the cookie jar that might work for
		// authenticating the login request.
		request.Macaroons = append(request.Macaroons,
			httpbakery.MacaroonsForURL(p.bakeryClient.Jar, p.cookieURL)...,
		)
	}
	err := caller.APICall("Admin", 3, "", "Login", request, &result)
	if err != nil {
		if !params.IsRedirect(err) {
			return nil, errors.Trace(err)
		}

		if rpcErr, ok := errors.Cause(err).(*rpc.RequestError); ok {
			var redirInfo params.RedirectErrorInfo
			err := rpcErr.UnmarshalInfo(&redirInfo)
			if err == nil && redirInfo.CACert != "" && len(redirInfo.Servers) != 0 {
				var controllerTag names.ControllerTag
				if redirInfo.ControllerTag != "" {
					if controllerTag, err = names.ParseControllerTag(redirInfo.ControllerTag); err != nil {
						return nil, errors.Trace(err)
					}
				}

				return nil, &RedirectError{
					Servers:         params.ToMachineHostsPorts(redirInfo.Servers),
					CACert:          redirInfo.CACert,
					ControllerTag:   controllerTag,
					ControllerAlias: redirInfo.ControllerAlias,
					FollowRedirect:  false, // user-action required
				}
			}
		}

		// We've been asked to redirect. Find out the redirection info.
		// If the rpc packet allowed us to return arbitrary information in
		// an error, we'd probably put this information in the Login response,
		// but we can't do that currently.
		var resp params.RedirectInfoResult
		if err := caller.APICall("Admin", 3, "", "RedirectInfo", nil, &resp); err != nil {
			return nil, errors.Annotatef(err, "cannot get redirect addresses")
		}
		return nil, &RedirectError{
			Servers:        params.ToMachineHostsPorts(resp.Servers),
			CACert:         resp.CACert,
			FollowRedirect: true, // JAAS-type redirect
		}
	}
	if result.DischargeRequired != nil || result.BakeryDischargeRequired != nil {
		// The result contains a discharge-required
		// macaroon. We discharge it and retry
		// the login request with the original macaroon
		// and its discharges.
		if result.DischargeRequiredReason == "" {
			result.DischargeRequiredReason = "no reason given for discharge requirement"
		}
		// Prefer the newer bakery.v2 macaroon.
		dcMac := result.BakeryDischargeRequired
		if dcMac == nil {
			dcMac, err = bakery.NewLegacyMacaroon(result.DischargeRequired)
			if err != nil {
				return nil, errors.Trace(err)
			}
		}
		if err := p.bakeryClient.HandleError(ctx, p.cookieURL, &httpbakery.Error{
			Message: result.DischargeRequiredReason,
			Code:    httpbakery.ErrDischargeRequired,
			Info: &httpbakery.ErrorInfo{
				Macaroon:     dcMac,
				MacaroonPath: "/",
			},
		}); err != nil {
			cause := errors.Cause(err)
			if httpbakery.IsInteractionError(cause) {
				// Just inform the user of the reason for the
				// failure, e.g. because the username/password
				// they presented was invalid.
				err = cause.(*httpbakery.InteractionError).Reason
			}
			return nil, errors.Trace(err)
		}
		// Add the macaroons that have been saved by HandleError to our login request.
		request.Macaroons = httpbakery.MacaroonsForURL(p.bakeryClient.Jar, p.cookieURL)
		result = params.LoginResult{} // zero result
		err = caller.APICall("Admin", 3, "", "Login", request, &result)
		if err != nil {
			return nil, errors.Trace(err)
		}
		if result.DischargeRequired != nil {
			return nil, errors.Errorf("login with discharged macaroons failed: %s", result.DischargeRequiredReason)
		}
	}

	var controllerAccess string
	var modelAccess string
	tag := p.tag
	if result.UserInfo != nil {
		tag, err = names.ParseTag(result.UserInfo.Identity)
		if err != nil {
			return nil, errors.Trace(err)
		}
		controllerAccess = result.UserInfo.ControllerAccess
		modelAccess = result.UserInfo.ModelAccess
	}
	servers := params.ToMachineHostsPorts(result.Servers)
	serverVersion, err := version.Parse(result.ServerVersion)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &LoginResultParams{
		tag:              tag,
		modelTag:         result.ModelTag,
		controllerTag:    result.ControllerTag,
		servers:          servers,
		publicDNSName:    result.PublicDNSName,
		facades:          result.Facades,
		modelAccess:      modelAccess,
		controllerAccess: controllerAccess,
		serverVersion:    serverVersion,
	}, nil
}
