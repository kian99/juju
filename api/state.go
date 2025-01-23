// Copyright 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package api

import (
	"context"
	"crypto/tls"
	"net/url"
	"path"
	"strconv"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/httpbakery"
	"github.com/juju/clock"
	"github.com/juju/errors"
	"github.com/juju/names/v5"
	"github.com/juju/version/v2"
	"gopkg.in/macaroon.v2"

	"github.com/juju/juju/api/agent/keyupdater"
	"github.com/juju/juju/core/network"
	jujuproxy "github.com/juju/juju/proxy"
	"github.com/juju/juju/rpc/jsoncodec"
)

// state is the internal implementation of the Connection interface.
type state struct {
	ctx    context.Context
	client rpcConnection
	conn   jsoncodec.JSONConn
	clock  clock.Clock

	// addr is the address used to connect to the root of the API server.
	// Its format is "<schema>://<host>:<port>/<path>" for use with url.Parse().
	addr url.URL

	// ipAddr is the IP address used to connect to the API server.
	ipAddr string

	// cookieURL is the URL that HTTP cookies for the API
	// will be associated with (specifically macaroon auth cookies).
	cookieURL *url.URL

	// modelTag holds the model tag.
	// It is empty if there is no model tag associated with the connection.
	modelTag names.ModelTag

	// controllerTag holds the controller's tag once we're connected.
	controllerTag names.ControllerTag

	// serverVersion holds the version of the API server that we are
	// connected to.  It is possible that this version is 0 if the
	// server does not report this during login.
	serverVersion version.Number

	// hostPorts is the API server addresses returned from Login,
	// which the client may cache and use for fail-over.
	hostPorts []network.MachineHostPorts

	// publicDNSName is the public host name returned from Login
	// which the client can use to make a connection verified
	// by an officially signed certificate.
	publicDNSName string

	// facadeVersions holds the versions of all facades as reported by
	// Login
	facadeVersions map[string][]int

	// pingFacadeVersion is the version to use for the pinger. This is lazily
	// set at initialization to avoid a race in our tests. See
	// http://pad.lv/1614732 for more details regarding the race.
	pingerFacadeVersion int

	// authTag holds the authenticated entity's tag after login.
	authTag names.Tag

	// mpdelAccess holds the access level of the user to the connected model.
	modelAccess string

	// controllerAccess holds the access level of the user to the connected controller.
	controllerAccess string

	// broken is a channel that gets closed when the connection is
	// broken.
	broken chan struct{}

	// closed is a channel that gets closed when State.Close is called.
	closed chan struct{}

	// loggedIn holds whether the client has successfully logged
	// in. It's a int32 so that the atomic package can be used to
	// access it safely.
	loggedIn int32

	// loginProvider holds the provider used for login.
	loginProvider LoginProvider

	// serverRootAddress holds the cached API server address and port used
	// to login.
	serverRootAddress string

	// serverScheme is the URI scheme of the API Server
	serverScheme string

	// tlsConfig holds the TLS config appropriate for making SSL
	// connections to the API endpoints.
	tlsConfig *tls.Config

	// bakeryClient holds the client that will be used to
	// authorize macaroon based login requests.
	bakeryClient *httpbakery.Client

	// proxier is the proxier used for this connection when not nil. If's expected
	// the proxy has already been started when placing in this var. This struct
	// will take the responsibility of closing the proxy.
	proxier jujuproxy.Proxier
}

// Login implements the Login method of the Connection interface providing authentication
// using basic auth or macaroons.
//
// TODO (alesstimec, wallyworld): This method should be removed and
// a login provider should be used instead.
func (st *state) Login(name names.Tag, password, nonce string, ms []macaroon.Slice) error {
	lp := NewLegacyLoginProvider(name, password, nonce, ms, st.bakeryClient, st.cookieURL)
	result, err := lp.Login(context.Background(), st)
	if err != nil {
		return errors.Trace(err)
	}
	return st.setLoginResult(result)
}

func (st *state) setLoginResult(p *LoginResultParams) error {
	st.authTag = p.tag
	st.serverVersion = p.serverVersion
	var modelTag names.ModelTag
	if p.modelTag != "" {
		var err error
		modelTag, err = names.ParseModelTag(p.modelTag)
		if err != nil {
			return errors.Annotatef(err, "invalid model tag in login result")
		}
	}
	if modelTag.Id() != st.modelTag.Id() {
		return errors.Errorf("mismatched model tag in login result (got %q want %q)", modelTag.Id(), st.modelTag.Id())
	}
	ctag, err := names.ParseControllerTag(p.controllerTag)
	if err != nil {
		return errors.Annotatef(err, "invalid controller tag %q returned from login", p.controllerTag)
	}
	st.controllerTag = ctag
	st.controllerAccess = p.controllerAccess
	st.modelAccess = p.modelAccess

	hostPorts := p.servers
	// if the connection is not proxied then we will add the connection address
	// to host ports
	if !st.IsProxied() {
		hostPorts, err = addAddress(p.servers, st.addr)
		if err != nil {
			if clerr := st.Close(); clerr != nil {
				err = errors.Annotatef(err, "error closing state: %v", clerr)
			}
			return err
		}
	}
	st.hostPorts = hostPorts

	st.publicDNSName = p.publicDNSName

	st.facadeVersions = make(map[string][]int, len(p.facades))
	for _, facade := range p.facades {
		st.facadeVersions[facade.Name] = facade.Versions
	}

	st.setLoggedIn()
	return nil
}

// AuthTag returns the tag of the authorized user of the state API connection.
func (st *state) AuthTag() names.Tag {
	return st.authTag
}

// ControllerAccess returns the access level of authorized user to the model.
func (st *state) ControllerAccess() string {
	return st.controllerAccess
}

// CookieURL returns the URL that HTTP cookies for the API will be
// associated with.
func (st *state) CookieURL() *url.URL {
	copy := *st.cookieURL
	return &copy
}

// slideAddressToFront moves the address at the location (serverIndex, addrIndex) to be
// the first address of the first server.
func slideAddressToFront(servers []network.MachineHostPorts, serverIndex, addrIndex int) {
	server := servers[serverIndex]
	hostPort := server[addrIndex]
	// Move the matching address to be the first in this server
	for ; addrIndex > 0; addrIndex-- {
		server[addrIndex] = server[addrIndex-1]
	}
	server[0] = hostPort
	for ; serverIndex > 0; serverIndex-- {
		servers[serverIndex] = servers[serverIndex-1]
	}
	servers[0] = server
}

// addAddress appends a new server derived from the given
// address to servers if the address is not already found
// there.
func addAddress(servers []network.MachineHostPorts, addr url.URL) ([]network.MachineHostPorts, error) {
	for i, server := range servers {
		for j, hostPort := range server {
			u := network.CanonicalURL(hostPort, addr.Scheme)
			if u.String() == addr.String() {
				slideAddressToFront(servers, i, j)
				return servers, nil
			}
		}
	}

	port, err := strconv.Atoi(addr.Port())
	if err != nil {
		return nil, err
	}
	result := make([]network.MachineHostPorts, 0, len(servers)+1)
	// Ensure we don't pass in a port value in the addresses of NewMachineHostPorts, i.e. use addr.Hostname()
	// since the function accepts URLs in a unique way (see docstring for NewMachineHostPorts)
	result = append(result, network.NewMachineHostPorts(port, path.Join(addr.Hostname(), addr.Path)))
	result = append(result, servers...)
	return result, nil
}

// KeyUpdater returns access to the KeyUpdater API
func (st *state) KeyUpdater() *keyupdater.State {
	return keyupdater.NewState(st)
}

// ServerVersion holds the version of the API server that we are connected to.
// It is possible that this version is Zero if the server does not report this
// during login. The second result argument indicates if the version number is
// set.
func (st *state) ServerVersion() (version.Number, bool) {
	return st.serverVersion, st.serverVersion != version.Zero
}
