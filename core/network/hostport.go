// Copyright 2014 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package network

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/juju/collections/set"
	"github.com/juju/errors"
)

// HostPort describes methods on an object that
// represents a network connection endpoint.
type HostPort interface {
	Address
	Port() int
}

// HostPortWithPath extends HostPort for addresses that include a path
// segment, consider scenarios where an address points to a loadbalancer.
type HostPortWithPath interface {
	HostPort
	AddressPath() string
}

// The generic type HostPorts[T] allows instaniating
// a slice of HostPort or HostPortWithPath and
// reusing the several methods on both.
type HostPorts[T HostPort] []T

type HostPortsWithPath []HostPortWithPath

// FilterUnusable returns a copy of the receiver HostPorts after removing
// any addresses unlikely to be usable (ScopeMachineLocal or ScopeLinkLocal).
func (hps HostPorts[T]) FilterUnusable() HostPorts[T] {
	filtered := make(HostPorts[T], 0, len(hps))
	for _, addr := range hps {
		switch addr.AddressScope() {
		case ScopeMachineLocal, ScopeLinkLocal:
			continue
		}
		filtered = append(filtered, addr)
	}
	return filtered
}

// Strings returns the HostPorts as a slice of
// strings suitable for passing to net.Dial.
func (hps HostPorts[T]) Strings() []string {
	result := make([]string, len(hps))
	for i, addr := range hps {
		result[i] = DialAddress(addr)
	}
	return result
}

// CanonicalURLs returns the HostPorts as a slice of strings
// after converting them to their full canonical URL form.
// An empty scheme will result in URLs without a scheme
// e.g. "host:port/path" as opposed to "scheme://host:port/path".
func (hps HostPortsWithPath) CanonicalURLs(scheme string) []string {
	result := make([]string, len(hps))
	for i, addr := range hps {
		u := CanonicalURL(addr, scheme)
		res := u.String()
		if scheme == "" {
			res = strings.TrimPrefix(res, "//")
		}
		result[i] = res
	}
	return result
}

// Unique returns a copy of the receiver HostPorts with duplicate endpoints
// removed. Note that this only applies to dial addresses; spaces are ignored.
func (hps HostPorts[T]) Unique() HostPorts[T] {
	results := make(HostPorts[T], 0, len(hps))
	seen := set.NewStrings()

	for _, addr := range hps {
		switch v := any(addr).(type) {
		case HostPortWithPath:
			url := CanonicalURL(v, "")
			if seen.Contains(url.String()) {
				continue
			}
		}
		da := DialAddress(addr)
		if seen.Contains(da) {
			continue
		}
		seen.Add(da)
		results = append(results, addr)
	}
	return results
}

// PrioritizedForScope orders the HostPorts by best match for the input scope
// matching function and returns them in NetAddr form.
// If there are no suitable addresses then an empty slice is returned.
func (hps HostPorts[T]) PrioritizedForScope(getMatcher ScopeMatchFunc) []string {
	indexes := indexesByScopeMatch(hps, getMatcher)
	out := make([]string, len(indexes))
	for i, index := range indexes {
		out[i] = DialAddress(hps[index])
	}
	return out
}

// CanonicalURL returns a URL value for the input HostPort,
// that includes the the provided scheme.
func CanonicalURL(a HostPortWithPath, scheme string) url.URL {
	hostPort := net.JoinHostPort(a.Host(), strconv.Itoa(a.Port()))
	u := url.URL{
		Scheme: scheme,
		Host:   hostPort,
		Path:   a.AddressPath(),
	}
	return u
}

// DialAddress returns a string value for the input HostPort,
// suitable for passing as an argument to net.Dial.
func DialAddress(a HostPort) string {
	hostPort := net.JoinHostPort(a.Host(), strconv.Itoa(a.Port()))
	return hostPort
}

// NetPort represents a network port.
// TODO (manadart 2019-08-15): Finish deprecation of `Port` and use that name.
type NetPort int

// Port returns the port number.
func (p NetPort) Port() int {
	return int(p)
}

// MachineHostPort associates a space-unaware address with a port.
type MachineHostPort struct {
	MachineAddress
	NetPort
}

var _ HostPort = MachineHostPort{}

// String implements Stringer.
func (hp MachineHostPort) String() string {
	return DialAddress(hp)
}

// GoString implements fmt.GoStringer.
func (hp MachineHostPort) GoString() string {
	return hp.String()
}

// MachineHostPorts is a slice of MachineHostPort
// allowing use as a receiver for bulk operations.
type MachineHostPorts []MachineHostPort

// HostPorts returns the slice as a new slice of the HostPort indirection.
func (hp MachineHostPorts) HostPorts() HostPorts[HostPort] {
	addrs := make(HostPorts[HostPort], len(hp))
	for i, hp := range hp {
		addrs[i] = hp
	}
	return addrs
}

// NewMachineHostPorts creates a list of MachineHostPorts
// from each given string address and port.
// The hostPort representation of a URL did not previously accommodate for a path
// so the format of addresses is not a canonical URL in order to keep the
// function backwards compatible. Normally addresses are expected to be in the
// form "host[:port][/path]" but we have a separate parameter for the port
// while the addresses are expected to be "host[/path]"
// The path is then extracted from the address if present, i.e.
// "host/my/path" is split into "host" and "my/path".
func NewMachineHostPorts(port int, addresses ...string) MachineHostPorts {
	hps := make(MachineHostPorts, len(addresses))
	for i, addr := range addresses {
		host, path, _ := strings.Cut(addr, "/")
		hps[i] = MachineHostPort{
			MachineAddress: NewMachineAddress(host, WithPath(path)),
			NetPort:        NetPort(port),
		}
	}
	return hps
}

var hasSchemaRegex = regexp.MustCompile(`^[a-zA-Z]+:\/\/`)

// ParseMachineHostPort converts a string containing a
// single host and port value to a MachineHostPort.
// The input string may also contain a path segment.
func ParseMachineHostPort(hp string) (*MachineHostPort, error) {
	originalHp := hp
	if !hasSchemaRegex.MatchString(hp) {
		// Add a schema if one is not present to avoid parsing ambiguity in url.Parse.
		hp = "schema://" + hp
	}
	errMsgf := "cannot parse %q as address:port[/path]"
	url, err := url.Parse(hp)
	if err != nil {
		return nil, errors.Annotatef(err, errMsgf, originalHp)
	}
	switch {
	case url.Scheme == "":
		// The input doesn't require a schema so don't mention the schema in the error.
		// It is only added to aid url.Parse.
		return nil, errors.Errorf(errMsgf, originalHp)
	case url.Host == "":
		return nil, errors.Errorf(errMsgf+": missing host", originalHp)
	case url.Port() == "":
		return nil, errors.Errorf(errMsgf+": missing port", originalHp)
	}
	numPort, err := strconv.Atoi(url.Port())
	if err != nil {
		return nil, errors.Annotatef(err, "cannot parse %q port", url.Port())
	}
	return &MachineHostPort{
		MachineAddress: NewMachineAddress(url.Hostname(), WithPath(url.Path)),
		NetPort:        NetPort(numPort),
	}, nil
}

// CollapseToHostPorts returns the input nested slice of MachineHostPort
// as a flat slice of HostPort, preserving the order.
func CollapseToHostPorts(serversHostPorts []MachineHostPorts) HostPorts[HostPort] {
	var collapsed HostPorts[HostPort]
	for _, hps := range serversHostPorts {
		for _, hp := range hps {
			collapsed = append(collapsed, hp)
		}
	}
	return collapsed
}

// CollapseToHostPortsWithPath returns the input nested slice of MachineHostPort
// as a flat slice of HostPortWithPath, preserving the order.
func CollapseToHostPortsWithPath(serversHostPorts []MachineHostPorts) HostPorts[HostPortWithPath] {
	var collapsed HostPorts[HostPortWithPath]
	for _, hps := range serversHostPorts {
		for _, hp := range hps {
			collapsed = append(collapsed, hp)
		}
	}
	return collapsed
}

// ProviderHostPort associates a provider/space aware address with a port.
type ProviderHostPort struct {
	ProviderAddress
	NetPort
}

var _ HostPort = ProviderHostPort{}

// String implements Stringer.
func (hp ProviderHostPort) String() string {
	return DialAddress(hp)
}

// GoString implements fmt.GoStringer.
func (hp ProviderHostPort) GoString() string {
	return hp.String()
}

// ProviderHostPorts is a slice of ProviderHostPort
// allowing use as a receiver for bulk operations.
type ProviderHostPorts []ProviderHostPort

// Addresses extracts the ProviderAddress from each member of the collection,
// then returns them as a new collection, effectively discarding the port.
func (hp ProviderHostPorts) Addresses() ProviderAddresses {
	addrs := make(ProviderAddresses, len(hp))
	for i, hp := range hp {
		addrs[i] = hp.ProviderAddress
	}
	return addrs
}

// HostPorts returns the slice as a new slice of the HostPort indirection.
func (hp ProviderHostPorts) HostPorts() HostPorts[HostPort] {
	addrs := make(HostPorts[HostPort], len(hp))
	for i, hp := range hp {
		addrs[i] = hp
	}
	return addrs
}

// ParseProviderHostPorts creates a slice of MachineHostPorts parsing
// each given string containing address:port.
// An error is returned if any string cannot be parsed as a MachineHostPort.
func ParseProviderHostPorts(hostPorts ...string) (ProviderHostPorts, error) {
	hps := make(ProviderHostPorts, len(hostPorts))
	for i, hp := range hostPorts {
		mhp, err := ParseMachineHostPort(hp)
		if err != nil {
			return nil, errors.Trace(err)
		}
		hps[i] = ProviderHostPort{
			ProviderAddress: ProviderAddress{MachineAddress: mhp.MachineAddress},
			NetPort:         mhp.NetPort,
		}
	}
	return hps, nil
}

// SpaceHostPort associates a space ID decorated address with a port.
type SpaceHostPort struct {
	SpaceAddress
	NetPort
}

var _ HostPort = SpaceHostPort{}

// String implements Stringer.
func (hp SpaceHostPort) String() string {
	return DialAddress(hp)
}

// GoString implements fmt.GoStringer.
func (hp SpaceHostPort) GoString() string {
	return hp.String()
}

// Less reports whether hp is ordered before hp2
// according to the criteria used by SortHostPorts.
func (hp SpaceHostPort) Less(hp2 SpaceHostPort) bool {
	order1 := SortOrderMostPublic(hp)
	order2 := SortOrderMostPublic(hp2)
	if order1 == order2 {
		if hp.SpaceAddress.Value == hp2.SpaceAddress.Value {
			return hp.Port() < hp2.Port()
		}
		return hp.SpaceAddress.Value < hp2.SpaceAddress.Value
	}
	return order1 < order2
}

// SpaceHostPorts is a slice of SpaceHostPort
// allowing use as a receiver for bulk operations.
type SpaceHostPorts []SpaceHostPort

// NewSpaceHostPorts creates a list of SpaceHostPorts
// from each input string address and port.
func NewSpaceHostPorts(port int, addresses ...string) SpaceHostPorts {
	hps := make(SpaceHostPorts, len(addresses))
	for i, addr := range addresses {
		hps[i] = SpaceHostPort{
			SpaceAddress: NewSpaceAddress(addr),
			NetPort:      NetPort(port),
		}
	}
	return hps
}

// HostPorts returns the slice as a new slice of the HostPort indirection.
func (hps SpaceHostPorts) HostPorts() HostPorts[HostPort] {
	addrs := make(HostPorts[HostPort], len(hps))
	for i, hp := range hps {
		addrs[i] = hp
	}
	return addrs
}

// InSpaces returns the SpaceHostPorts that are in the input spaces.
func (hps SpaceHostPorts) InSpaces(spaces ...SpaceInfo) (SpaceHostPorts, bool) {
	if len(spaces) == 0 {
		logger.Errorf("host ports not filtered - no spaces given.")
		return hps, false
	}

	spaceInfos := SpaceInfos(spaces)
	var selectedHostPorts SpaceHostPorts
	for _, hp := range hps {
		if space := spaceInfos.GetByID(hp.SpaceID); space != nil {
			logger.Debugf("selected %q as a hostPort in space %q", hp.Value, space.Name)
			selectedHostPorts = append(selectedHostPorts, hp)
		}
	}

	if len(selectedHostPorts) > 0 {
		return selectedHostPorts, true
	}

	logger.Errorf("no hostPorts found in spaces %s", spaceInfos)
	return hps, false
}

// AllMatchingScope returns the HostPorts that best satisfy the input scope
// matching function, as strings usable as arguments to net.Dial.
func (hps SpaceHostPorts) AllMatchingScope(getMatcher ScopeMatchFunc) []string {
	indexes := indexesForScope(hps, getMatcher)
	out := make([]string, 0, len(indexes))
	for _, index := range indexes {
		out = append(out, DialAddress(hps[index]))
	}
	return out
}

// ToProviderHostPorts transforms the SpaceHostPorts to ProviderHostPorts
// by using the input lookup for conversion of space ID to space info.
func (hps SpaceHostPorts) ToProviderHostPorts(lookup SpaceLookup) (ProviderHostPorts, error) {
	if hps == nil {
		return nil, nil
	}

	var spaces SpaceInfos
	if len(hps) > 0 {
		var err error
		if spaces, err = lookup.AllSpaceInfos(); err != nil {
			return nil, errors.Trace(err)
		}
	}

	pHPs := make(ProviderHostPorts, len(hps))
	for i, hp := range hps {
		pHPs[i] = ProviderHostPort{
			ProviderAddress: ProviderAddress{MachineAddress: hp.MachineAddress},
			NetPort:         hp.NetPort,
		}

		if hp.SpaceID != "" {
			info := spaces.GetByID(hp.SpaceID)
			if info == nil {
				return nil, errors.NotFoundf("space with ID %q", hp.SpaceID)
			}
			pHPs[i].SpaceName = info.Name
			pHPs[i].ProviderSpaceID = info.ProviderId
		}
	}
	return pHPs, nil
}

func (hps SpaceHostPorts) Len() int      { return len(hps) }
func (hps SpaceHostPorts) Swap(i, j int) { hps[i], hps[j] = hps[j], hps[i] }
func (hps SpaceHostPorts) Less(i, j int) bool {
	return hps[i].Less(hps[j])
}

// SpaceAddressesWithPort returns the input SpaceAddresses
// all associated with the given port.
func SpaceAddressesWithPort(addrs SpaceAddresses, port int) SpaceHostPorts {
	hps := make(SpaceHostPorts, len(addrs))
	for i, addr := range addrs {
		hps[i] = SpaceHostPort{
			SpaceAddress: addr,
			NetPort:      NetPort(port),
		}
	}
	return hps
}

// APIHostPortsToNoProxyString converts list of lists of NetAddrs() to
// a NoProxy-like comma separated string, ignoring local addresses
func APIHostPortsToNoProxyString(ahp []SpaceHostPorts) string {
	noProxySet := set.NewStrings()
	for _, host := range ahp {
		for _, hp := range host {
			if hp.SpaceAddress.Scope == ScopeMachineLocal || hp.SpaceAddress.Scope == ScopeLinkLocal {
				continue
			}
			noProxySet.Add(hp.SpaceAddress.Value)
		}
	}
	return strings.Join(noProxySet.SortedValues(), ",")
}

// EnsureFirstHostPort scans the given list of SpaceHostPorts and if
// "first" is found, it moved to index 0. Otherwise, if "first" is not
// in the list, it's inserted at index 0.
func EnsureFirstHostPort(first SpaceHostPort, hps SpaceHostPorts) SpaceHostPorts {
	var result []SpaceHostPort
	found := false
	for _, hp := range hps {
		if hp.String() == first.String() && !found {
			// Found, so skip it.
			found = true
			continue
		}
		result = append(result, hp)
	}
	// Insert it at the top.
	result = append(SpaceHostPorts{first}, result...)
	return result
}
