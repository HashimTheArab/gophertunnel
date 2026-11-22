// Package netguard keeps outbound connections on public internet addresses, so a remote peer cannot
// aim a server-side client at the host itself, its private networks or cloud metadata services.
// Checks run on the resolved address at connect or send time, which DNS rebinding cannot bypass.
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrNotPublic is matched by errors.Is on every error this package returns for a refused address.
var ErrNotPublic = errors.New("netguard: address is not public")

// BlockedError is a connection refused because Addr is not a public address.
type BlockedError struct {
	Addr netip.Addr
}

// Error ...
func (e *BlockedError) Error() string {
	return fmt.Sprintf("netguard: %s is not a public address", e.Addr)
}

// Is reports ErrNotPublic.
func (e *BlockedError) Is(target error) bool { return target == ErrNotPublic }

// blockedV4 lists the IANA special-purpose IPv4 ranges a public server never uses.
var blockedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),        // "this network"
	netip.MustParsePrefix("10.0.0.0/8"),       // private
	netip.MustParsePrefix("100.64.0.0/10"),    // carrier-grade NAT
	netip.MustParsePrefix("127.0.0.0/8"),      // loopback
	netip.MustParsePrefix("169.254.0.0/16"),   // link-local, including cloud metadata
	netip.MustParsePrefix("172.16.0.0/12"),    // private
	netip.MustParsePrefix("192.0.0.0/24"),     // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),     // documentation
	netip.MustParsePrefix("192.88.99.0/24"),   // deprecated 6to4 and 6a44 relay anycast
	netip.MustParsePrefix("192.168.0.0/16"),   // private
	netip.MustParsePrefix("198.18.0.0/15"),    // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),  // documentation
	netip.MustParsePrefix("203.0.113.0/24"),   // documentation
	netip.MustParsePrefix("224.0.0.0/4"),      // multicast
	netip.MustParsePrefix("240.0.0.0/4"),      // reserved, including broadcast
	netip.MustParsePrefix("168.63.129.16/32"), // Azure's host-local platform endpoint
}

// globalV6 is the only IPv6 range allocated for global unicast; blockedV6 are the special ranges in it.
var (
	globalV6  = netip.MustParsePrefix("2000::/3")
	blockedV6 = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),     // IETF protocol assignments, including Teredo
		netip.MustParsePrefix("2001:db8::/32"), // documentation
		netip.MustParsePrefix("2002::/16"),     // 6to4, which can embed a private IPv4 address
		netip.MustParsePrefix("3fff::/20"),     // documentation
	}
)

// Public reports whether addr is a globally routable unicast address. IPv4-mapped IPv6 addresses
// are judged as the IPv4 address they carry.
func Public(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	switch {
	case addr.Is4():
		return !containsAny(blockedV4, addr)
	case addr.Is6():
		return globalV6.Contains(addr) && !containsAny(blockedV6, addr)
	}
	return false
}

func containsAny(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Check returns a *BlockedError unless addr is public and not assigned to this host, whose own
// public address reaches services listening on every interface. It fails closed if the host's
// addresses cannot be listed.
func Check(addr netip.Addr) error {
	if !Public(addr) || local(addr) {
		return &BlockedError{Addr: addr}
	}
	return nil
}

// local reports whether addr is assigned to one of this host's interfaces, listed afresh so a
// changed address is never missed.
func local(addr netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	addr = addr.Unmap().WithZone("")
	for _, assigned := range addrs {
		if prefix, ok := assigned.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(prefix.IP); ok && ip.Unmap() == addr {
				return true
			}
		}
	}
	return false
}

// Control is a net.Dialer Control function refusing non-public addresses. The dialer calls it with
// each resolved address, so a host name that resolves to both kinds still connects to a public one.
func Control(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("netguard: parse dial address: %w", err)
	}
	return Check(addrPort.Addr())
}

// HTTPTransport returns a transport with http.DefaultTransport's settings that connects only to
// public addresses. It uses no proxy, whose address would be checked in place of the server's, and
// is built afresh so hooks set on http.DefaultTransport cannot bypass the check.
func HTTPTransport() *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: Control}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}
