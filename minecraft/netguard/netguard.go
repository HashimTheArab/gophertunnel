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

	"github.com/wlynxg/anet"
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

// globalV6 is the only IPv6 range allocated for global unicast; blockedV6 are the special ranges in
// it. nat64 is the well-known NAT64 prefix, judged by the IPv4 address it embeds.
var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	globalV6  = netip.MustParsePrefix("2000::/3")
	blockedV6 = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),     // IETF protocol assignments, including Teredo
		netip.MustParsePrefix("2001:db8::/32"), // documentation
		netip.MustParsePrefix("2002::/16"),     // 6to4, which can embed a private IPv4 address
		netip.MustParsePrefix("3fff::/20"),     // documentation
	}
)

// Public reports whether addr is a globally routable unicast address. IPv4-mapped and well-known
// NAT64 addresses are judged as the IPv4 address they carry.
func Public(addr netip.Addr) bool {
	addr = canonical(addr)
	switch {
	case addr.Is4():
		return !containsAny(blockedV4, addr)
	case addr.Is6():
		return globalV6.Contains(addr) && !containsAny(blockedV6, addr)
	}
	return false
}

// canonical returns addr without a zone, as the IPv4 address it carries if it is IPv4-mapped or NAT64.
func canonical(addr netip.Addr) netip.Addr {
	addr = addr.Unmap().WithZone("")
	if nat64.Contains(addr) {
		b := addr.As16()
		return netip.AddrFrom4([4]byte(b[12:]))
	}
	return addr
}

// containsAny reports whether any of prefixes contains addr.
func containsAny(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Policy refuses destinations that are not public, that belong to the host, or that Deny lists. The
// zero value is ready to use.
type Policy struct {
	// Deny lists more refused ranges, for host addresses no local interface holds: a 1:1 NAT public
	// address, the host seen from a bridged container, or other cluster nodes.
	Deny []netip.Prefix
}

// Check returns a *BlockedError for an address the policy refuses. The host's addresses are listed on
// each call, and an address is refused if they cannot be listed.
func (p Policy) Check(addr netip.Addr) error {
	original, addr := addr.WithZone(""), canonical(addr)
	if !Public(addr) || containsAny(p.Deny, original) || containsAny(p.Deny, addr) || local(addr) {
		return &BlockedError{Addr: addr}
	}
	return nil
}

// local reports whether addr is assigned to one of this host's interfaces, is the network or
// broadcast address of an attached IPv4 subnet (Linux before 5.14 broadcasts to both), or is the
// subnet-router anycast address of an attached IPv6 subnet. Addresses
// are listed through anet, so Android's netlink restrictions do not fail every check.
func local(addr netip.Addr) bool {
	addrs, err := anet.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, assigned := range addrs {
		var ip net.IP
		var mask net.IPMask
		switch assigned := assigned.(type) {
		case *net.IPNet:
			ip, mask = assigned.IP, assigned.Mask
		case *net.IPAddr:
			ip = assigned.IP
		}
		host, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		host = canonical(host)
		if host == addr {
			return true
		}
		ones, bits := mask.Size()
		switch {
		case host.Is4() && bits == 32 && ones < 31:
			subnet := netip.PrefixFrom(host, ones).Masked()
			if addr == subnet.Addr() || addr == lastAddr(subnet) {
				return true
			}
		case host.Is6() && bits == 128 && ones < 127:
			if addr == netip.PrefixFrom(host, ones).Masked().Addr() {
				return true
			}
		}
	}
	return false
}

// lastAddr returns the highest address of an IPv4 prefix.
func lastAddr(prefix netip.Prefix) netip.Addr {
	b := prefix.Addr().As4()
	mask := net.CIDRMask(prefix.Bits(), 32)
	for i := range b {
		b[i] |= ^mask[i]
	}
	return netip.AddrFrom4(b)
}

// Control is a net.Dialer Control function refusing what p refuses. The dialer calls it with each
// resolved address, so a host name that resolves to both kinds still connects to a public one.
func (p Policy) Control(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("netguard: parse dial address: %w", err)
	}
	return p.Check(addrPort.Addr())
}

// HTTPTransport returns a transport with http.DefaultTransport's settings that connects only where p
// allows. It uses no proxy, whose address would be checked in place of the server's, and is built
// afresh so hooks set on http.DefaultTransport cannot bypass the check.
func (p Policy) HTTPTransport() *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: p.Control}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}
