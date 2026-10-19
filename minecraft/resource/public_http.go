package resource

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// NewPublicHTTPClient returns a client for server-supplied resource pack URLs.
// It allows only HTTPS on public addresses, checks resolved addresses at connect
// time, and limits redirects. Callers still supply request deadlines and bounds
// through ReadURLWithClient.
func NewPublicHTTPClient() *http.Client {
	return &http.Client{
		Transport: publicPackTransport{&http.Transport{
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, Control: dialPublicOnly}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) >= 5 {
				return errors.New("resource pack redirect refused")
			}
			return nil
		},
	}
}

// publicPackTransport rejects non-HTTPS requests before opening a connection.
type publicPackTransport struct{ transport *http.Transport }

// RoundTrip applies the URL restriction to the initial request as well as redirects.
func (t publicPackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, errors.New("resource pack URL must use HTTPS")
	}
	return t.transport.RoundTrip(req)
}

// specialUseNetworks records the IANA special-purpose prefixes not already
// rejected by netip's unicast/private checks, with their reachable exceptions.
// Use the longest matching prefix. Registry snapshots last updated 2025-10-09:
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
var specialUseNetworks = []struct {
	prefix netip.Prefix
	public bool
}{
	{netip.MustParsePrefix("0.0.0.0/8"), false},
	{netip.MustParsePrefix("100.64.0.0/10"), false},
	{netip.MustParsePrefix("192.0.0.0/24"), false},
	{netip.MustParsePrefix("192.0.0.9/32"), true},
	{netip.MustParsePrefix("192.0.0.10/32"), true},
	{netip.MustParsePrefix("192.0.2.0/24"), false},
	{netip.MustParsePrefix("192.88.99.0/24"), false},
	{netip.MustParsePrefix("198.18.0.0/15"), false},
	{netip.MustParsePrefix("198.51.100.0/24"), false},
	{netip.MustParsePrefix("203.0.113.0/24"), false},
	{netip.MustParsePrefix("240.0.0.0/4"), false},
	{netip.MustParsePrefix("64:ff9b:1::/48"), false},
	{netip.MustParsePrefix("100::/64"), false},
	{netip.MustParsePrefix("100:0:0:1::/64"), false},
	{netip.MustParsePrefix("2001::/23"), false},
	{netip.MustParsePrefix("2001:1::1/128"), true},
	{netip.MustParsePrefix("2001:1::2/128"), true},
	{netip.MustParsePrefix("2001:1::3/128"), true},
	{netip.MustParsePrefix("2001:3::/32"), true},
	{netip.MustParsePrefix("2001:4:112::/48"), true},
	{netip.MustParsePrefix("2001:20::/28"), true},
	{netip.MustParsePrefix("2001:30::/28"), true},
	{netip.MustParsePrefix("2001:db8::/32"), false},
	{netip.MustParsePrefix("2002::/16"), false},
	{netip.MustParsePrefix("3fff::/20"), false},
	{netip.MustParsePrefix("5f00::/16"), false},
}

var wellKnownNAT64 = netip.MustParsePrefix("64:ff9b::/96")

// publicPackAddress rejects non-public and transition destinations. The standard
// NAT64 prefix is allowed only when its embedded IPv4 destination is public.
func publicPackAddress(addr netip.Addr) bool {
	addr = addr.WithZone("").Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	if wellKnownNAT64.Contains(addr) {
		b := addr.As16()
		return publicPackAddress(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	allowed, bits := true, -1
	for _, network := range specialUseNetworks {
		if network.prefix.Bits() > bits && network.prefix.Contains(addr) {
			allowed, bits = network.public, network.prefix.Bits()
		}
	}
	return allowed
}

// dialPublicOnly checks the resolved address at connect time, after DNS, so a
// server-supplied hostname cannot resolve to a private address.
func dialPublicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if !publicPackAddress(addr) {
		return errors.New("resource pack host is not a public address")
	}
	return nil
}
