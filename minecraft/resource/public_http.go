package resource

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// NewPublicHTTPClient returns a resource-pack download client that rejects
// loopback, private, link-local and shared-address-space destinations after DNS.
// Redirects must use HTTPS and are limited to five requests. Callers validate
// the initial URL and supply request deadlines and size limits.
func NewPublicHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, Control: dialPublicOnly}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) >= 5 {
				return errors.New("resource pack redirect refused")
			}
			return nil
		},
	}
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

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
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || sharedAddressSpace.Contains(addr) {
		return errors.New("resource pack host is not a public address")
	}
	return nil
}
