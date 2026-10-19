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
