package minecraft

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/df-mc/go-nethernet/endpoint"
)

// AddressNetwork is a Network for a server named by host:port. Like the vanilla client joining
// such a server, it probes the address for NetherNet HTTP signaling and dials NetherNet when the
// probe succeeds, RakNet otherwise. The choice is made per dial and never cached.
type AddressNetwork struct {
	// RakNet dials servers that do not answer the probe.
	RakNet RakNet
	// NetherNet configures NetherNet dials. Its Signaling and DialSignaling are replaced by HTTP
	// signaling to the probed endpoint.
	NetherNet NetherNet
	// HTTPClient sends the probe and signaling requests; nil uses http.DefaultTransport.
	// Redirects are never followed.
	HTTPClient *http.Client
	// ServerTrust, when set, decides whether to join a NetherNet server and replaces the NetherNet
	// dialer's server identity checks; servers without an identity are then refused, as in vanilla.
	ServerTrust ServerTrust
}

// netherNetProbeTimeout bounds the whole probe, after which the vanilla client joins over RakNet.
const netherNetProbeTimeout = 3 * time.Second

// defaultServerPort is the port vanilla probes when a server address has none.
const defaultServerPort = 19132

// Select returns the network to dial address with: RakNet, or NetherNet bound to the endpoint
// that answered the probe. It fails only when ctx ends first.
func (n AddressNetwork) Select(ctx context.Context, address string) (Network, error) {
	client := probeHTTPClient(n.HTTPClient)
	host, port := splitServerAddress(address)
	endpoint, err := probeNetherNet(ctx, client, host, port, netherNetProbeTimeout)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return n.RakNet, nil
	}
	return httpNetherNet{nethernet: n.NetherNet, url: endpoint, endpoint: explicitPort(endpoint), client: client, trust: n.ServerTrust}, nil
}

// DialContext ...
func (n AddressNetwork) DialContext(ctx context.Context, address string) (net.Conn, error) {
	network, err := n.Select(ctx, address)
	if err != nil {
		return nil, err
	}
	return network.DialContext(ctx, address)
}

// DialContextIdentityProvider presents the identity on NetherNet; RakNet dials ignore it.
func (n AddressNetwork) DialContextIdentityProvider(ctx context.Context, address, token string, key *ecdsa.PrivateKey, identityProvider string) (net.Conn, error) {
	network, err := n.Select(ctx, address)
	if err != nil {
		return nil, err
	}
	if dialer, ok := network.(identityProviderDialer); ok {
		return dialer.DialContextIdentityProvider(ctx, address, token, key, identityProvider)
	}
	return network.DialContext(ctx, address)
}

// PingContext pings over RakNet.
func (n AddressNetwork) PingContext(ctx context.Context, address string) ([]byte, error) {
	return n.RakNet.PingContext(ctx, address)
}

// Listen ...
func (AddressNetwork) Listen(string) (NetworkListener, error) {
	return nil, errors.New("minecraft: AddressNetwork.Listen: not supported")
}

// ProbeNetherNet returns the base URL of the NetherNet HTTP signaling endpoint a server answers
// on. Candidates are tried in turn, HTTPS first, within three seconds in total; one answers when
// GET {url}/v1/join returns a 2xx status. A port of zero also tries the scheme's default port.
func ProbeNetherNet(ctx context.Context, client *http.Client, host string, port uint16) (string, error) {
	return probeNetherNet(ctx, probeHTTPClient(client), host, port, netherNetProbeTimeout)
}

func probeNetherNet(ctx context.Context, client *http.Client, host string, port uint16, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var errs []error
	for _, endpoint := range probeEndpoints(host, port) {
		err := probeEndpoint(ctx, client, endpoint)
		if err == nil {
			return endpoint, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return "", fmt.Errorf("probe NetherNet: %w", errors.Join(errs...))
}

// probeEndpoints lists base URLs in vanilla's order. Hosts are formatted unbracketed as vanilla
// formats them, so an IPv6 literal never answers.
func probeEndpoints(host string, port uint16) []string {
	if port != 0 {
		return []string{
			fmt.Sprintf("https://%s:%d", host, port),
			fmt.Sprintf("http://%s:%d", host, port),
		}
	}
	return []string{
		fmt.Sprintf("https://%s:%d", host, defaultServerPort),
		"https://" + host,
		fmt.Sprintf("http://%s:%d", host, defaultServerPort),
		"http://" + host,
	}
}

func probeEndpoint(ctx context.Context, client *http.Client, endpoint string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/join", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	// The answer counts only once its whole body has arrived; the probe deadline bounds the read,
	// so a stalled or endless body loses to the timeout.
	_, err = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if err != nil {
		return fmt.Errorf("%s: read body: %w", endpoint, err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("%s: status %d", endpoint, response.StatusCode)
	}
	return nil
}

// probeHTTPClient copies client with redirects disabled, so a 3xx counts as no answer.
func probeHTTPClient(client *http.Client) *http.Client {
	copied := http.Client{}
	if client != nil {
		copied = *client
	}
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copied
}

// splitServerAddress splits host:port; an address without a valid port gets port zero.
func splitServerAddress(address string) (string, uint16) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return address, 0
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return host, 0
	}
	return host, uint16(port)
}

// httpNetherNet dials NetherNet through one server's HTTP signaling endpoint.
type httpNetherNet struct {
	nethernet NetherNet
	url       string // the URL that answered the probe
	endpoint  string // url with an explicit port, the dial address endpoint.Client expects
	client    *http.Client
	trust     ServerTrust
}

// transport returns NetherNet signaling through the endpoint, opening fresh signaling per dial.
func (n httpNetherNet) transport() NetherNet {
	transport := n.nethernet
	transport.Signaling = nil
	transport.DialSignaling = func(context.Context, string) (SignalingConn, error) {
		return endpointSignaling{endpoint.ClientConfig{HTTPClient: n.client, Logger: n.nethernet.Log}.New()}, nil
	}
	if n.trust != nil {
		transport.Dialer.AllowIdentitylessServer = false
		transport.Dialer.VerifyServerToken = func(ctx context.Context, token, _ string) (*ecdsa.PublicKey, error) {
			key, err := serverTokenKey(token)
			if err != nil {
				return nil, err
			}
			trusted, err := n.trust.TrustServer(ctx, n.url, key)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrServerNotTrusted, err)
			}
			if !trusted {
				return nil, ErrServerNotTrusted
			}
			return key, nil
		}
	}
	return transport
}

// DialContext ignores address: the endpoint already names the server.
func (n httpNetherNet) DialContext(ctx context.Context, _ string) (net.Conn, error) {
	return n.transport().DialContext(ctx, n.endpoint)
}

// DialContextIdentity ...
func (n httpNetherNet) DialContextIdentity(ctx context.Context, _ string, token string, key *ecdsa.PrivateKey) (net.Conn, error) {
	return n.transport().DialContextIdentity(ctx, n.endpoint, token, key)
}

// DialContextIdentityProvider ...
func (n httpNetherNet) DialContextIdentityProvider(ctx context.Context, _ string, token string, key *ecdsa.PrivateKey, identityProvider string) (net.Conn, error) {
	return n.transport().DialContextIdentityProvider(ctx, n.endpoint, token, key, identityProvider)
}

// PingContext ...
func (httpNetherNet) PingContext(context.Context, string) ([]byte, error) {
	return nil, errors.New("minecraft: NetherNet HTTP signaling: ping not supported")
}

// Listen ...
func (httpNetherNet) Listen(string) (NetworkListener, error) {
	return nil, errors.New("minecraft: NetherNet HTTP signaling: listen not supported")
}

// endpointSignaling owns an endpoint.Client for one dial; the client holds no connection to close.
type endpointSignaling struct{ *endpoint.Client }

// Close ...
func (endpointSignaling) Close() error { return nil }

// explicitPort adds the scheme's default port to a probed URL that names none.
func explicitPort(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Port() != "" {
		return rawURL
	}
	port := "443"
	if u.Scheme == "http" {
		port = "80"
	}
	u.Host = net.JoinHostPort(u.Hostname(), port)
	return u.String()
}
