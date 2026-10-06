package minecraft

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet"
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
	return httpNetherNet{nethernet: n.NetherNet, endpoint: endpoint, client: client}, nil
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
	endpoint  string
	client    *http.Client
}

// transport returns NetherNet signaling through the endpoint, opening fresh signaling per dial.
func (n httpNetherNet) transport() NetherNet {
	transport := n.nethernet
	transport.Signaling = nil
	transport.DialSignaling = func(context.Context, string) (SignalingConn, error) {
		return newHTTPSignaling(n.client, n.endpoint), nil
	}
	return transport
}

// remoteNetworkID returns the random ID vanilla addresses an HTTP signaling server by.
func remoteNetworkID() string { return strconv.FormatUint(rand.Uint64(), 10) }

// DialContext ignores address: the endpoint already names the server.
func (n httpNetherNet) DialContext(ctx context.Context, _ string) (net.Conn, error) {
	return n.transport().DialContext(ctx, remoteNetworkID())
}

// DialContextIdentity ...
func (n httpNetherNet) DialContextIdentity(ctx context.Context, _ string, token string, key *ecdsa.PrivateKey) (net.Conn, error) {
	return n.transport().DialContextIdentity(ctx, remoteNetworkID(), token, key)
}

// DialContextIdentityProvider ...
func (n httpNetherNet) DialContextIdentityProvider(ctx context.Context, _ string, token string, key *ecdsa.PrivateKey, identityProvider string) (net.Conn, error) {
	return n.transport().DialContextIdentityProvider(ctx, remoteNetworkID(), token, key, identityProvider)
}

// PingContext ...
func (httpNetherNet) PingContext(context.Context, string) ([]byte, error) {
	return nil, errors.New("minecraft: NetherNet HTTP signaling: ping not supported")
}

// Listen ...
func (httpNetherNet) Listen(string) (NetworkListener, error) {
	return nil, errors.New("minecraft: NetherNet HTTP signaling: listen not supported")
}

// maxSignalingBody bounds bodies read from a signaling endpoint.
const maxSignalingBody = 1 << 20

// httpSignaling carries one negotiation over a server's HTTP signaling endpoint: the offer is
// POSTed to {endpoint}/v1/join/{id} and the response body is the answer. The endpoint has no
// channel for later signals, so candidates travel in the SDPs and trickle ICE is disabled.
type httpSignaling struct {
	client   *http.Client
	endpoint string
	localID  string
	ctx      context.Context
	cancel   context.CancelFunc

	mu        sync.Mutex
	notifiers map[uint64]nethernet.Notifier
	next      uint64
}

func newHTTPSignaling(client *http.Client, endpoint string) *httpSignaling {
	ctx, cancel := context.WithCancel(context.Background())
	return &httpSignaling{
		client:    client,
		endpoint:  endpoint,
		localID:   remoteNetworkID(),
		ctx:       ctx,
		cancel:    cancel,
		notifiers: make(map[uint64]nethernet.Notifier),
	}
}

// Signal sends an offer and delivers the answer; other signals have no channel and are dropped.
func (s *httpSignaling) Signal(ctx context.Context, signal *nethernet.Signal) error {
	if signal.Type != nethernet.SignalTypeOffer {
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/v1/join/"+signal.NetworkID, strings.NewReader(signal.Data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/sdp")
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxSignalingBody))
	if err != nil {
		return fmt.Errorf("read answer: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("signaling endpoint answered status %d", response.StatusCode)
	}
	if len(answer) == 0 {
		return errors.New("signaling endpoint answered without an SDP")
	}
	s.notify(&nethernet.Signal{
		Type:         nethernet.SignalTypeAnswer,
		ConnectionID: signal.ConnectionID,
		Data:         string(answer),
		NetworkID:    signal.NetworkID,
	})
	return nil
}

func (s *httpSignaling) notify(signal *nethernet.Signal) {
	s.mu.Lock()
	notifiers := make([]nethernet.Notifier, 0, len(s.notifiers))
	for _, notifier := range s.notifiers {
		notifiers = append(notifiers, notifier)
	}
	s.mu.Unlock()
	for _, notifier := range notifiers {
		notifier.NotifySignal(signal)
	}
}

// Notify ...
func (s *httpSignaling) Notify(n nethernet.Notifier) (stop func()) {
	s.mu.Lock()
	id := s.next
	s.next++
	s.notifiers[id] = n
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.notifiers, id)
		s.mu.Unlock()
	}
}

// Context ...
func (s *httpSignaling) Context() context.Context { return s.ctx }

// Credentials returns nil: the endpoint advertises no ICE servers.
func (s *httpSignaling) Credentials(context.Context) (*nethernet.Credentials, error) {
	return nil, nil
}

// NetworkID ...
func (s *httpSignaling) NetworkID() string { return s.localID }

// PongData ...
func (s *httpSignaling) PongData([]byte) {}

// DisableTrickleICE ...
func (s *httpSignaling) DisableTrickleICE() bool { return true }

// Close ...
func (s *httpSignaling) Close() error {
	s.cancel()
	return nil
}
