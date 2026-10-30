package minecraft

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/df-mc/go-nethernet/endpoint"
)

// AddressNetwork is a Network for a server named by host:port. Like the vanilla client joining
// such a server, it probes the address for NetherNet HTTP signaling and dials NetherNet when the
// probe succeeds, RakNet otherwise. Vanilla probes on every join; set Probes to reuse answers.
type AddressNetwork struct {
	// RakNet dials servers that do not answer the probe.
	RakNet RakNet
	// NetherNet configures NetherNet dials. Its Signaling and DialSignaling are replaced by HTTP
	// signaling to the probed endpoint.
	NetherNet NetherNet
	// HTTPClient sends the probe and signaling requests; nil uses http.DefaultTransport.
	// Redirects are never followed.
	HTTPClient *http.Client
	// ServerTrust, when set, decides whether to join a NetherNet server once it has proved its
	// identity; servers without an identity are then refused, as in vanilla. A decision slow enough
	// for the server to drop the idle connection is followed by one silent redial.
	ServerTrust ServerTrust
	// Probes, when set, reuses probe answers. Answers can depend on HTTPClient, so share a cache
	// only between networks whose clients reach servers the same way. When nil, every dial probes.
	Probes *ProbeCache
	// RakNetAfterNetherNetFailure makes a failed NetherNet dial store a RakNet answer in Probes, so
	// later dials join over RakNet until it expires or fails too. Vanilla probes again instead.
	// A cancelled dial or a server refused by ServerTrust is probed again either way.
	RakNetAfterNetherNetFailure bool

	probeHeadStart   time.Duration // overrides httpProbeHeadStart in tests
	probeTimeout     time.Duration // overrides netherNetProbeTimeout in tests
	trustRedialAfter time.Duration // overrides trustRedialAfter in tests
}

// netherNetProbeTimeout bounds the whole probe, after which the vanilla client joins over RakNet.
const netherNetProbeTimeout = 6 * time.Second

// httpProbeHeadStart is how long the HTTPS batch runs alone at most before HTTP is asked too.
// Vanilla waits for every HTTPS request, so a dropped 443 hides HTTP until the timeout.
const httpProbeHeadStart = time.Second

// defaultServerPort is the port vanilla probes when a server address has none.
const defaultServerPort = 19132

// transportSelector is a Network that chooses the transport to dial an address with.
type transportSelector interface {
	Select(ctx context.Context, address string) (Network, error)
}

// Select returns the network to dial address with: RakNet, or NetherNet bound to the endpoint
// that answered the probe. It fails only when ctx ends first.
func (n AddressNetwork) Select(ctx context.Context, address string) (Network, error) {
	client := probeHTTPClient(n.HTTPClient)
	host, port := splitServerAddress(address)
	// Vanilla keys its probe cache by the lower-cased host and the port exactly as given.
	choice := probeChoice{cache: n.Probes, key: probeKey{host: strings.ToLower(host), port: port}}
	choice.entry = n.Probes.lookup(choice.key)
	if choice.entry == nil {
		endpoint, err := n.probe(ctx, client, probeBatches(host, port))
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			endpoint = ""
		}
		choice.entry = n.Probes.store(choice.key, endpoint)
	} else if choice.entry.endpoint != "" {
		// Vanilla still asks a remembered URL before every join, and joins over RakNet if it no
		// longer answers.
		if _, err := n.probe(ctx, client, [][]string{{choice.entry.endpoint}}); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return probedRakNet{RakNet: n.RakNet, choice: choice}, nil
		}
	}
	if choice.entry.endpoint == "" {
		return probedRakNet{RakNet: n.RakNet, choice: choice}, nil
	}
	return NetherNetHTTP{URL: choice.entry.endpoint, NetherNet: n.NetherNet, HTTPClient: n.HTTPClient, ServerTrust: n.ServerTrust, trustRedialAfter: n.trustRedialAfter, choice: choice, rakNetAfterFailure: n.RakNetAfterNetherNetFailure}, nil
}

// probe runs probeNetherNet with the package timings unless a test overrides them.
func (n AddressNetwork) probe(ctx context.Context, client *http.Client, batches [][]string) (string, error) {
	return probeNetherNet(ctx, client, batches, cmp.Or(n.probeHeadStart, httpProbeHeadStart), cmp.Or(n.probeTimeout, netherNetProbeTimeout))
}

// probeCacheTTL bounds how long a probe answer is reused, so a server that changes transport
// without failing dials on the old one is picked up again.
const probeCacheTTL = 10 * time.Minute

// ProbeCache holds AddressNetwork probe answers per host and port for ten minutes, or until a dial
// through one fails. The zero value is ready to use.
type ProbeCache struct {
	mu      sync.Mutex
	entries map[probeKey]*probeEntry
}

type probeKey struct {
	host string
	port uint16
}

// probeEntry is one probe answer: a NetherNet endpoint, or "" for RakNet.
type probeEntry struct {
	endpoint string
	expires  time.Time
}

// lookup returns an unexpired probe answer, or nil.
func (c *ProbeCache) lookup(key probeKey) *probeEntry {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	if entry == nil || !time.Now().Before(entry.expires) {
		return nil
	}
	return entry
}

// store records a probe answer, removes expired entries and returns the answer. A nil cache
// returns it unrecorded.
func (c *ProbeCache) store(key probeKey, endpoint string) *probeEntry {
	now := time.Now()
	entry := &probeEntry{endpoint: endpoint, expires: now.Add(probeCacheTTL)}
	if c == nil {
		return entry
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[probeKey]*probeEntry)
	}
	for k, stored := range c.entries {
		if !now.Before(stored.expires) {
			delete(c.entries, k)
		}
	}
	c.entries[key] = entry
	return entry
}

// probeChoice is the probe answer a Network was built from.
type probeChoice struct {
	cache *ProbeCache
	key   probeKey
	entry *probeEntry
}

// forgetAfter drops the answer after any failed dial, so the next Select probes again. An answer
// stored since by another Select is kept.
func (p probeChoice) forgetAfter(err error) {
	p.replaceAfter(err, nil)
}

// rakNetAfter replaces the answer with RakNet after any failed dial, keeping a newer answer.
func (p probeChoice) rakNetAfter(err error) {
	p.replaceAfter(err, &probeEntry{expires: time.Now().Add(probeCacheTTL)})
}

// replaceAfter swaps the answer for next, or drops it when next is nil, if err is set.
func (p probeChoice) replaceAfter(err error, next *probeEntry) {
	if p.cache == nil || err == nil {
		return
	}
	p.cache.mu.Lock()
	defer p.cache.mu.Unlock()
	if p.cache.entries[p.key] != p.entry {
		return
	}
	if next == nil {
		delete(p.cache.entries, p.key)
		return
	}
	p.cache.entries[p.key] = next
}

// loginAddress returns the server address a vanilla client puts in its login after joining this
// endpoint: the URL, with its port.
func (n NetherNetHTTP) loginAddress() string {
	return explicitPort(n.URL)
}

// probedRakNet is the RakNet a probe chose; a failed dial forgets that choice.
type probedRakNet struct {
	RakNet
	choice probeChoice
}

// DialContext ...
func (r probedRakNet) DialContext(ctx context.Context, address string) (net.Conn, error) {
	conn, err := r.RakNet.DialContext(ctx, address)
	r.choice.forgetAfter(err)
	return conn, err
}

// DialContext ...
func (n AddressNetwork) DialContext(ctx context.Context, address string) (net.Conn, error) {
	network, err := n.Select(ctx, address)
	if err != nil {
		return nil, err
	}
	return network.DialContext(ctx, address)
}

// DialContextIdentity presents the identity, self-signed when token is empty, on NetherNet; RakNet
// dials ignore it.
func (n AddressNetwork) DialContextIdentity(ctx context.Context, address, token string, key *ecdsa.PrivateKey) (net.Conn, error) {
	network, err := n.Select(ctx, address)
	if err != nil {
		return nil, err
	}
	if dialer, ok := network.(identityDialer); ok {
		return dialer.DialContextIdentity(ctx, address, token, key)
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

// ProbeNetherNet returns the base URL of the first NetherNet HTTP signaling endpoint that answers
// GET {url}/v1/join with a 2xx within six seconds, asking HTTPS before HTTP and, for port 19132 or
// zero, the schemes' default ports too. Unlike vanilla, HTTP is asked after a one-second head
// start at the latest, and on the game port as soon as HTTPS there fails.
func ProbeNetherNet(ctx context.Context, client *http.Client, host string, port uint16) (string, error) {
	return probeNetherNet(ctx, probeHTTPClient(client), probeBatches(host, port), httpProbeHeadStart, netherNetProbeTimeout)
}

// probeNetherNet returns the first endpoint to answer with a 2xx, cancelling the rest even if a
// preferred one is about to answer. Each batch starts once the one before it has finished or
// headStart has passed; its first endpoint, the game port, also starts once the one before fails.
func probeNetherNet(ctx context.Context, client *http.Client, batches [][]string, headStart, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	total := 0
	for _, endpoints := range batches {
		total += len(endpoints)
	}
	results := make(chan probeResult, total)
	var before *probeBatch
	for i, endpoints := range batches {
		batch, previous := newProbeBatch(len(endpoints)), before
		startBy := time.Now().Add(time.Duration(i) * headStart)
		for j, endpoint := range endpoints {
			go func() {
				if previous != nil {
					previous.wait(ctx, startBy, j == 0)
				}
				err := ctx.Err()
				if err != nil {
					err = fmt.Errorf("%s: %w", endpoint, err)
				} else {
					err = probeEndpoint(ctx, client, endpoint)
				}
				batch.finish(j == 0, err)
				results <- probeResult{endpoint, err}
			}()
		}
		before = batch
	}
	var errs []error
	for range total {
		if r := <-results; r.err != nil {
			errs = append(errs, r.err)
		} else {
			return r.endpoint, nil
		}
	}
	return "", fmt.Errorf("probe NetherNet: %w", errors.Join(errs...))
}

// probeResult is one endpoint's answer; err is nil for a 2xx.
type probeResult struct {
	endpoint string
	err      error
}

// probeBatch tells the batch after it when to start.
type probeBatch struct {
	pending    atomic.Int32
	finished   chan struct{} // closed once every request has finished
	gameFailed chan struct{} // closed once the request to the game port has failed
}

func newProbeBatch(size int) *probeBatch {
	b := &probeBatch{finished: make(chan struct{}), gameFailed: make(chan struct{})}
	b.pending.Store(int32(size))
	return b
}

// finish records one finished request; game reports whether it went to the game port.
func (b *probeBatch) finish(game bool, err error) {
	if game && err != nil {
		close(b.gameFailed)
	}
	if b.pending.Add(-1) == 0 {
		close(b.finished)
	}
}

// wait blocks until the next batch may start: once this one has finished, at startBy, or, for the
// game port, once the game port here has failed.
func (b *probeBatch) wait(ctx context.Context, startBy time.Time, game bool) {
	var gameFailed <-chan struct{}
	if game {
		gameFailed = b.gameFailed
	}
	select {
	case <-b.finished:
	case <-gameFailed:
	case <-time.After(time.Until(startBy)):
	case <-ctx.Done():
	}
}

// probeBatches lists base URLs in vanilla's order: the HTTPS batch, then the HTTP batch, each with
// the game port first. Hosts are formatted unbracketed as vanilla formats them, so an IPv6 literal
// never answers.
func probeBatches(host string, port uint16) [][]string {
	if port != 0 && port != defaultServerPort {
		return [][]string{
			{fmt.Sprintf("https://%s:%d", host, port)},
			{fmt.Sprintf("http://%s:%d", host, port)},
		}
	}
	return [][]string{
		{fmt.Sprintf("https://%s:%d", host, defaultServerPort), "https://" + host},
		{fmt.Sprintf("http://%s:%d", host, defaultServerPort), "http://" + host},
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

// NetherNetHTTP is a Network that dials NetherNet through one server's HTTP signaling endpoint and
// never falls back to RakNet. When URL is empty, the endpoint is the one ProbeNetherNet finds for
// the dial address.
type NetherNetHTTP struct {
	// URL is the endpoint's base URL, such as https://play.example.com:19132. When set, the dial
	// address is ignored and nothing is probed.
	URL string
	// NetherNet configures the dial; its Signaling and DialSignaling are replaced by the endpoint's.
	NetherNet NetherNet
	// HTTPClient sends the probe and signaling requests; nil uses http.DefaultTransport. Redirects
	// are never followed.
	HTTPClient *http.Client
	// ServerTrust, when set, decides whether to join once the server has proved its identity;
	// servers without an identity are then refused.
	ServerTrust ServerTrust

	trustRedialAfter   time.Duration // overrides trustRedialAfter in tests
	choice             probeChoice   // the AddressNetwork answer to drop, or replace by RakNet, when a dial fails
	rakNetAfterFailure bool          // a failed dial answers RakNet instead of forgetting the choice
}

// Select returns n with its endpoint resolved: URL when set, otherwise the endpoint ProbeNetherNet
// finds for address. It fails when nothing answers.
func (n NetherNetHTTP) Select(ctx context.Context, address string) (Network, error) {
	return n.resolve(ctx, address)
}

func (n NetherNetHTTP) resolve(ctx context.Context, address string) (NetherNetHTTP, error) {
	if n.URL != "" {
		return n, nil
	}
	host, port := splitServerAddress(address)
	found, err := ProbeNetherNet(ctx, n.HTTPClient, host, port)
	if err != nil {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		return n, fmt.Errorf("minecraft: no NetherNet HTTP signaling at %s: %w", address, err)
	}
	n.URL = found
	return n, nil
}

// trustRedialAfter is how long a trust decision may keep a fresh connection idle before it is
// replaced with a new one: servers drop a connection left idle for about ten seconds.
const trustRedialAfter = 5 * time.Second

// transport returns NetherNet signaling through the endpoint, opening fresh signaling per dial.
func (n NetherNetHTTP) transport() NetherNet {
	transport := n.NetherNet
	transport.Signaling = nil
	client := probeHTTPClient(n.HTTPClient)
	transport.DialSignaling = func(context.Context, string) (SignalingConn, error) {
		return endpointSignaling{endpoint.ClientConfig{HTTPClient: client, Logger: n.NetherNet.Log}.New()}, nil
	}
	if n.ServerTrust != nil {
		transport.Dialer.AllowIdentitylessServer = false
	}
	return transport
}

func (n NetherNetHTTP) redialAfter() time.Duration {
	if n.trustRedialAfter > 0 {
		return n.trustRedialAfter
	}
	return trustRedialAfter
}

// dial resolves the endpoint, runs a NetherNet dial to it and asks ServerTrust about the key the
// server proved it holds. A decision slow enough that the server may have dropped the idle
// connection is followed by a redial, which does not ask again about keys already trusted.
func (n NetherNetHTTP) dial(ctx context.Context, address string, dial func(t NetherNet, endpoint string) (net.Conn, error)) (conn net.Conn, err error) {
	defer func() {
		if n.rakNetAfterFailure && !errors.Is(err, ErrServerNotTrusted) && !errors.Is(ctx.Err(), context.Canceled) {
			n.choice.rakNetAfter(err)
			return
		}
		n.choice.forgetAfter(err)
	}()
	if n, err = n.resolve(ctx, address); err != nil {
		return nil, err
	}
	endpoint := explicitPort(n.URL)
	var trusted []*ecdsa.PublicKey
	for {
		conn, err := dial(n.transport(), endpoint)
		if err != nil || n.ServerTrust == nil {
			return conn, err
		}
		holder, ok := conn.(interface{ PublicKey() *ecdsa.PublicKey })
		key := (*ecdsa.PublicKey)(nil)
		if ok {
			key = holder.PublicKey()
		}
		if key == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: server presented no verified identity", ErrServerNotTrusted)
		}
		if slices.ContainsFunc(trusted, func(known *ecdsa.PublicKey) bool { return known.Equal(key) }) {
			return conn, nil
		}
		start := time.Now()
		ok, err = n.ServerTrust.TrustServer(ctx, n.URL, key)
		if err != nil || !ok {
			_ = conn.Close()
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrServerNotTrusted, err)
			}
			return nil, ErrServerNotTrusted
		}
		if err := ctx.Err(); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if time.Since(start) <= n.redialAfter() {
			return conn, nil
		}
		trusted = append(trusted, key)
		_ = conn.Close()
	}
}

// DialContext dials the endpoint; address is used only to find one when URL is empty.
func (n NetherNetHTTP) DialContext(ctx context.Context, address string) (net.Conn, error) {
	return n.dial(ctx, address, func(t NetherNet, endpoint string) (net.Conn, error) { return t.DialContext(ctx, endpoint) })
}

// DialContextIdentity ...
func (n NetherNetHTTP) DialContextIdentity(ctx context.Context, address, token string, key *ecdsa.PrivateKey) (net.Conn, error) {
	return n.dial(ctx, address, func(t NetherNet, endpoint string) (net.Conn, error) {
		return t.DialContextIdentity(ctx, endpoint, token, key)
	})
}

// DialContextIdentityProvider ...
func (n NetherNetHTTP) DialContextIdentityProvider(ctx context.Context, address, token string, key *ecdsa.PrivateKey, identityProvider string) (net.Conn, error) {
	return n.dial(ctx, address, func(t NetherNet, endpoint string) (net.Conn, error) {
		return t.DialContextIdentityProvider(ctx, endpoint, token, key, identityProvider)
	})
}

// PingContext ...
func (NetherNetHTTP) PingContext(context.Context, string) ([]byte, error) {
	return nil, errors.New("minecraft: NetherNet HTTP signaling: ping not supported")
}

// Listen ...
func (NetherNetHTTP) Listen(string) (NetworkListener, error) {
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
