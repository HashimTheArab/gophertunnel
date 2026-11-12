package minecraft

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"encoding/json"
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

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/endpoint"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
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
	// Probes, when set, reuses probe answers, keyed by the reported protocol. Answers can depend on
	// HTTPClient, so share a cache only between networks whose clients reach servers the same way.
	// When nil, every dial probes.
	Probes *ProbeCache
	// RakNetAfterNetherNetFailure makes a NetherNet dial that never reached the server, by timing
	// out or failing to connect to signaling, store a RakNet answer in Probes until it expires or
	// fails too. Any other failure, such as a refused identity or a server error, is probed again,
	// as vanilla probes again after every failure.
	RakNetAfterNetherNetFailure bool
	// ProbeClientInfo is reported on the probe, as the vanilla client reports its own, by joins and
	// pings alike. A Dialer fills its unset fields from the dial; any still unset report
	// DefaultProtocol on Android.
	ProbeClientInfo endpoint.ClientInfo

	probeHeadStart   time.Duration // overrides HTTPProbeHeadStart in tests
	probeTimeout     time.Duration // overrides netherNetProbeTimeout in tests
	trustRedialAfter time.Duration // overrides trustRedialAfter in tests
}

// probeClientInfo returns ProbeClientInfo with each unset field reporting DefaultProtocol on Android,
// so the probe never carries the partial info servers refuse.
func (n AddressNetwork) probeClientInfo() endpoint.ClientInfo {
	return fillClientInfo(n.ProbeClientInfo, defaultProbeClientInfo())
}

// defaultProbeClientInfo is the info a probe reports when no dial supplies it.
func defaultProbeClientInfo() endpoint.ClientInfo {
	return endpoint.ClientInfo{Version: DefaultProtocol.Ver(), Protocol: int(DefaultProtocol.ID()), Platform: int(protocol.DeviceAndroid)}
}

// withProbeClientInfo returns n reporting info in the fields of ProbeClientInfo left unset.
func (n AddressNetwork) withProbeClientInfo(info endpoint.ClientInfo) transportSelector {
	n.ProbeClientInfo = fillClientInfo(n.ProbeClientInfo, info)
	return n
}

// fillClientInfo returns info with each unset field taken from fallback.
func fillClientInfo(info, fallback endpoint.ClientInfo) endpoint.ClientInfo {
	return endpoint.ClientInfo{Version: cmp.Or(info.Version, fallback.Version), Protocol: cmp.Or(info.Protocol, fallback.Protocol), Platform: cmp.Or(info.Platform, fallback.Platform)}
}

// netherNetProbeTimeout bounds the whole probe, after which the join goes over RakNet. Vanilla
// waits up to a minute; a shorter bound keeps that fallback quick.
const netherNetProbeTimeout = 6 * time.Second

// HTTPProbeHeadStart is how long the HTTPS batch runs alone at most before HTTP is asked too, as
// in vanilla. HTTP starts sooner once every HTTPS request has failed.
const HTTPProbeHeadStart = 3 * time.Second

// defaultServerPort is the game port probed, besides the scheme's own, when a server address names
// no port.
const defaultServerPort = 19132

// transportSelector is a Network that chooses the transport to dial an address with.
type transportSelector interface {
	Select(ctx context.Context, address string) (Network, error)
}

// TransportError is a failed Dialer dial on a network that picks its transport per address, such
// as AddressNetwork. Network is the transport picked, which IsRakNet tells apart from NetherNet.
// A net.Error cause, such as a timeout, is found through Unwrap with errors.As.
type TransportError struct {
	Network Network
	Err     error
}

// Error returns Err's message unchanged.
func (e *TransportError) Error() string { return e.Err.Error() }

// Unwrap ...
func (e *TransportError) Unwrap() error { return e.Err }

// Select returns the network to dial address with: RakNet, or NetherNet bound to the endpoint
// that answered the probe. It fails only when ctx ends first.
func (n AddressNetwork) Select(ctx context.Context, address string) (Network, error) {
	choice, _, probeClient, err := n.resolveProbe(ctx, address)
	if err != nil {
		return nil, err
	}
	if probeClient == nil {
		return probedRakNet{RakNet: n.RakNet, choice: choice}, nil
	}
	return NetherNetHTTP{URL: choice.entry.endpoint, NetherNet: n.NetherNet, HTTPClient: n.HTTPClient, ServerTrust: n.ServerTrust, trustRedialAfter: n.trustRedialAfter, choice: choice, rakNetAfterFailure: n.RakNetAfterNetherNetFailure, probeClient: probeClient}, nil
}

// resolveProbe returns the answer Select dials by: the one Probes remembers, asked again first, or a
// fresh probe it stores, with the body and the client whose network ID the offer must reuse.
func (n AddressNetwork) resolveProbe(ctx context.Context, address string) (choice probeChoice, body []byte, probeClient *endpoint.Client, err error) {
	info := n.probeClientInfo()
	host, port := splitServerAddress(address)
	choice = rememberedChoice(n.Probes, host, port, info)
	if choice.rakNet() {
		return choice, nil, nil, nil
	}
	batches := probeBatches(host, port)
	if choice.entry != nil {
		batches = [][]string{{choice.entry.endpoint}}
	}
	client := probeHTTPClient(n.HTTPClient)
	probeClient = endpoint.ClientConfig{HTTPClient: client, Logger: n.NetherNet.Log, ClientInfo: info}.New()
	found, body, status, err := n.probe(ctx, client, batches, probeClient)
	switch {
	case choice.entry == nil:
	case err == nil && status && !choice.entry.status:
		choice = choice.replace(&probeEntry{endpoint: found, status: true, expires: choice.entry.expires})
	case errors.Is(err, errNotStatus) || err == nil && !status && choice.entry.status:
		// The remembered endpoint answers with less than it did, such as a website's page.
		choice = choice.replace(nil)
		found, body, status, err = n.probe(ctx, client, probeBatches(host, port), probeClient)
	}
	if err != nil {
		if ctx.Err() != nil {
			return choice, nil, nil, ctx.Err()
		}
		if choice.entry == nil {
			choice.entry = n.Probes.store(choice.key, "", false)
		}
		return choice, nil, nil, nil
	}
	if choice.entry == nil {
		choice.entry = n.Probes.store(choice.key, found, status)
	}
	return choice, body, probeClient, nil
}

// rememberedChoice returns the answer cache remembers for host and port probed with info, with a
// nil entry when it has none. Vanilla keys its probe cache by the lower-cased host and the port
// exactly as given; the protocol is part of the key because a server may refuse outdated ones.
func rememberedChoice(cache *ProbeCache, host string, port uint16, info endpoint.ClientInfo) probeChoice {
	choice := probeChoice{cache: cache, key: probeKey{host: strings.ToLower(host), port: port, protocol: info.Protocol}}
	choice.entry = cache.lookup(choice.key)
	return choice
}

// probe runs probeNetherNet with the package timings unless a test overrides them.
func (n AddressNetwork) probe(ctx context.Context, client *http.Client, batches [][]string, probeClient *endpoint.Client) (string, []byte, bool, error) {
	return probeNetherNet(ctx, client, batches, cmp.Or(n.probeHeadStart, HTTPProbeHeadStart), cmp.Or(n.probeTimeout, netherNetProbeTimeout), probeClient)
}

// probeCacheTTL bounds how long a probe answer is reused, so a server that changes transport
// without failing dials on the old one is picked up again.
const probeCacheTTL = 10 * time.Minute

// ProbeCache holds AddressNetwork probe answers per host, port and reported protocol for ten
// minutes, or until a dial through one fails. The zero value is ready to use.
type ProbeCache struct {
	mu      sync.Mutex
	entries map[probeKey]*probeEntry
}

type probeKey struct {
	host     string
	port     uint16
	protocol int // the protocol the probe reported
}

// probeEntry is one probe answer: a NetherNet endpoint, or "" for RakNet.
type probeEntry struct {
	endpoint string
	status   bool // the endpoint answered with a status, not only some 2xx
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
func (c *ProbeCache) store(key probeKey, endpoint string, status bool) *probeEntry {
	now := time.Now()
	entry := &probeEntry{endpoint: endpoint, status: status, expires: now.Add(probeCacheTTL)}
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

// rakNet reports whether the answer is a remembered RakNet answer.
func (p probeChoice) rakNet() bool {
	return p.entry != nil && p.entry.endpoint == ""
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
	if err != nil {
		p.replace(next)
	}
}

// replace returns p holding next, which is stored in place of p's answer, or dropping it when next
// is nil, unless another Select has stored a newer answer since.
func (p probeChoice) replace(next *probeEntry) probeChoice {
	if p.cache != nil {
		p.cache.mu.Lock()
		if p.cache.entries[p.key] == p.entry {
			if next == nil {
				delete(p.cache.entries, p.key)
			} else {
				p.cache.entries[p.key] = next
			}
		}
		p.cache.mu.Unlock()
	}
	p.entry = next
	return p
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

// PingContext returns the server's status as RakNet pong data, from the NetherNet HTTP signaling
// endpoint a probe finds or over RakNet, whichever answers first. A NetherNet answer is the
// endpoint's status via [endpoint.Status.RakNet] (random server ID, ports 19132). Probe answers are
// shared with Select through Probes, and a failed RakNet ping drops its remembered answer.
func (n AddressNetwork) PingContext(ctx context.Context, address string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		pong []byte
		err  error
	}
	answers := make(chan answer, 2)
	host, port := splitServerAddress(address)
	remembered := rememberedChoice(n.Probes, host, port, n.probeClientInfo())
	go func() {
		pong, err := n.RakNet.PingContext(ctx, address)
		if remembered.rakNet() {
			remembered.forgetAfter(err)
		}
		answers <- answer{pong, err}
	}()
	go func() {
		pong, err := n.pingNetherNet(ctx, address)
		answers <- answer{pong, err}
	}()
	var errs []error
	for range 2 {
		a := <-answers
		if a.err == nil {
			return a.pong, nil
		}
		errs = append(errs, a.err)
	}
	return nil, errors.Join(errs...)
}

// errNoNetherNetEndpoint is pingNetherNet's answer for a server no endpoint answers for.
var errNoNetherNetEndpoint = errors.New("minecraft: no NetherNet HTTP signaling endpoint answered")

// pingNetherNet returns the status the probed NetherNet endpoint answered with, as RakNet pong data.
func (n AddressNetwork) pingNetherNet(ctx context.Context, address string) ([]byte, error) {
	choice, body, probeClient, err := n.resolveProbe(ctx, address)
	if err != nil {
		return nil, err
	}
	if probeClient == nil {
		return nil, errNoNetherNetEndpoint
	}
	status, err := parseProbeStatus(body)
	if err != nil {
		return nil, fmt.Errorf("%s: read status: %w", choice.entry.endpoint, err)
	}
	return status.RakNet(), nil
}

// parseProbeStatus reads the server status a NetherNet endpoint answers the probe with. An empty body
// or one decoding to no status, such as {} or null, is errNoStatus; any other is errNotStatus.
func parseProbeStatus(body []byte) (endpoint.Status, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return endpoint.Status{}, errNoStatus
	}
	var status endpoint.Status
	if err := json.Unmarshal(body, &status); err != nil {
		return endpoint.Status{}, fmt.Errorf("%w: %w", errNotStatus, err)
	}
	if status == (endpoint.Status{}) {
		return endpoint.Status{}, errNoStatus
	}
	return status, nil
}

var (
	// errNoStatus is an endpoint's answer that sets no status, as go-nethernet's handler answers
	// before one is set.
	errNoStatus = errors.New("no status")
	// errNotStatus is an answer that is not a status at all, such as a website's page.
	errNotStatus = errors.New("not a NetherNet status")
)

// Listen ...
func (AddressNetwork) Listen(string) (NetworkListener, error) {
	return nil, errors.New("minecraft: AddressNetwork.Listen: not supported")
}

// ProbeNetherNet returns the base URL of the NetherNet HTTP signaling endpoint that answers
// GET {url}/v1/join within six seconds, as probeNetherNet picks it, asking HTTPS before HTTP and, for
// port zero or 19132, port 19132 and the schemes' default ports. The GET carries no client info.
func ProbeNetherNet(ctx context.Context, client *http.Client, host string, port uint16) (string, error) {
	found, _, _, err := probeNetherNet(ctx, probeHTTPClient(client), probeBatches(host, port), HTTPProbeHeadStart, netherNetProbeTimeout, endpoint.ClientConfig{}.New())
	return found, err
}

// probeNetherNet returns the winning endpoint, the start of its body and whether that is a status. A
// status wins at once, a 2xx with errNoStatus only once nothing better can answer, and errNotStatus
// is no answer.
func probeNetherNet(ctx context.Context, client *http.Client, batches [][]string, headStart, timeout time.Duration, probe *endpoint.Client) (string, []byte, bool, error) {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	total := 0
	for _, endpoints := range batches {
		total += len(endpoints)
	}
	results := make(chan probeResult, total)
	var before *probeBatch
	order := 0
	for i, endpoints := range batches {
		batch, previous := newProbeBatch(len(endpoints)), before
		startBy := time.Now().Add(time.Duration(i) * headStart)
		for _, endpoint := range endpoints {
			r := probeResult{order: order, endpoint: endpoint}
			order++
			go func() {
				if previous != nil {
					previous.wait(ctx, startBy)
				}
				if r.err = ctx.Err(); r.err != nil {
					r.err = fmt.Errorf("%s: %w", endpoint, r.err)
				} else if r.body, r.err = probeEndpoint(ctx, client, endpoint, probe); r.err == nil {
					_, err := parseProbeStatus(r.body)
					r.status = err == nil
					if errors.Is(err, errNotStatus) {
						r.err = fmt.Errorf("%s: %w", endpoint, err)
					}
				}
				results <- r
				if r.err != nil || !r.status {
					batch.fail()
				}
			}()
		}
		before = batch
	}
	var errs []error
	var other *probeResult // the earliest 2xx in URL order that sets no status
	for range total {
		r := <-results
		switch {
		case r.err != nil:
			errs = append(errs, r.err)
		case r.status:
			return r.endpoint, r.body, true, nil
		case other == nil || r.order < other.order:
			other = &r
		}
	}
	if other != nil && parent.Err() == nil {
		return other.endpoint, other.body, false, nil
	}
	if err := parent.Err(); err != nil {
		errs = append(errs, err)
	}
	return "", nil, false, fmt.Errorf("probe NetherNet: %w", errors.Join(errs...))
}

// probeResult is one endpoint's answer, by its place in URL order; err is nil for a 2xx whose body is
// a server status, reported by status, or sets none.
type probeResult struct {
	order    int
	endpoint string
	body     []byte
	status   bool
	err      error
}

// probeBatch tells the batch after it when to start. A status ends the whole probe, so only failures,
// which here include a 2xx that sets no status, release the next batch.
type probeBatch struct {
	pending atomic.Int32
	failed  chan struct{} // closed once every request has failed
}

func newProbeBatch(size int) *probeBatch {
	b := &probeBatch{failed: make(chan struct{})}
	b.pending.Store(int32(size))
	return b
}

// fail records one failed request, after its result was sent.
func (b *probeBatch) fail() {
	if b.pending.Add(-1) == 0 {
		close(b.failed)
	}
}

// wait blocks until the next batch may start: once every request here has failed, or at startBy.
func (b *probeBatch) wait(ctx context.Context, startBy time.Time) {
	select {
	case <-b.failed:
	case <-time.After(time.Until(startBy)):
	case <-ctx.Done():
	}
}

// probeBatches lists base URLs in vanilla's order: the HTTPS batch, then the HTTP batch, each with
// the game port first. An address with no port or port 19132 also asks the scheme's own port.
// Unlike vanilla, IPv6 literals are bracketed, so such a host can answer.
func probeBatches(host string, port uint16) [][]string {
	if port != 0 && port != defaultServerPort {
		return [][]string{{probeURL("https", host, port)}, {probeURL("http", host, port)}}
	}
	return [][]string{
		{probeURL("https", host, defaultServerPort), probeURL("https", host, 0)},
		{probeURL("http", host, defaultServerPort), probeURL("http", host, 0)},
	}
}

// probeURL returns scheme://host:port, or scheme://host for port zero, bracketing an IPv6 literal
// whether or not host came bracketed.
func probeURL(scheme, host string, port uint16) string {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != 0 {
		host += ":" + strconv.Itoa(int(port))
	}
	return scheme + "://" + host
}

// maxProbeStatusSize is how much of a probe answer's body is kept as the server's status.
const maxProbeStatusSize = 64 << 10

// probeEndpoint asks endpoint for GET /v1/join and returns up to maxProbeStatusSize bytes of the
// body of a 2xx answer, which holds the server's status.
func probeEndpoint(ctx context.Context, client *http.Client, base string, probe *endpoint.Client) ([]byte, error) {
	request, err := probe.ProbeRequest(ctx, base)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	// The answer counts only once its whole body has arrived; the probe deadline bounds the read,
	// so a stalled or endless body loses to the timeout.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProbeStatusSize))
	if err == nil {
		_, err = io.Copy(io.Discard, response.Body)
	}
	_ = response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("%s: read body: %w", base, err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("%s: status %d", base, response.StatusCode)
	}
	return body, nil
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

// splitServerAddress splits host:port, unbracketing an IPv6 host; an address without a valid port
// gets port zero.
func splitServerAddress(address string) (string, uint16) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return strings.TrimSuffix(strings.TrimPrefix(address, "["), "]"), 0
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

	trustRedialAfter   time.Duration       // overrides trustRedialAfter in tests
	choice             probeChoice         // the AddressNetwork answer to drop, or replace by RakNet, when a dial fails
	rakNetAfterFailure bool                // a failed dial answers RakNet instead of forgetting the choice
	probeClient        *endpoint.Client    // the probe's client, reused for the offer so both carry one network ID
	probeInfo          endpoint.ClientInfo // the info a probe for an empty URL reports, filled by a Dialer
}

// withProbeClientInfo returns n reporting info in the unset fields of the probe it sends when URL is
// empty.
func (n NetherNetHTTP) withProbeClientInfo(info endpoint.ClientInfo) transportSelector {
	n.probeInfo = fillClientInfo(n.probeInfo, info)
	return n
}

// Select returns n with its endpoint resolved: URL when set, otherwise the endpoint a probe of
// address finds, as ProbeNetherNet would but reporting the client. It fails when nothing answers.
func (n NetherNetHTTP) Select(ctx context.Context, address string) (Network, error) {
	return n.resolve(ctx, address)
}

// fixedTransport names n as the transport of a Dialer dial whose Select found no endpoint.
func (n NetherNetHTTP) fixedTransport() Network { return n }

// resolve returns n with URL set, probing address for it when it is empty.
func (n NetherNetHTTP) resolve(ctx context.Context, address string) (NetherNetHTTP, error) {
	if n.URL != "" {
		return n, nil
	}
	host, port := splitServerAddress(address)
	// The offer reuses the probe's client, so its POST carries the network ID the GET announced.
	client := probeHTTPClient(n.HTTPClient)
	n.probeClient = endpoint.ClientConfig{HTTPClient: client, Logger: n.NetherNet.Log, ClientInfo: fillClientInfo(n.probeInfo, defaultProbeClientInfo())}.New()
	found, _, _, err := probeNetherNet(ctx, client, probeBatches(host, port), HTTPProbeHeadStart, netherNetProbeTimeout, n.probeClient)
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

// transport returns NetherNet signaling through the endpoint, with the probe's network ID when an
// AddressNetwork probed it and a fresh one otherwise.
func (n NetherNetHTTP) transport() NetherNet {
	transport := n.NetherNet
	transport.Signaling = nil
	signaling := n.probeClient
	if signaling == nil {
		signaling = endpoint.ClientConfig{HTTPClient: probeHTTPClient(n.HTTPClient), Logger: n.NetherNet.Log}.New()
	}
	transport.DialSignaling = func(context.Context, string) (SignalingConn, error) {
		return endpointSignaling{signaling}, nil
	}
	if n.ServerTrust != nil {
		transport.Dialer.AllowIdentitylessServer = false
	}
	if verify := transport.Dialer.VerifyServerIdentity; verify != nil {
		transport.Dialer.VerifyServerIdentity = func(ctx context.Context, identity *nethernet.RemoteIdentity) (*ecdsa.PublicKey, error) {
			key, err := verify(ctx, identity)
			if err != nil {
				return nil, identityError{err}
			}
			return key, nil
		}
	}
	return transport
}

// identityError is a failed server identity verification. It may wrap a network error or a
// deadline, but never means the server was unreachable.
type identityError struct{ error }

// Unwrap ...
func (e identityError) Unwrap() error { return e.error }

func (n NetherNetHTTP) redialAfter() time.Duration {
	if n.trustRedialAfter > 0 {
		return n.trustRedialAfter
	}
	return trustRedialAfter
}

// dial resolves the endpoint, runs a NetherNet dial to it and asks ServerTrust about the key the
// server proved it holds. A decision slow enough that the server may have dropped the idle
// connection is followed by a redial, which does not ask again about keys already trusted. Only a
// dial that never connected can answer RakNet; one that failed later reached the server.
func (n NetherNetHTTP) dial(ctx context.Context, address string, dial func(t NetherNet, endpoint string) (net.Conn, error)) (conn net.Conn, err error) {
	connected := false
	defer func() {
		if n.rakNetAfterFailure && !connected && unreachable(err) && !errors.Is(ctx.Err(), context.Canceled) {
			n.choice.rakNetAfter(err)
			return
		}
		n.choice.forgetAfter(err)
	}()
	if n, err = n.resolve(ctx, address); err != nil {
		return nil, err
	}
	target := explicitPort(n.URL)
	var trusted []*ecdsa.PublicKey
	for {
		conn, err := dial(n.transport(), target)
		if err != nil || n.ServerTrust == nil {
			return conn, err
		}
		connected = true
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

// unreachable reports whether a failed NetherNet dial never reached the server: no answer arrived,
// ICE never connected, the dial deadline passed, or the signaling endpoint could not be dialed.
// Rejections, identity verification failures, server errors and errors on an established connection
// are not.
func unreachable(err error) bool {
	if _, ok := errors.AsType[identityError](err); ok {
		return false
	}
	// go-nethernet names its WebRTC-level reachability failures with sentinels; the signaling
	// endpoint refusing the connection surfaces as a dial OpError from the HTTP transport.
	var opErr *net.OpError
	return errors.Is(err, nethernet.ErrICEConnectFailed) || errors.Is(err, nethernet.ErrNoAnswer) ||
		errors.Is(err, context.DeadlineExceeded) || errors.As(err, &opErr) && opErr.Op == "dial"
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

// endpointSignaling wraps the endpoint.Client a dial signals through; the client holds no connection
// to close.
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
