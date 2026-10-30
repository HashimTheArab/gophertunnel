package minecraft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/endpoint"
)

func TestProbeBatchesFollowVanillaOrder(t *testing.T) {
	t.Parallel()
	want := [][]string{{"https://example.com:19133"}, {"http://example.com:19133"}}
	if got := probeBatches("example.com", 19133); !reflect.DeepEqual(got, want) {
		t.Fatalf("probeBatches with port = %q, want %q", got, want)
	}
	want = [][]string{{"https://example.com:19132", "https://example.com"}, {"http://example.com:19132", "http://example.com"}}
	for _, port := range []uint16{0, 19132} {
		if got := probeBatches("example.com", port); !reflect.DeepEqual(got, want) {
			t.Fatalf("probeBatches with port %d = %q, want %q", port, got, want)
		}
	}
	want = [][]string{{"https://[::1]:19132", "https://[::1]"}, {"http://[::1]:19132", "http://[::1]"}}
	for _, host := range []string{"::1", "[::1]"} {
		if got := probeBatches(host, 0); !reflect.DeepEqual(got, want) {
			t.Fatalf("probeBatches for IPv6 literal %q = %q, want %q", host, got, want)
		}
	}
}

// An IPv6 literal, with or without its port, is probed at a bracketed URL that can answer.
func TestAddressNetworkProbesIPv6Literal(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "OK")
	})}}
	server.Start()
	t.Cleanup(server.Close)

	selected, err := AddressNetwork{}.Select(t.Context(), listener.Addr().String())
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if n, ok := selected.(httpNetherNet); !ok || n.url != server.URL {
		t.Fatalf("Select = %#v, want NetherNet at %q", selected, server.URL)
	}
	if host, port := splitServerAddress("[::1]"); host != "::1" || port != 0 {
		t.Fatalf("splitServerAddress([::1]) = %q, %d; want ::1 without a port", host, port)
	}
}

// Only failures release the next batch, so HTTP never starts behind an HTTPS answer.
func TestProbeBatchReleasesOnlyOnFailure(t *testing.T) {
	t.Parallel()
	released := func(ch <-chan struct{}) bool {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
	b := newProbeBatch(2)
	b.fail(false)
	if released(b.failed) || released(b.gameFailed) {
		t.Fatal("next batch released while the game port has not failed")
	}
	b.fail(true)
	if !released(b.failed) || !released(b.gameFailed) {
		t.Fatal("next batch held after every request failed")
	}
}

// The first endpoint of a batch to answer wins without waiting for one that never responds.
func TestProbeNetherNetFirstAnswerWins(t *testing.T) {
	t.Parallel()
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(hang.Close)
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(ok.Close)

	start := time.Now()
	endpoint, err := probeNetherNet(t.Context(), probeHTTPClient(nil), [][]string{{hang.URL, ok.URL}}, time.Minute, time.Minute)
	if err != nil || endpoint != ok.URL {
		t.Fatalf("probeNetherNet = %q, %v; want %q", endpoint, err, ok.URL)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("probeNetherNet waited %v for the endpoint that never answers", elapsed)
	}
}

// HTTP on the game port answers well before the timeout while HTTPS on 443 never does: at once
// when HTTPS on the game port fails, otherwise after the head start.
func TestProbeNetherNetDoesNotWaitForSilentHTTPS(t *testing.T) {
	t.Parallel()
	game := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(game.Close)
	gameHTTPS := "https://" + game.Listener.Addr().String()
	silentGame, silent443, silent80 := "https://"+silentTCPAddress(t), "https://"+silentTCPAddress(t), "http://"+silentTCPAddress(t)

	for name, test := range map[string]struct {
		batches   [][]string
		headStart time.Duration
	}{
		"https fails on the game port": {[][]string{{gameHTTPS, silent443}, {game.URL, silent80}}, netherNetProbeTimeout},
		"https never answers":          {[][]string{{silentGame, silent443}, {game.URL, silent80}}, httpProbeHeadStart},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			endpoint, err := probeNetherNet(t.Context(), probeHTTPClient(nil), test.batches, test.headStart, netherNetProbeTimeout)
			elapsed := time.Since(start)
			if err != nil || endpoint != game.URL {
				t.Fatalf("probeNetherNet = %q, %v; want %q", endpoint, err, game.URL)
			}
			if elapsed > netherNetProbeTimeout/2 {
				t.Fatalf("probeNetherNet took %v, want HTTP asked well before the %v timeout", elapsed, netherNetProbeTimeout)
			}
		})
	}
}

// A refused 443 does not start port 80 early, so a website answering there cannot beat a slower
// HTTPS game port.
func TestProbeNetherNetHoldsDefaultPortHTTPForTheHeadStart(t *testing.T) {
	t.Parallel()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	t.Cleanup(secure.Close)
	var webRequests atomic.Int32
	web := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { webRequests.Add(1) }))
	t.Cleanup(web.Close)
	refused443, gameHTTP := "https://"+closedTCPAddress(t), "http://"+closedTCPAddress(t)

	batches := [][]string{{secure.URL, refused443}, {gameHTTP, web.URL}}
	endpoint, err := probeNetherNet(t.Context(), probeHTTPClient(secure.Client()), batches, time.Minute, 5*time.Second)
	if err != nil || endpoint != secure.URL {
		t.Fatalf("probeNetherNet = %q, %v; want %q", endpoint, err, secure.URL)
	}
	if n := webRequests.Load(); n != 0 {
		t.Fatalf("port 80 asked %d times before the HTTPS batch finished or the head start passed", n)
	}
}

// HTTPS wins whenever its 2xx arrives first, and HTTP whenever its own does: a later answer is
// discarded, even over HTTPS.
func TestProbeNetherNetFirstSuccessWins(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		httpsDelay time.Duration
		headStart  time.Duration
		httpStatus int
		wantHTTPS  bool
		httpAsked  bool
	}{
		"https before the head start":       {headStart: time.Minute, httpStatus: http.StatusOK, wantHTTPS: true},
		"https after http fails":            {httpsDelay: 200 * time.Millisecond, headStart: 10 * time.Millisecond, httpStatus: http.StatusNotFound, wantHTTPS: true, httpAsked: true},
		"http answers first after the head": {httpsDelay: time.Minute, headStart: 10 * time.Millisecond, httpStatus: http.StatusOK, httpAsked: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(test.httpsDelay):
				case <-r.Context().Done():
				}
			}))
			t.Cleanup(secure.Close)
			var httpRequests atomic.Int32
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httpRequests.Add(1)
				w.WriteHeader(test.httpStatus)
			}))
			t.Cleanup(plain.Close)

			endpoint, err := probeNetherNet(t.Context(), probeHTTPClient(secure.Client()), [][]string{{secure.URL}, {plain.URL}}, test.headStart, 5*time.Second)
			want := plain.URL
			if test.wantHTTPS {
				want = secure.URL
			}
			if err != nil || endpoint != want {
				t.Fatalf("probeNetherNet = %q, %v; want %q", endpoint, err, want)
			}
			if asked := httpRequests.Load() > 0; asked != test.httpAsked {
				t.Fatalf("HTTP asked = %v, want %v", asked, test.httpAsked)
			}
		})
	}
}

func TestProbeNetherNetPrefersHTTPS(t *testing.T) {
	t.Parallel()
	var requests []string
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		_, _ = io.WriteString(w, "OK")
	}))
	t.Cleanup(server.Close)
	host, port := serverHostPort(t, server.Listener.Addr())

	endpoint, err := ProbeNetherNet(t.Context(), server.Client(), host, port)
	if err != nil {
		t.Fatalf("ProbeNetherNet: %v", err)
	}
	if want := fmt.Sprintf("https://%s:%d", host, port); endpoint != want {
		t.Fatalf("endpoint = %q, want %q", endpoint, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(requests, []string{"GET /v1/join"}) {
		t.Fatalf("requests = %q, want one GET /v1/join", requests)
	}
}

// A plain-HTTP endpoint fails the HTTPS handshake and answers the HTTP candidate.
func TestProbeNetherNetFallsBackToHTTP(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "OK")
	}))
	t.Cleanup(server.Close)
	host, port := serverHostPort(t, server.Listener.Addr())

	endpoint, err := ProbeNetherNet(t.Context(), nil, host, port)
	if err != nil {
		t.Fatalf("ProbeNetherNet: %v", err)
	}
	if want := fmt.Sprintf("http://%s:%d", host, port); endpoint != want {
		t.Fatalf("endpoint = %q, want %q", endpoint, want)
	}
}

func TestProbeNetherNetRejectsNonSuccessStatus(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusFound, http.StatusNotFound, http.StatusBadRequest} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if status == http.StatusFound {
				http.Redirect(w, r, "/elsewhere", status)
				return
			}
			w.WriteHeader(status)
		}))
		host, port := serverHostPort(t, server.Listener.Addr())
		if endpoint, err := ProbeNetherNet(t.Context(), nil, host, port); err == nil {
			t.Errorf("status %d: endpoint %q, want no answer", status, endpoint)
		}
		server.Close()
	}
}

func TestProbeNetherNetGivesUpAtTimeout(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	host, port := serverHostPort(t, server.Listener.Addr())

	start := time.Now()
	_, err := probeNetherNet(t.Context(), probeHTTPClient(nil), probeBatches(host, port), 50*time.Millisecond, 150*time.Millisecond)
	if err == nil {
		t.Fatal("probe answered a server that never responds")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("probe took %v, want it bounded by its timeout", elapsed)
	}
}

// A 2xx whose body never finishes, however much of it arrives, must not select NetherNet once the
// probe has timed out.
func TestProbeNetherNetRejectsStalledBody(t *testing.T) {
	t.Parallel()
	for _, sent := range []int{0, 1<<20 + 1} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(sent+10))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(make([]byte, sent))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}))
		host, port := serverHostPort(t, server.Listener.Addr())
		if endpoint, err := probeNetherNet(t.Context(), probeHTTPClient(nil), probeBatches(host, port), 50*time.Millisecond, 300*time.Millisecond); err == nil {
			t.Errorf("stalled body after %d bytes answered at %q", sent, endpoint)
		}
		server.Close()
	}
}

func TestAddressNetworkSelectsRakNetWhenProbeFails(t *testing.T) {
	t.Parallel()
	network := AddressNetwork{RakNet: RakNet{MaxMTU: 1400}}
	selected, err := network.Select(t.Context(), closedTCPAddress(t))
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	rakNet, ok := selected.(probedRakNet)
	if !ok || !reflect.DeepEqual(rakNet.RakNet, network.RakNet) {
		t.Fatalf("selected %#v, want the configured RakNet", selected)
	}
	for _, n := range []Network{network.RakNet, &network.RakNet, rakNet, &rakNet} {
		if !IsRakNet(n) {
			t.Errorf("IsRakNet(%T) = false, want true", n)
		}
	}
	if IsRakNet(network) {
		t.Error("IsRakNet(AddressNetwork) = true, want false")
	}
}

// A server that answers no probe request is joined over RakNet once the probe times out.
func TestAddressNetworkSelectsRakNetWhenNothingAnswers(t *testing.T) {
	t.Parallel()
	network := AddressNetwork{probeHeadStart: 20 * time.Millisecond, probeTimeout: 200 * time.Millisecond}
	start := time.Now()
	selected, err := network.Select(t.Context(), silentTCPAddress(t))
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if _, ok := selected.(probedRakNet); !ok {
		t.Fatalf("selected %T, want RakNet", selected)
	}
	if elapsed := time.Since(start); elapsed > network.probeTimeout+time.Second {
		t.Fatalf("Select took %v, want RakNet chosen at the %v probe timeout", elapsed, network.probeTimeout)
	}
}

// A repeat Select for an address that failed the probe dials RakNet without probing again.
func TestAddressNetworkCachesRakNetAnswer(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	network := AddressNetwork{Probes: &ProbeCache{}}

	if _, err := network.Select(t.Context(), server.Listener.Addr().String()); err != nil {
		t.Fatalf("first Select: %v", err)
	}
	probed := requests.Load()
	if probed == 0 {
		t.Fatal("first Select did not probe")
	}
	selected, err := network.Select(t.Context(), server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("second Select: %v", err)
	}
	if _, ok := selected.(probedRakNet); !ok {
		t.Fatalf("second Select chose %T, want RakNet", selected)
	}
	if got := requests.Load(); got != probed {
		t.Fatalf("second Select sent %d more probe requests, want none", got-probed)
	}
}

// A failed dial through a cached answer makes the next Select probe again.
func TestAddressNetworkReprobesAfterFailedDial(t *testing.T) {
	t.Parallel()
	var probes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			probes.Add(1)
			_, _ = io.WriteString(w, "OK")
			return
		}
		http.Error(w, "no session", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	network := AddressNetwork{Probes: &ProbeCache{}, NetherNet: NetherNet{Log: slog.New(slog.DiscardHandler)}}
	address := server.Listener.Addr().String()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := network.Select(ctx, address); err != nil {
		t.Fatalf("Select: %v", err)
	}
	if conn, err := network.DialContext(ctx, address); err == nil {
		_ = conn.Close()
		t.Fatal("dial succeeded, want the NetherNet failure")
	}
	before := probes.Load()
	if _, err := network.Select(ctx, address); err != nil {
		t.Fatalf("Select after failed dial: %v", err)
	}
	if probes.Load() == before {
		t.Fatal("Select after a failed dial reused the cached answer")
	}
}

// With RakNetAfterNetherNetFailure only a NetherNet dial that never reached the server makes the next
// Select join over RakNet without probing; a server error or a cancelled dial is probed again.
func TestAddressNetworkRakNetAfterNetherNetFailure(t *testing.T) {
	t.Parallel()
	hang := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}
	for name, test := range map[string]struct {
		offer      http.HandlerFunc // answers the signaling offer
		timeout    time.Duration    // bounds the dial when set
		cancel     bool             // the caller cancels once the offer arrives
		wantRakNet bool
	}{
		"dial times out": {offer: hang, timeout: 300 * time.Millisecond, wantRakNet: true},
		"server error": {offer: func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "no session", http.StatusInternalServerError)
		}},
		"dial cancelled": {offer: hang, cancel: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var probes atomic.Int32
			offered := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					probes.Add(1)
					_, _ = io.WriteString(w, "OK")
					return
				}
				select {
				case offered <- struct{}{}:
				default:
				}
				test.offer(w, r)
			}))
			t.Cleanup(server.Close)
			network := AddressNetwork{Probes: &ProbeCache{}, RakNetAfterNetherNetFailure: true, NetherNet: NetherNet{Log: slog.New(slog.DiscardHandler)}}
			address := server.Listener.Addr().String()

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			dialCtx, cancelDial := context.WithCancel(ctx)
			defer cancelDial()
			if test.timeout > 0 {
				dialCtx, cancelDial = context.WithTimeout(ctx, test.timeout)
				defer cancelDial()
			}
			if test.cancel {
				go func() {
					<-offered
					cancelDial()
				}()
			}
			if conn, err := network.DialContext(dialCtx, address); err == nil {
				_ = conn.Close()
				t.Fatal("dial succeeded, want the NetherNet failure")
			}
			before := probes.Load()
			selected, err := network.Select(ctx, address)
			if err != nil {
				t.Fatalf("Select after failed dial: %v", err)
			}
			_, rakNet := selected.(probedRakNet)
			if reprobed := probes.Load() != before; rakNet != test.wantRakNet || reprobed == test.wantRakNet {
				t.Fatalf("Select chose %T and probed again = %v, want RakNet without a probe = %v", selected, reprobed, test.wantRakNet)
			}
		})
	}
}

// Only a deadline or a failed connection counts as never reaching the server.
func TestUnreachableNetherNetDial(t *testing.T) {
	t.Parallel()
	refused := &url.Error{Op: "Post", URL: "http://example.com/v1/join", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}
	for err, want := range map[error]bool{
		fmt.Errorf("start transports: start ICE: %w", context.DeadlineExceeded):   true,
		fmt.Errorf("signal offer: %w", refused):                                   true,
		errors.New("identityless answer SDP not allowed"):                         false,
		errors.New("signal offer: POST http://example.com/v1/join: 500"):          false,
		fmt.Errorf("%w: %w", ErrServerNotTrusted, context.DeadlineExceeded):       true, // excluded by the caller
		fmt.Errorf("verify server identity token: %w", identityError{refused}):    false,
		identityError{context.DeadlineExceeded}:                                   false,
		&net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset")}: false,
		context.Canceled: false,
	} {
		if got := unreachable(err); got != want {
			t.Errorf("unreachable(%v) = %v, want %v", err, got, want)
		}
	}
}

// A failed Dialer dial over an AddressNetwork names the transport it used, keeping its error text.
func TestDialerNamesTheTransportOfAFailedAddressDial(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "OK")
			return
		}
		http.Error(w, "no session", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	for name, test := range map[string]struct {
		address string
		rakNet  bool
	}{
		"raknet":    {closedTCPAddress(t), true},
		"nethernet": {server.Listener.Addr().String(), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			network := AddressNetwork{NetherNet: NetherNet{Log: slog.New(slog.DiscardHandler)}}
			_, err := Dialer{}.DialContextNetwork(ctx, network, test.address)
			transportErr, ok := errors.AsType[*TransportError](err)
			if !ok {
				t.Fatalf("dial error %v does not name its transport", err)
			}
			if IsRakNet(transportErr.Network) != test.rakNet || err.Error() != transportErr.Err.Error() {
				t.Fatalf("dial error names %T as %q, want RakNet = %v and the unwrapped text", transportErr.Network, err, test.rakNet)
			}
		})
	}
}

// Wrapping a dial error names its transport without changing whether it is a net.Error.
func TestTransportErrorKeepsNetErrorBehaviour(t *testing.T) {
	t.Parallel()
	timeout := &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
	wrapped := wrapTransportError(RakNet{}, timeout)
	if !os.IsTimeout(wrapped) {
		t.Fatal("wrapped timeout no longer reports os.IsTimeout")
	}
	if netErr, ok := wrapped.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("wrapped timeout %T is not a timing-out net.Error", wrapped)
	}
	if transportErr, ok := errors.AsType[*TransportError](wrapped); !ok || !IsRakNet(transportErr.Network) || !errors.Is(wrapped, os.ErrDeadlineExceeded) {
		t.Fatal("wrapped timeout does not name RakNet or lost its cause")
	}
	if _, ok := wrapTransportError(RakNet{}, errors.New("kicked")).(net.Error); ok {
		t.Fatal("a wrapped non-network error became a net.Error")
	}
}

// A dial cancelled while hung on a stale RakNet answer makes the next Select probe again.
func TestAddressNetworkReprobesAfterCancelledRakNetDial(t *testing.T) {
	t.Parallel()
	var probes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	network := AddressNetwork{Probes: &ProbeCache{}, RakNet: RakNet{
		UpstreamDialer: upstreamDialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	}}
	address := server.Listener.Addr().String()
	selected, err := network.Select(t.Context(), address)
	if err != nil {
		t.Fatal(err)
	}
	before := probes.Load()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := selected.DialContext(ctx, address); !errors.Is(err, context.Canceled) {
		t.Fatalf("dial error = %v, want context.Canceled", err)
	}
	if _, err := network.Select(t.Context(), address); err != nil {
		t.Fatal(err)
	}
	if probes.Load() == before {
		t.Fatal("Select after a cancelled dial reused the cached answer")
	}
}

// A slow dial failing on an old answer keeps the answer another Select stored since.
func TestAddressNetworkFailedDialKeepsNewerAnswer(t *testing.T) {
	t.Parallel()
	var probes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	network := AddressNetwork{Probes: &ProbeCache{}, RakNet: RakNet{
		UpstreamDialer: upstreamDialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unreachable")
		}),
	}}
	address := server.Listener.Addr().String()
	selectNetwork := func() Network {
		t.Helper()
		selected, err := network.Select(t.Context(), address)
		if err != nil {
			t.Fatal(err)
		}
		return selected
	}

	slow, failed := selectNetwork(), selectNetwork()
	if _, err := failed.DialContext(t.Context(), address); err == nil {
		t.Fatal("dial succeeded, want the RakNet failure")
	}
	selectNetwork()
	stored := probes.Load()
	if _, err := slow.DialContext(t.Context(), address); err == nil {
		t.Fatal("dial succeeded, want the RakNet failure")
	}
	selectNetwork()
	if got := probes.Load(); got != stored {
		t.Fatalf("Select sent %d more probe requests after an old answer failed, want none", got-stored)
	}
}

func TestAddressNetworkSelectsNetherNetWhenProbeAnswers(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "OK")
	}))
	t.Cleanup(server.Close)

	selected, err := AddressNetwork{}.Select(t.Context(), server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	netherNet, ok := selected.(httpNetherNet)
	if !ok {
		t.Fatalf("selected %T, want NetherNet over HTTP signaling", selected)
	}
	if IsRakNet(selected) {
		t.Fatal("IsRakNet reports NetherNet as RakNet")
	}
	if netherNet.endpoint != server.URL {
		t.Fatalf("endpoint = %q, want %q", netherNet.endpoint, server.URL)
	}
	if _, ok := selected.(identityProviderDialer); !ok {
		t.Fatal("selected NetherNet cannot present the login identity")
	}
}

func TestAddressNetworkSelectStopsWithContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (AddressNetwork{}).Select(ctx, closedTCPAddress(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Select error = %v, want context.Canceled", err)
	}
}

func TestAddressNetworkDialsNetherNetOverHTTPSignaling(t *testing.T) {
	t.Parallel()
	signaling := endpoint.HandlerConfig{Logger: slog.New(slog.DiscardHandler)}.New()
	t.Cleanup(func() { _ = signaling.Close() })
	listener, err := (nethernet.ListenConfig{AllowAnonymous: true, DisableTrickleICE: true}).Listen(signaling)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := httptest.NewServer(signaling)
	t.Cleanup(server.Close)

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			close(accepted)
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	network := AddressNetwork{NetherNet: NetherNet{Dialer: nethernet.Dialer{AllowIdentitylessServer: true}}}
	client, err := network.DialContext(ctx, server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, ok := client.(*nethernet.Conn); !ok {
		t.Fatalf("dialed %T, want a NetherNet connection", client)
	}
	conn := <-accepted
	if conn == nil {
		t.FailNow()
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("hello")) {
		t.Fatalf("server read %q, %v; want hello", buf[:n], err)
	}
}

func TestAddressNetworkDialsRakNetWhenProbeFails(t *testing.T) {
	t.Parallel()
	listener, err := (RakNet{}).Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		if conn, err := listener.Accept(); err == nil {
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	conn, err := (AddressNetwork{}).DialContext(ctx, listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()
	if _, ok := conn.(*nethernet.Conn); ok {
		t.Fatal("dialed NetherNet for a server without HTTP signaling")
	}
}

// Once the probe picks NetherNet a failed negotiation ends the dial, even with RakNet on the port.
func TestAddressNetworkDoesNotFallBackAfterNetherNetFails(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "OK")
			return
		}
		http.Error(w, "no session", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	rakNet, err := (RakNet{}).Listen(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Listen RakNet on the signaling port: %v", err)
	}
	t.Cleanup(func() { _ = rakNet.Close() })
	go func() {
		if conn, err := rakNet.Accept(); err == nil {
			t.Error("dial fell back to RakNet")
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if conn, err := (AddressNetwork{}).DialContext(ctx, server.Listener.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatalf("dial succeeded with %T, want the NetherNet failure", conn)
	}
}

func serverHostPort(t *testing.T, addr net.Addr) (string, uint16) {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(port)
}

// closedTCPAddress returns a loopback address with no TCP listener.
func closedTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

// silentTCPAddress returns a loopback address that completes TCP handshakes and never answers.
func silentTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

// Probe answers are keyed like vanilla's: the host case-insensitively and the port exactly as given.
func TestAddressNetworkProbeCacheKeyMatchesVanilla(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	cache := &ProbeCache{}
	cache.store(probeKey{host: "play.example.com", port: 19132}, server.URL)

	selected, err := AddressNetwork{Probes: cache}.Select(t.Context(), "Play.Example.COM:19132")
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if n, ok := selected.(httpNetherNet); !ok || n.url != server.URL {
		t.Fatalf("Select = %#v, want the answer cached for the lower-cased host", selected)
	}
	if cache.lookup(probeKey{host: "play.example.com", port: 0}) != nil {
		t.Fatal("an address without a port shared the 19132 answer")
	}
}

// A remembered NetherNet URL is still asked before the join, as vanilla does.
func TestAddressNetworkProbesCachedEndpointBeforeJoin(t *testing.T) {
	t.Parallel()
	var probes int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		probes++
		mu.Unlock()
	}))
	t.Cleanup(server.Close)
	address := closedTCPAddress(t)
	host, port := splitServerAddress(address)
	cache := &ProbeCache{}
	cache.store(probeKey{host: host, port: port}, server.URL)

	selected, err := AddressNetwork{Probes: cache}.Select(t.Context(), address)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if n, ok := selected.(httpNetherNet); !ok || n.url != server.URL {
		t.Fatalf("Select = %#v, want NetherNet at the cached %q", selected, server.URL)
	}
	mu.Lock()
	defer mu.Unlock()
	if probes != 1 {
		t.Fatalf("cached URL was asked %d times, want 1", probes)
	}
}

// A remembered NetherNet URL that no longer answers joins over RakNet, as vanilla does.
func TestAddressNetworkJoinsRakNetWhenCachedEndpointStopsAnswering(t *testing.T) {
	t.Parallel()
	address := closedTCPAddress(t)
	host, port := splitServerAddress(address)
	cache := &ProbeCache{}
	cache.store(probeKey{host: host, port: port}, "http://"+closedTCPAddress(t))

	selected, err := AddressNetwork{Probes: cache}.Select(t.Context(), address)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if _, ok := selected.(probedRakNet); !ok {
		t.Fatalf("Select = %#v, want RakNet", selected)
	}
}

// A Dialer joining by address names the endpoint the probe chose in its login, as vanilla does.
func TestDialerSendsChosenEndpointAsServerAddress(t *testing.T) {
	t.Parallel()
	signaling := endpoint.HandlerConfig{Logger: slog.New(slog.DiscardHandler)}.New()
	t.Cleanup(func() { _ = signaling.Close() })
	server := httptest.NewServer(signaling)
	t.Cleanup(server.Close)
	listener, err := ListenConfig{AuthenticationDisabled: true, ErrorLog: slog.New(slog.DiscardHandler)}.ListenNetwork(NetherNet{
		Signaling:    signaling,
		ListenConfig: nethernet.ListenConfig{AllowAnonymous: true},
	}, signaling.NetworkID())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan *Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c.(*Conn)
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	network := AddressNetwork{NetherNet: NetherNet{Dialer: nethernet.Dialer{AllowIdentitylessServer: true}}}
	go func() {
		if conn, err := (Dialer{}).DialContextNetwork(ctx, network, server.Listener.Addr().String()); err == nil {
			_ = conn.Close()
		}
	}()
	select {
	case conn := <-accepted:
		if conn == nil {
			t.Fatal("listener stopped before a client joined")
		}
		t.Cleanup(func() { _ = conn.Close() })
		if got, want := conn.ClientData().ServerAddress, server.URL; got != want {
			t.Fatalf("login ServerAddress = %q, want %q", got, want)
		}
	case <-ctx.Done():
		t.Fatal("no client joined over NetherNet")
	}
}
