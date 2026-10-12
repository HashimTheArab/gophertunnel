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
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/endpoint"
)

func TestProbeEndpointsFollowVanillaOrder(t *testing.T) {
	t.Parallel()
	if got, want := probeEndpoints("example.com", 19133), []string{"https://example.com:19133", "http://example.com:19133"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("probeEndpoints with port = %q, want %q", got, want)
	}
	want := []string{"https://example.com:19132", "https://example.com", "http://example.com:19132", "http://example.com"}
	if got := probeEndpoints("example.com", 0); !reflect.DeepEqual(got, want) {
		t.Fatalf("probeEndpoints without port = %q, want %q", got, want)
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
	_, err := probeNetherNet(t.Context(), probeHTTPClient(nil), host, port, 150*time.Millisecond)
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
		if endpoint, err := probeNetherNet(t.Context(), probeHTTPClient(nil), host, port, 300*time.Millisecond); err == nil {
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
	if !reflect.DeepEqual(selected, network.RakNet) {
		t.Fatalf("selected %#v, want the configured RakNet", selected)
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
