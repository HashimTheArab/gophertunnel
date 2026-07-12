package minecraft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/df-mc/go-xsapi/v2/xal"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"golang.org/x/oauth2"
)

func TestDialContextReturnsPreLoginTransferError(t *testing.T) {
	want := &packet.Transfer{Address: "hub.zeqa.net", Port: 19133, ReloadWorld: true}
	network := newScriptedDialNetwork(func(conn net.Conn) error {
		decoder, encoder, err := startScriptedLogin(conn)
		if err != nil {
			return err
		}
		if err := encodeScriptedPackets(encoder, want); err != nil {
			return fmt.Errorf("write Transfer: %w", err)
		}
		return expectScriptedClose(conn, decoder)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := (Dialer{FlushRate: -1}).DialContextNetwork(ctx, network, "zeqa.net:19132")
	scriptErr := <-network.done
	if scriptErr != nil {
		t.Fatalf("scripted server: %v (dial error: %v)", scriptErr, err)
	}
	if conn != nil {
		_ = conn.Close()
		t.Fatal("DialContextNetwork returned a connection after pre-login Transfer")
	}
	var transferErr *TransferError
	if !errors.As(err, &transferErr) {
		t.Fatalf("DialContextNetwork error = %v, want *TransferError", err)
	}
	if transferErr.Address != want.Address || transferErr.Port != want.Port || transferErr.ReloadWorld != want.ReloadWorld {
		t.Fatalf("TransferError = %#v, want address=%q port=%d reload=%v", transferErr, want.Address, want.Port, want.ReloadWorld)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		t.Fatalf("DialContextNetwork error = %v, want dial net.OpError wrapper", err)
	}
}

func TestDialContextOrdinaryLoginStillCompletes(t *testing.T) {
	network := newScriptedDialNetwork(func(conn net.Conn) error {
		decoder, encoder, err := startScriptedLogin(conn)
		if err != nil {
			return err
		}
		if err := encodeScriptedPackets(encoder,
			&packet.ItemRegistry{},
			&packet.ChunkRadiusUpdated{ChunkRadius: 16},
			&packet.PlayStatus{Status: packet.PlayStatusPlayerSpawn},
		); err != nil {
			return fmt.Errorf("finish login: %w", err)
		}
		if _, err := decoder.Decode(); err != nil {
			return fmt.Errorf("read login acknowledgement: %w", err)
		}
		return expectScriptedClose(conn, decoder)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := (Dialer{FlushRate: -1}).DialContextNetwork(ctx, network, "example.com:19132")
	if err != nil {
		t.Fatalf("DialContextNetwork ordinary login: %v (scripted server: %v)", err, <-network.done)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if scriptErr := <-network.done; scriptErr != nil {
		t.Fatalf("scripted server: %v", scriptErr)
	}
}

func startScriptedLogin(conn net.Conn) (*packet.Decoder, *packet.Encoder, error) {
	decoder := packet.NewDecoder(conn)
	encoder := packet.NewEncoder(conn)
	if _, err := decoder.Decode(); err != nil {
		return nil, nil, fmt.Errorf("read RequestNetworkSettings: %w", err)
	}
	if err := encodeScriptedPackets(encoder, &packet.NetworkSettings{
		CompressionThreshold: math.MaxUint16,
		CompressionAlgorithm: packet.CompressionAlgorithmFlate,
	}); err != nil {
		return nil, nil, fmt.Errorf("write NetworkSettings: %w", err)
	}
	decoder.EnableCompression(packet.FlateCompression, math.MaxInt)
	encoder.EnableCompression(packet.FlateCompression, math.MaxUint16)
	if _, err := decoder.Decode(); err != nil {
		return nil, nil, fmt.Errorf("read Login: %w", err)
	}
	if err := encodeScriptedPackets(encoder, &packet.StartGame{}); err != nil {
		return nil, nil, fmt.Errorf("write StartGame: %w", err)
	}
	if _, err := decoder.Decode(); err != nil {
		return nil, nil, fmt.Errorf("read StartGame responses: %w", err)
	}
	return decoder, encoder, nil
}

func encodeScriptedPackets(encoder *packet.Encoder, packets ...packet.Packet) error {
	encoded := make([][]byte, 0, len(packets))
	for _, pk := range packets {
		buf := new(bytes.Buffer)
		if err := (&packet.Header{PacketID: pk.ID()}).Write(buf); err != nil {
			return err
		}
		pk.Marshal(DefaultProtocol.NewWriter(buf, 0))
		encoded = append(encoded, buf.Bytes())
	}
	return encoder.Encode(encoded)
}

func expectScriptedClose(conn net.Conn, decoder *packet.Decoder) error {
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err := decoder.Decode()
	if err == nil {
		return errors.New("client connection remained open")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return errors.New("timed out waiting for client connection close")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("wait for client connection close: %w", err)
	}
	return nil
}

type scriptedDialNetwork struct {
	script func(net.Conn) error
	done   chan error
}

func newScriptedDialNetwork(script func(net.Conn) error) *scriptedDialNetwork {
	return &scriptedDialNetwork{script: script, done: make(chan error, 1)}
}

func (n *scriptedDialNetwork) DialContext(context.Context, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		n.done <- n.script(server)
	}()
	return client, nil
}

func (*scriptedDialNetwork) PingContext(context.Context, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (*scriptedDialNetwork) Listen(string) (NetworkListener, error) {
	return nil, errors.New("not implemented")
}

func TestDialAuthContextPropagatesHTTPClient(t *testing.T) {
	t.Parallel()

	client := &http.Client{}
	ctx := auth.WithContextClient(context.Background(), client)

	if got, _ := ctx.Value(xal.HTTPClient).(*http.Client); got != client {
		t.Fatalf("xal.HTTPClient = %p, want %p", got, client)
	}
	if got, _ := ctx.Value(oauth2.HTTPClient).(*http.Client); got != client {
		t.Fatalf("oauth2.HTTPClient = %p, want %p", got, client)
	}
}

func TestDialAuthContextDoesNotOverwriteHTTPClient(t *testing.T) {
	t.Parallel()

	existingXAL := &http.Client{}
	existingOAuth := &http.Client{}
	replacement := &http.Client{}
	ctx := context.WithValue(context.Background(), xal.HTTPClient, existingXAL)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, existingOAuth)
	ctx = auth.WithContextClient(ctx, replacement)

	if got, _ := ctx.Value(xal.HTTPClient).(*http.Client); got != existingXAL {
		t.Fatalf("xal.HTTPClient = %p, want existing %p", got, existingXAL)
	}
	if got, _ := ctx.Value(oauth2.HTTPClient).(*http.Client); got != existingOAuth {
		t.Fatalf("oauth2.HTTPClient = %p, want existing %p", got, existingOAuth)
	}
}

func TestDialContextWithMultiplayerTokenSourceSkipsLegacySessionSetup(t *testing.T) {
	cache := auth.AndroidConfig.NewTokenCache()
	ctx := auth.WithXBLTokenCache(context.Background(), cache)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("stop before auth discovery")
	})}

	_, err := Dialer{
		HTTPClient:  client,
		TokenSource: dialTestMultiplayerTokenSource{},
	}.DialContext(ctx, "unused", "example.com:19132")
	if err == nil {
		t.Fatal("expected DialContext to fail before network dial")
	}
	if cache.Session() != nil {
		t.Fatal("DialContext created a legacy XBL session for a MultiplayerTokenSource")
	}
}

func TestDialContextDialsOriginalAddressWithoutPinging(t *testing.T) {
	const networkID = "test-pong-port"
	dialErr := errors.New("stop after address capture")
	var dialAddress string
	pingCalled := false

	RegisterNetwork(networkID, func(*slog.Logger) Network {
		return dialTestNetwork{
			dial: func(_ context.Context, address string) (net.Conn, error) {
				dialAddress = address
				return nil, dialErr
			},
			ping: func(context.Context, string) ([]byte, error) {
				pingCalled = true
				return []byte("MCPE;InsaneSMP;800;1.21.80;0;100;123;World;Survival;1;25565;19133;"), nil
			},
		}
	})
	t.Cleanup(func() {
		UnregisterNetwork(networkID)
	})

	_, err := Dialer{}.DialContext(context.Background(), networkID, "insanesmp.net:19132")
	if !errors.Is(err, dialErr) {
		t.Fatalf("DialContext error = %v, want %v", err, dialErr)
	}
	if dialAddress != "insanesmp.net:19132" {
		t.Fatalf("dial address = %q, want insanesmp.net:19132", dialAddress)
	}
	if pingCalled {
		t.Fatal("DialContext called PingContext before dialing")
	}
}

func TestDialContextNetworkUsesExplicitNetwork(t *testing.T) {
	t.Parallel()

	dialErr := errors.New("stop after explicit network dial")
	ctx := context.WithValue(context.Background(), testContextKey{}, "explicit")
	network := dialTestNetwork{
		dial: func(gotCtx context.Context, address string) (net.Conn, error) {
			if gotCtx != ctx {
				t.Fatal("DialContextNetwork did not pass caller context to network")
			}
			if address != "nethernet-id" {
				t.Fatalf("network address = %q, want nethernet-id", address)
			}
			return nil, dialErr
		},
	}

	_, err := Dialer{}.DialContextNetwork(ctx, network, "nethernet-id")
	if !errors.Is(err, dialErr) {
		t.Fatalf("DialContextNetwork error = %v, want %v", err, dialErr)
	}
}

type dialTestNetwork struct {
	dial func(context.Context, string) (net.Conn, error)
	ping func(context.Context, string) ([]byte, error)
}

func (n dialTestNetwork) DialContext(ctx context.Context, address string) (net.Conn, error) {
	return n.dial(ctx, address)
}

func (n dialTestNetwork) PingContext(ctx context.Context, address string) ([]byte, error) {
	if n.ping != nil {
		return n.ping(ctx, address)
	}
	return nil, errors.New("not implemented")
}

func (dialTestNetwork) Listen(string) (NetworkListener, error) {
	return nil, errors.New("not implemented")
}

type dialTestMultiplayerTokenSource struct{}

func (dialTestMultiplayerTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "live", Expiry: time.Now().Add(time.Hour)}, nil
}

func (dialTestMultiplayerTokenSource) MultiplayerToken(context.Context, *ecdsa.PublicKey) (string, error) {
	return "", errors.New("unexpected multiplayer token request")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type testContextKey struct{}
