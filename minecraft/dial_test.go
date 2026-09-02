package minecraft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/df-mc/go-xsapi/v2/xal"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"golang.org/x/oauth2"
)

func TestNetherNetIdentityProviderNormalizesIssuer(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://authorization.example.test",
		"https://authorization.example.test/",
	} {
		issuer, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse issuer %q: %v", raw, err)
		}
		if got, want := netherNetIdentityProvider(issuer), "https://authorization.example.test/"; got != want {
			t.Errorf("netherNetIdentityProvider(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestDefaultClientDataUsesCurrentVanillaVersion(t *testing.T) {
	data := login.ClientData{}
	defaultClientData("example.com:19132", "Player", &data)

	version, err := base64.StdEncoding.DecodeString(data.SkinGeometryVersion)
	if err != nil {
		t.Fatalf("decode skin geometry engine version: %v", err)
	}
	if got, want := string(version), "0.0.0"; got != want {
		t.Fatalf("skin geometry engine version = %q, want %q", got, want)
	}
	if got, want := data.GameVersion, "1.26.45"; got != want {
		t.Fatalf("game version = %q, want %q", got, want)
	}
	if got, want := data.MemoryTier, 4; got != want {
		t.Fatalf("memory tier = %d, want %d", got, want)
	}
}

func TestDefaultClientDataPreservesSkinGeometryEngineVersion(t *testing.T) {
	want := base64.StdEncoding.EncodeToString([]byte("0.0.0"))
	data := login.ClientData{SkinGeometryVersion: want}
	defaultClientData("example.com:19132", "Player", &data)
	if data.SkinGeometryVersion != want {
		t.Fatalf("skin geometry engine version = %q, want preserved %q", data.SkinGeometryVersion, want)
	}
}

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

// TestDialContextClosesConnectionOnDeadline covers a dial that gives up while the server is still
// working through the login it already received. listenConn would otherwise carry that login to
// completion on its own goroutine, leaving a logged-in session behind that the caller has no handle
// to close, so servers rejecting duplicate logins kick the session the caller actually kept.
func TestDialContextClosesConnectionOnDeadline(t *testing.T) {
	for _, test := range []struct {
		name string
		// stallAfterLogin waits for the Login packet before stalling, so the server is left
		// holding a login it never answers.
		stallAfterLogin bool
	}{
		{name: "before login"},
		{name: "after login", stallAfterLogin: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			// stalling closes once the server has read the last packet it is going to read, so
			// the dial is given up at a point the server has provably reached. Timing the deadline
			// against wall clock instead would let a loaded runner expire it before the server got
			// there, and the server would report an EOF for a packet it never saw.
			stalling := make(chan struct{})
			network := newScriptedDialNetwork(func(conn net.Conn) error {
				decoder := packet.NewDecoder(conn)
				encoder := packet.NewEncoder(conn)
				if _, err := decoder.Decode(); err != nil {
					return fmt.Errorf("read RequestNetworkSettings: %w", err)
				}
				if test.stallAfterLogin {
					if err := encodeScriptedPackets(encoder, &packet.NetworkSettings{
						CompressionThreshold: math.MaxUint16,
						CompressionAlgorithm: packet.CompressionAlgorithmFlate,
					}); err != nil {
						return fmt.Errorf("write NetworkSettings: %w", err)
					}
					decoder.EnableCompression(packet.FlateCompression, math.MaxInt)
					encoder.EnableCompression(packet.FlateCompression, math.MaxUint16)
					if _, err := decoder.Decode(); err != nil {
						return fmt.Errorf("read Login: %w", err)
					}
				}
				// Never answer: the dial gives up with the server still treating this
				// connection as one that is logging in.
				close(stalling)
				return expectScriptedClose(conn, decoder)
			})

			// The timeout is a deadlock guard only. The dial is given up by cancelling with
			// context.DeadlineExceeded, so DialContextNetwork takes the same path and reports the
			// same error a real dial deadline produces.
			guard, cancelGuard := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelGuard()
			ctx, cancel := context.WithCancelCause(guard)
			defer cancel(context.Canceled)
			go func() {
				select {
				case <-stalling:
					cancel(context.DeadlineExceeded)
				case <-guard.Done():
				}
			}()

			conn, err := (Dialer{FlushRate: -1}).DialContextNetwork(ctx, network, "zeqa.net:19132")
			if conn != nil {
				_ = conn.Close()
				t.Fatal("DialContextNetwork returned a connection after the deadline expired")
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("DialContextNetwork error = %v, want context.DeadlineExceeded", err)
			}
			if scriptErr := <-network.done; scriptErr != nil {
				t.Fatalf("scripted server: %v", scriptErr)
			}
		})
	}
}

// TestDialContextGivesUpOnPeerThatStoppedReading covers a dial given up while the connection still
// holds a reply the peer never read. Cleaning up through Conn.Close would flush that reply first,
// blocking for as long as the peer stays silent, so the dial would hang in its cleanup instead of
// returning the error it was given up for.
func TestDialContextGivesUpOnPeerThatStoppedReading(t *testing.T) {
	// queued closes once the client has encoded its resource pack response, so the dial is given
	// up with that reply provably stuck: either it still sits in the send buffer for the cleanup
	// to flush, or listenConn is already blocked writing it and holds the encoder lock.
	queued := make(chan struct{})
	release := make(chan struct{})
	network := newScriptedDialNetwork(func(conn net.Conn) error {
		decoder := packet.NewDecoder(conn)
		encoder := packet.NewEncoder(conn)
		if _, err := decoder.Decode(); err != nil {
			return fmt.Errorf("read RequestNetworkSettings: %w", err)
		}
		if err := encodeScriptedPackets(encoder, &packet.NetworkSettings{
			CompressionThreshold: math.MaxUint16,
			CompressionAlgorithm: packet.CompressionAlgorithmFlate,
		}); err != nil {
			return fmt.Errorf("write NetworkSettings: %w", err)
		}
		decoder.EnableCompression(packet.FlateCompression, math.MaxInt)
		encoder.EnableCompression(packet.FlateCompression, math.MaxUint16)
		if _, err := decoder.Decode(); err != nil {
			return fmt.Errorf("read Login: %w", err)
		}
		if err := encodeScriptedPackets(encoder, &packet.PlayStatus{Status: packet.PlayStatusLoginSuccess}); err != nil {
			return fmt.Errorf("write login success: %w", err)
		}
		if _, err := decoder.Decode(); err != nil {
			return fmt.Errorf("read ClientCacheStatus: %w", err)
		}
		if err := encodeScriptedPackets(encoder, &packet.ResourcePacksInfo{}); err != nil {
			return fmt.Errorf("write ResourcePacksInfo: %w", err)
		}
		// Stop reading from here on, leaving the client's response with nowhere to go. Once the
		// dial has returned, the response must have been dropped along with the connection rather
		// than still be waiting for a reader.
		<-release
		return expectScriptedClose(conn, decoder)
	})

	guard, cancelGuard := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelGuard()
	ctx, cancel := context.WithCancelCause(guard)
	defer cancel(context.Canceled)
	go func() {
		select {
		case <-queued:
			cancel(context.DeadlineExceeded)
		case <-guard.Done():
		}
	}()

	var once sync.Once
	dialer := Dialer{
		FlushRate: -1,
		PacketFunc: func(header packet.Header, _ []byte, _, _ net.Addr) {
			if header.PacketID == packet.IDResourcePackClientResponse {
				once.Do(func() { close(queued) })
			}
		},
	}
	type dialResult struct {
		conn *Conn
		err  error
	}
	results := make(chan dialResult, 1)
	go func() {
		conn, err := dialer.DialContextNetwork(ctx, network, "zeqa.net:19132")
		results <- dialResult{conn: conn, err: err}
	}()

	select {
	case result := <-results:
		close(release)
		if result.conn != nil {
			_ = result.conn.Close()
			t.Fatal("DialContextNetwork returned a connection after the dial was given up")
		}
		if !errors.Is(result.err, context.DeadlineExceeded) {
			t.Fatalf("DialContextNetwork error = %v, want context.DeadlineExceeded", result.err)
		}
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("DialContextNetwork did not return: cleanup blocked flushing to a peer that stopped reading")
	}
	if scriptErr := <-network.done; scriptErr != nil {
		t.Fatalf("scripted server: %v", scriptErr)
	}
}

func TestDialContextReturnsRemappedPreLoginTransferError(t *testing.T) {
	for _, test := range []struct {
		name       string
		transferID uint32
	}{
		{name: "unexpected ID", transferID: remappedTransferID},
		{name: "currently expected ID", transferID: packet.IDItemRegistry},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := &packet.Transfer{Address: "hub.zeqa.net", Port: 19133, ReloadWorld: true}
			network := newScriptedDialNetwork(func(conn net.Conn) error {
				decoder, encoder, err := startScriptedLogin(conn)
				if err != nil {
					return err
				}
				if err := encodeScriptedPacketWithID(encoder, test.transferID, want); err != nil {
					return fmt.Errorf("write remapped Transfer: %w", err)
				}
				return expectScriptedClose(conn, decoder)
			})

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := (Dialer{
				FlushRate: -1,
				Protocol: remappedTransferProtocol{
					Protocol:   DefaultProtocol,
					transferID: test.transferID,
				},
			}).DialContextNetwork(ctx, network, "zeqa.net:19132")
			if conn != nil {
				_ = conn.Close()
				t.Fatal("DialContextNetwork returned a connection after remapped pre-login Transfer")
			}
			var transferErr *TransferError
			if !errors.As(err, &transferErr) {
				t.Fatalf("DialContextNetwork error = %v, want *TransferError", err)
			}
			if scriptErr := <-network.done; scriptErr != nil {
				t.Fatalf("scripted server: %v (dial error: %v)", scriptErr, err)
			}
		})
	}
}

func TestDialContextDoesNotTreatReusedLatestTransferIDAsTransfer(t *testing.T) {
	network := newScriptedDialNetwork(func(conn net.Conn) error {
		decoder, encoder, err := startScriptedLogin(conn)
		if err != nil {
			return err
		}
		if err := encodeScriptedPacketWithID(encoder, packet.IDTransfer, &packet.ItemRegistry{}); err != nil {
			return fmt.Errorf("write packet using latest Transfer ID: %w", err)
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
	conn, err := (Dialer{
		FlushRate: -1,
		Protocol: remappedTransferProtocol{
			Protocol:              DefaultProtocol,
			transferID:            remappedTransferID,
			reuseLatestTransferID: true,
		},
	}).DialContextNetwork(ctx, network, "example.com:19132")
	if err != nil {
		t.Fatalf("DialContextNetwork reused latest Transfer ID: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if scriptErr := <-network.done; scriptErr != nil {
		t.Fatalf("scripted server: %v", scriptErr)
	}
}

func TestListenConnPreservesPreLoginTransferCloseCause(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
	})

	conn := newConn(client, nil, slog.Default(), DefaultProtocol, -1, false)
	conn.pool = conn.proto.Packets(false)
	conn.expect(packet.IDPlayStatus)

	dialCtx, cancel := context.WithCancelCause(context.Background())
	go listenConn(conn, make(chan struct{}), make(chan struct{}), cancel)

	want := &packet.Transfer{Address: "hub.zeqa.net", Port: 19133, ReloadWorld: true}
	if err := encodeScriptedPackets(packet.NewEncoder(server), want); err != nil {
		t.Fatalf("write Transfer: %v", err)
	}

	select {
	case <-dialCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("listenConn did not cancel the dial context")
	}
	select {
	case <-conn.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("listenConn did not close the connection")
	}

	var dialTransferErr, closeTransferErr *TransferError
	if !errors.As(context.Cause(dialCtx), &dialTransferErr) {
		t.Fatalf("dial context cause = %v, want *TransferError", context.Cause(dialCtx))
	}
	if !errors.As(context.Cause(conn.ctx), &closeTransferErr) {
		t.Fatalf("connection close cause = %v, want *TransferError", context.Cause(conn.ctx))
	}
	if *closeTransferErr != *dialTransferErr {
		t.Fatalf("connection close cause = %#v, want %#v", closeTransferErr, dialTransferErr)
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

func TestDialContextIgnoresDuplicateLoginSuccess(t *testing.T) {
	network := newScriptedDialNetwork(func(conn net.Conn) error {
		decoder, encoder, err := startScriptedLogin(conn)
		if err != nil {
			return err
		}
		if err := encodeScriptedPackets(encoder,
			&packet.ItemRegistry{},
			&packet.PlayStatus{Status: packet.PlayStatusLoginSuccess},
			&packet.ChunkRadiusUpdated{ChunkRadius: 16},
			&packet.PlayStatus{Status: packet.PlayStatusPlayerSpawn},
		); err != nil {
			return fmt.Errorf("finish login after duplicate success: %w", err)
		}
		if _, err := decoder.Decode(); err != nil {
			return fmt.Errorf("read login acknowledgement: %w", err)
		}
		return expectScriptedClose(conn, decoder)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := (Dialer{FlushRate: -1}).DialContextNetwork(ctx, network, "pvp.inpvp.net:19132")
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("DialContextNetwork duplicate LoginSuccess: %v", err)
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
	if err := encodeScriptedPackets(encoder, &packet.PlayStatus{Status: packet.PlayStatusLoginSuccess}); err != nil {
		return nil, nil, fmt.Errorf("write login success: %w", err)
	}
	if _, err := decoder.Decode(); err != nil {
		return nil, nil, fmt.Errorf("read ClientCacheStatus: %w", err)
	}
	if err := encodeScriptedPackets(encoder, &packet.ResourcePacksInfo{}); err != nil {
		return nil, nil, fmt.Errorf("write ResourcePacksInfo: %w", err)
	}
	if _, err := decoder.Decode(); err != nil {
		return nil, nil, fmt.Errorf("read ResourcePackClientResponse: %w", err)
	}
	if err := encodeScriptedPackets(encoder, &packet.ResourcePackStack{}, &packet.StartGame{}); err != nil {
		return nil, nil, fmt.Errorf("write StartGame: %w", err)
	}
	if _, err := decoder.Decode(); err != nil {
		return nil, nil, fmt.Errorf("read ResourcePackStack response: %w", err)
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

func encodeScriptedPacketWithID(encoder *packet.Encoder, id uint32, pk packet.Packet) error {
	buf := new(bytes.Buffer)
	if err := (&packet.Header{PacketID: id}).Write(buf); err != nil {
		return err
	}
	pk.Marshal(DefaultProtocol.NewWriter(buf, 0))
	return encoder.Encode([][]byte{buf.Bytes()})
}

func expectScriptedClose(conn net.Conn, decoder *packet.Decoder) error {
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	_, err := decoder.Decode()
	if err == nil {
		return errors.New("client connection remained open")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return errors.New("timed out waiting for client connection close")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("wait for client connection close: %w", err)
	}
	return nil
}

type scriptedDialNetwork struct {
	script func(net.Conn) error
	done   chan error
}

const remappedTransferID = 0x3ff

type remappedTransferProtocol struct {
	Protocol
	transferID            uint32
	reuseLatestTransferID bool
}

func (p remappedTransferProtocol) Packets(listener bool) packet.Pool {
	pool := p.Protocol.Packets(listener)
	if !listener {
		delete(pool, packet.IDTransfer)
		if p.reuseLatestTransferID {
			pool[packet.IDTransfer] = func() packet.Packet { return &packet.ItemRegistry{} }
		}
		pool[p.transferID] = func() packet.Packet { return &packet.Transfer{} }
	}
	return pool
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
	return pipeConn{Conn: client}, nil
}

// pipeConn gives a net.Pipe the error a real net.Conn reports once it is closed locally. A pipe
// reports io.ErrClosedPipe instead, which Conn treats as an unexpected encoding failure rather than
// an ordinary shutdown.
type pipeConn struct {
	net.Conn
}

func (c pipeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	return n, closedPipeAsClosedConn(err)
}

func (c pipeConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	return n, closedPipeAsClosedConn(err)
}

func closedPipeAsClosedConn(err error) error {
	if errors.Is(err, io.ErrClosedPipe) {
		return net.ErrClosed
	}
	return err
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

func TestServerPacketPool_LazyBlockActorDataIsOptIn(t *testing.T) {
	t.Parallel()

	for _, protocolTest := range []struct {
		name     string
		protocol Protocol
	}{
		{name: "current", protocol: DefaultProtocol},
		{name: "1.26.40", protocol: Protocol12640()},
		{name: "1.26.44", protocol: Protocol12644()},
	} {
		t.Run(protocolTest.name, func(t *testing.T) {
			for _, lazy := range []bool{false, true} {
				pk := serverPacketPool(protocolTest.protocol, lazy)[packet.IDBlockActorData]().(*packet.BlockActorData)
				wire := []byte{0x02, 0x80, 0x01, 0x03, 0x0a, 0x00, 0x03, 0x05, 'p', 'a', 'i', 'r', 'x', 0x04, 0x00}
				pk.Marshal(protocol.NewReader(bytes.NewBuffer(wire), 0, true))
				if lazy && pk.NBTData != nil {
					t.Fatalf("lazy NBTData = %#v, want nil", pk.NBTData)
				}
				if !lazy && pk.NBTData == nil {
					t.Fatal("default NBTData is nil")
				}
			}
		})
	}
}

func TestServerPacketPool_PreservesProtocolSpecificBlockActorData(t *testing.T) {
	t.Parallel()

	p := customBlockActorProtocol{Protocol: DefaultProtocol}
	got := serverPacketPool(p, true)[packet.IDBlockActorData]()
	if _, ok := got.(*customBlockActorData); !ok {
		t.Fatalf("lazy pool BlockActorData = %T, want %T", got, &customBlockActorData{})
	}
}

func TestServerPacketPool_DoesNotMutateProtocolPool(t *testing.T) {
	t.Parallel()

	pool := DefaultProtocol.Packets(false)
	p := sharedPacketPoolProtocol{Protocol: DefaultProtocol, pool: pool}
	got := serverPacketPool(p, true)
	if _, ok := got[packet.IDBlockActorData]().(*packet.BlockActorData); !ok {
		t.Fatalf("lazy pool BlockActorData = %T, want %T", got[packet.IDBlockActorData](), &packet.BlockActorData{})
	}
	original := p.Packets(false)
	blockActorData := original[packet.IDBlockActorData]().(*packet.BlockActorData)
	blockActorData.Marshal(protocol.NewReader(bytes.NewBuffer(blockActorDataGoldenWireForDialTest()), 0, true))
	if blockActorData.NBTData == nil {
		t.Fatal("protocol pool was changed to lazy BlockActorData")
	}
}

type customBlockActorProtocol struct {
	Protocol
}

// Packets replaces BlockActorData with a protocol-specific wire representation.
func (p customBlockActorProtocol) Packets(listener bool) packet.Pool {
	pool := p.Protocol.Packets(listener)
	if !listener {
		pool[packet.IDBlockActorData] = func() packet.Packet { return &customBlockActorData{} }
	}
	return pool
}

type customBlockActorData struct{}

// ID returns the BlockActorData packet ID.
func (*customBlockActorData) ID() uint32 { return packet.IDBlockActorData }

// Marshal implements packet.Packet for the protocol-specific fixture.
func (*customBlockActorData) Marshal(protocol.IO) {}

type sharedPacketPoolProtocol struct {
	Protocol
	pool packet.Pool
}

// Packets returns the same packet pool on each call.
func (p sharedPacketPoolProtocol) Packets(bool) packet.Pool { return p.pool }

// blockActorDataGoldenWireForDialTest returns a valid BlockActorData payload.
func blockActorDataGoldenWireForDialTest() []byte {
	return []byte{0x02, 0x80, 0x01, 0x03, 0x0a, 0x00, 0x03, 0x05, 'p', 'a', 'i', 'r', 'x', 0x04, 0x00}
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

func TestDialContextForwardClientCacheStatusSkipsInjectedStatus(t *testing.T) {
	network := newScriptedDialNetwork(func(conn net.Conn) error {
		decoder := packet.NewDecoder(conn)
		encoder := packet.NewEncoder(conn)
		if _, err := decoder.Decode(); err != nil {
			return fmt.Errorf("read RequestNetworkSettings: %w", err)
		}
		if err := encodeScriptedPackets(encoder, &packet.NetworkSettings{
			CompressionThreshold: math.MaxUint16,
			CompressionAlgorithm: packet.CompressionAlgorithmFlate,
		}); err != nil {
			return fmt.Errorf("write NetworkSettings: %w", err)
		}
		decoder.EnableCompression(packet.FlateCompression, math.MaxInt)
		encoder.EnableCompression(packet.FlateCompression, math.MaxUint16)
		if _, err := decoder.Decode(); err != nil {
			return fmt.Errorf("read Login: %w", err)
		}
		if err := encodeScriptedPackets(encoder, &packet.PlayStatus{Status: packet.PlayStatusLoginSuccess}); err != nil {
			return fmt.Errorf("write login success: %w", err)
		}
		// The first packet after LoginSuccess must be the caller's, not an injected ClientCacheStatus.
		batch, err := decoder.Decode()
		if err != nil {
			return fmt.Errorf("read first post-login batch: %w", err)
		}
		if len(batch) != 1 {
			return fmt.Errorf("first post-login batch has %d packets, want 1", len(batch))
		}
		var header packet.Header
		if err := header.Read(bytes.NewBuffer(batch[0])); err != nil {
			return fmt.Errorf("read header: %w", err)
		}
		if header.PacketID != packet.IDText {
			return fmt.Errorf("first post-login packet ID = %d, want Text (%d)", header.PacketID, packet.IDText)
		}
		return expectScriptedClose(conn, decoder)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := (Dialer{
		FlushRate:                -1,
		DisablePacketHandling:    true,
		EnableBatchReading:       true,
		ForwardClientCacheStatus: true,
	}).DialContextNetwork(ctx, network, "example.com:19132")
	if err != nil {
		t.Fatalf("DialContextNetwork passthrough login: %v (scripted server: %v)", err, <-network.done)
	}
	if err := conn.WritePacket(&packet.Text{Message: "forwarded"}); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if scriptErr := <-network.done; scriptErr != nil {
		t.Fatalf("scripted server: %v", scriptErr)
	}
}
