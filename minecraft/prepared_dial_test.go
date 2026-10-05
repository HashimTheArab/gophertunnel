package minecraft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/sandertv/go-raknet"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/service"
	"golang.org/x/oauth2"
)

func TestPreparedDialDefersLoginAndBindsCurrentCallbacks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		loginObserved := make(chan *packet.Login, 1)
		var oldCalls, currentCalls, admitted atomic.Int32
		var oldBatches, currentBatches atomic.Int32
		network := newScriptedDialNetwork(func(conn net.Conn) error {
			decoder, encoder, err := preparedScriptSettings(conn)
			if err != nil {
				return err
			}
			if err := encodeScriptedPackets(encoder,
				&packet.PlayStatus{Status: packet.PlayStatusLoginSuccess},
				&packet.ServerToClientHandshake{JWT: []byte("invalid-before-login")},
				&packet.ResourcePacksInfo{}, &packet.ResourcePackStack{}, &packet.StartGame{},
			); err != nil {
				return err
			}
			pk, err := preparedScriptRead(decoder, packet.IDLogin)
			if err != nil {
				return err
			}
			loginObserved <- pk.(*packet.Login)
			if err := preparedScriptFinish(decoder, encoder); err != nil {
				return err
			}
			return expectScriptedClose(conn, decoder)
		})
		d := Dialer{FlushRate: -1, RelayStartup: true, ClientData: login.ClientData{LanguageCode: "en-GB"},
			PacketFunc:      func(packet.Header, []byte, net.Addr, net.Addr) { oldCalls.Add(1) },
			PacketBatchFunc: func(packet.BatchEncodeStats) { oldBatches.Add(1) },
		}
		p, err := d.PrepareContextNetwork(context.Background(), network, "127.0.0.1:19132", 7)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		<-p.Done()
		synctest.Wait()
		if !p.Ready() {
			t.Fatalf("preparation not ready: %v", p.Err())
		}
		select {
		case <-loginObserved:
			t.Fatal("Login was sent before CommitContext")
		default:
		}
		if oldCalls.Load() != 0 || p.conn.loginSuccessReceived || p.conn.handshakeComplete || p.conn.loggedIn {
			t.Fatal("pre-login packets triggered observers or application actions")
		}
		d.ClientData.LanguageCode = "fr-FR"
		d.PacketFunc = func(packet.Header, []byte, net.Addr, net.Addr) { currentCalls.Add(1) }
		d.PacketBatchFunc = func(packet.BatchEncodeStats) { currentBatches.Add(1) }
		d.AcceptPacketHeader = func(header packet.Header) bool {
			if header.PacketID == packet.IDResourcePacksInfo {
				admitted.Add(1)
			}
			return true
		}
		conn, err := p.CommitContext(context.Background(), d, "127.0.0.1:19132", 7)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		request := <-loginObserved
		_, clientData, _, err := login.Parse(request.ConnectionRequest, nil)
		if err != nil || clientData.LanguageCode != "fr-FR" {
			t.Fatalf("Login did not use current client data: locale=%q err=%v", clientData.LanguageCode, err)
		}
		if currentCalls.Load() == 0 || oldCalls.Load() != 0 || admitted.Load() != 1 {
			t.Fatalf("callback binding: current=%d old=%d admission=%d", currentCalls.Load(), oldCalls.Load(), admitted.Load())
		}
		if currentBatches.Load() == 0 || oldBatches.Load() != 0 {
			t.Fatalf("batch callback binding: current=%d old=%d", currentBatches.Load(), oldBatches.Load())
		}
		if _, err := p.CommitContext(context.Background(), d, "127.0.0.1:19132", 7); !errors.Is(err, ErrPreparedDialClaimed) {
			t.Fatalf("second commit error = %v", err)
		}
		_ = conn.Close()
		if err := <-network.done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestPreparedDialRejectsMismatchesWithoutLogin(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*Dialer, *string, *uint64)
	}{
		{"address", func(_ *Dialer, a *string, _ *uint64) { *a = "other:19132" }},
		{"account generation", func(_ *Dialer, _ *string, g *uint64) { *g++ }},
		{"protocol", func(d *Dialer, _ *string, _ *uint64) {
			d.Protocol = remappedTransferProtocol{Protocol: DefaultProtocol}
		}},
		{"flush rate", func(d *Dialer, _ *string, _ *uint64) { d.FlushRate = time.Millisecond }},
		{"decompression limit", func(d *Dialer, _ *string, _ *uint64) { d.MaxDecompressedLen = 1 }},
		{"authentication mode", func(d *Dialer, _ *string, _ *uint64) { d.TokenSource = dialTestMultiplayerTokenSource{} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			network := newScriptedDialNetwork(func(conn net.Conn) error {
				decoder, _, err := preparedScriptSettings(conn)
				if err != nil {
					return err
				}
				return expectScriptedClose(conn, decoder)
			})
			d := Dialer{FlushRate: -1, RelayStartup: true}
			p, err := d.PrepareContextNetwork(context.Background(), network, "127.0.0.1:19132", 7)
			if err != nil {
				t.Fatal(err)
			}
			<-p.Done()
			address, generation := "127.0.0.1:19132", uint64(7)
			change.edit(&d, &address, &generation)
			if conn, err := p.CommitContext(context.Background(), d, address, generation); conn != nil || !errors.Is(err, ErrPreparedDialMismatch) {
				t.Fatalf("mismatched commit: conn=%v err=%v", conn != nil, err)
			}
			_ = p.Close()
			if err := <-network.done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPreparedDialUnfinishedCommitNeverWaits(t *testing.T) {
	started := make(chan struct{})
	network := dialTestNetwork{dial: func(ctx context.Context, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	d := Dialer{FlushRate: -1}
	p, err := d.PrepareContextNetwork(context.Background(), network, "127.0.0.1:19132", 7)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if conn, err := p.CommitContext(context.Background(), d, "127.0.0.1:19132", 7); conn != nil || !errors.Is(err, ErrPreparedDialNotReady) {
		t.Fatalf("unfinished commit: conn=%v err=%v", conn != nil, err)
	}
	_ = p.Close()
	if p.Ready() || !errors.Is(p.Err(), context.Canceled) {
		t.Fatalf("cancelled preparation: ready=%v err=%v", p.Ready(), p.Err())
	}
}

func TestPreparedDialFailedTransportNeverBecomesReady(t *testing.T) {
	want := errors.New("fixture transport unavailable")
	network := dialTestNetwork{dial: func(context.Context, string) (net.Conn, error) { return nil, want }}
	d := Dialer{FlushRate: -1}
	p, err := d.PrepareContextNetwork(context.Background(), network, "127.0.0.1:19132", 7)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	<-p.Done()
	if p.Ready() || !errors.Is(p.Err(), want) {
		t.Fatalf("failed transport: ready=%v err=%v", p.Ready(), p.Err())
	}
	if conn, err := p.CommitContext(context.Background(), d, "127.0.0.1:19132", 7); conn != nil || !errors.Is(err, ErrPreparedDialNotReady) {
		t.Fatalf("failed commit: conn=%v err=%v", conn != nil, err)
	}
}

func TestPreparedDialRejectsIdentityAwareTransport(t *testing.T) {
	if p, err := (Dialer{}).PrepareContextNetwork(context.Background(), NetherNet{}, "fixture", 7); p != nil || !errors.Is(err, ErrPreparedDialUnsupported) {
		t.Fatalf("identity-aware preparation: preparation=%v err=%v", p != nil, err)
	}
}

func TestPreparedDialCommitCancellationUnblocksPeerThatStoppedReading(t *testing.T) {
	connClosed := make(chan struct{})
	loginEncoded := make(chan struct{})
	network := newScriptedDialNetwork(func(conn net.Conn) error {
		decoder, _, err := preparedScriptSettings(conn)
		if err != nil {
			return err
		}
		// The peer does not read the Login until after cancellation has released its writer.
		<-connClosed
		return expectScriptedClose(conn, decoder)
	})
	d := Dialer{FlushRate: -1, PacketFunc: func(header packet.Header, _ []byte, _, _ net.Addr) {
		if header.PacketID == packet.IDLogin {
			close(loginEncoded)
		}
	}}
	p, err := d.PrepareContextNetwork(context.Background(), network, "127.0.0.1:19132", 7)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	<-p.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := p.CommitContext(ctx, d, "127.0.0.1:19132", 7)
		if conn != nil {
			_ = conn.Close()
			result <- errors.New("cancelled commit returned a connection")
			return
		}
		result <- err
	}()
	<-loginEncoded
	cancel()
	err = <-result
	close(connClosed)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled commit error = %v", err)
	}
	if err := <-network.done; err != nil {
		t.Fatal(err)
	}
}

func TestPreparedDialExpiresWithoutLogin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		network := newScriptedDialNetwork(func(conn net.Conn) error {
			decoder, _, err := preparedScriptSettings(conn)
			if err != nil {
				return err
			}
			// Wait for the preparation timeout, not a server-side read timeout.
			_, err = decoder.Decode()
			if err == nil {
				return errors.New("application packet sent before expiry")
			}
			return nil
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		d := Dialer{FlushRate: -1}
		p, err := d.PrepareContextNetwork(ctx, network, "127.0.0.1:19132", 7)
		if err != nil {
			t.Fatal(err)
		}
		<-p.Done()
		if !p.Ready() {
			t.Fatal("preparation was not ready before expiry")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if conn, err := p.CommitContext(context.Background(), d, "127.0.0.1:19132", 7); conn != nil || !errors.Is(err, ErrPreparedDialNotReady) {
			t.Fatalf("expired commit: conn=%v err=%v", conn != nil, err)
		}
		_ = p.Close()
		if err := <-network.done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestPreparedDialPreLoginFailuresStayUnclaimable(t *testing.T) {
	for _, pk := range []packet.Packet{
		&packet.Disconnect{Reason: packet.DisconnectReasonKicked, Message: "preparation rejected"},
		&packet.PlayStatus{Status: packet.PlayStatusLoginFailedServerFull},
		&packet.Transfer{Address: "other", Port: 19132},
		&packet.Unknown{PacketID: packet.IDNetworkSettings, Payload: []byte{1}},
	} {
		t.Run(fmt.Sprintf("%T", pk), func(t *testing.T) {
			network := newScriptedDialNetwork(func(conn net.Conn) error {
				decoder, encoder := packet.NewDecoder(conn), packet.NewEncoder(conn)
				if _, err := preparedScriptRead(decoder, packet.IDRequestNetworkSettings); err != nil {
					return err
				}
				if err := encodeScriptedPackets(encoder, pk); err != nil {
					return err
				}
				return expectScriptedClose(conn, decoder)
			})
			d := Dialer{FlushRate: -1}
			p, err := d.PrepareContextNetwork(context.Background(), network, "127.0.0.1:19132", 7)
			if err != nil {
				t.Fatal(err)
			}
			<-p.Done()
			if p.Ready() || p.Err() == nil {
				t.Fatalf("failed preparation: ready=%v err=%v", p.Ready(), p.Err())
			}
			if conn, err := p.CommitContext(context.Background(), d, "127.0.0.1:19132", 7); conn != nil || !errors.Is(err, ErrPreparedDialNotReady) {
				t.Fatalf("failed commit: conn=%v err=%v", conn != nil, err)
			}
			_ = p.Close()
			if err := <-network.done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPreparedDialAuthenticationAndSettingsOverlapWithFreshKeys(t *testing.T) {
	environment, source := preparedAuthenticationFixture(t)
	for range 2 {
		mint := make(chan struct{})
		source.release = mint
		settings := make(chan struct{})
		network := newScriptedDialNetwork(func(conn net.Conn) error {
			decoder, encoder, err := preparedScriptSettings(conn)
			if err != nil {
				return err
			}
			close(settings)
			pk, err := preparedScriptRead(decoder, packet.IDLogin)
			if err != nil {
				return err
			}
			verifier, err := environment.VerifierContext(context.Background())
			if err != nil {
				return err
			}
			_, data, result, err := login.Parse(pk.(*packet.Login).ConnectionRequest, verifier)
			if err != nil || !result.XBOXLiveAuthenticated || data.LanguageCode != "fr-FR" || !result.PublicKey.Equal(source.lastKey) {
				return fmt.Errorf("prepared Login lost authenticated key/client data binding: %v", err)
			}
			if err := preparedScriptFinish(decoder, encoder); err != nil {
				return err
			}
			return expectScriptedClose(conn, decoder)
		})
		d := Dialer{FlushRate: -1, RelayStartup: true, TokenSource: source}
		p, err := d.PrepareContextNetwork(context.Background(), network, "127.0.0.1:19132", 7)
		if err != nil {
			t.Fatal(err)
		}
		<-source.started
		<-settings
		if p.Ready() {
			t.Fatal("preparation ready before authentication finished")
		}
		close(mint)
		<-p.Done()
		if !p.Ready() {
			t.Fatalf("authenticated preparation not ready: %v", p.Err())
		}
		d.ClientData.LanguageCode = "fr-FR"
		conn, err := p.CommitContext(context.Background(), d, "127.0.0.1:19132", 7)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.Close()
		_ = p.Close()
		if err := <-network.done; err != nil {
			t.Fatal(err)
		}
	}
	if len(source.keys) != 2 || source.keys[0].Equal(source.keys[1]) {
		t.Fatal("different preparations reused a private key")
	}
}

func TestPreparedDialRejectsTokenForAnotherKey(t *testing.T) {
	_, source := preparedAuthenticationFixture(t)
	source.wrongKey = true
	mint := make(chan struct{})
	settings := make(chan struct{})
	source.release = mint
	network := newScriptedDialNetwork(func(conn net.Conn) error {
		decoder, _, err := preparedScriptSettings(conn)
		if err != nil {
			return err
		}
		close(settings)
		return expectScriptedClose(conn, decoder)
	})
	d := Dialer{FlushRate: -1, TokenSource: source}
	p, err := d.PrepareContextNetwork(context.Background(), network, "127.0.0.1:19132", 7)
	if err != nil {
		t.Fatal(err)
	}
	<-source.started
	<-settings
	close(mint)
	<-p.Done()
	if p.Ready() || p.Err() == nil {
		t.Fatalf("wrong-key token accepted: ready=%v err=%v", p.Ready(), p.Err())
	}
	_ = p.Close()
	if err := <-network.done; err != nil {
		t.Fatal(err)
	}
}

func TestPreparedDialRakNetKeepsEncryptionAndSurvivesPreparationCancellation(t *testing.T) {
	var logins atomic.Int32
	textDelivered := make(chan struct{}, 1)
	listener, err := (ListenConfig{AuthenticationDisabled: true, FlushRate: -1,
		PacketFunc: func(header packet.Header, _ []byte, _, _ net.Addr) {
			if header.PacketID == packet.IDLogin {
				logins.Add(1)
			}
			if header.PacketID == packet.IDText {
				textDelivered <- struct{}{}
			}
		},
	}).Listen("raknet", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		server := conn.(*Conn)
		if err := server.SendStartGame(GameData{}); err != nil {
			serverDone <- err
			return
		}
		if err := server.Flush(); err != nil {
			serverDone <- err
			return
		}
		<-textDelivered
		serverDone <- nil
	}()
	ctx, cancel := context.WithCancel(context.Background())
	d := Dialer{FlushRate: -1, RelayStartup: true}
	p, err := d.PrepareContextNetwork(ctx, RakNet{}, listener.Addr().String(), 7)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer p.Close()
	<-p.Done()
	if !p.Ready() || logins.Load() != 0 {
		cancel()
		t.Fatalf("before click: ready=%v login packets=%d err=%v", p.Ready(), logins.Load(), p.Err())
	}
	join, stopJoin := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopJoin()
	conn, err := p.CommitContext(join, d, listener.Addr().String(), 7)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	stopJoin()
	_ = p.Close()
	if _, ok := conn.conn.(*raknet.Conn); !ok {
		t.Fatalf("prepared transport capability hidden by %T", conn.conn)
	}
	if logins.Load() != 1 || !conn.handshakeComplete || conn.disableEncryption || conn.ctx.Err() != nil {
		t.Fatalf("committed connection lost lifetime/encryption: logins=%d handshake=%v encryptionDisabled=%v err=%v", logins.Load(), conn.handshakeComplete, conn.disableEncryption, conn.ctx.Err())
	}
	// A valid encrypted packet reaches the retained transport after both setup contexts are cancelled.
	if err := conn.WritePacket(&packet.Text{TextType: packet.TextTypeChat, Message: "loopback fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestPreparedDialCloseAndCommitHaveOneOwner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 16 {
			var logins atomic.Int32
			network := newScriptedDialNetwork(func(conn net.Conn) error {
				decoder, encoder, err := preparedScriptSettings(conn)
				if err != nil {
					return err
				}
				if _, err := preparedScriptRead(decoder, packet.IDLogin); err != nil {
					if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
						return nil
					}
					return err
				}
				logins.Add(1)
				if err := preparedScriptFinish(decoder, encoder); err != nil {
					return err
				}
				return expectScriptedClose(conn, decoder)
			})
			d := Dialer{FlushRate: -1, RelayStartup: true}
			p, err := d.PrepareContextNetwork(context.Background(), network, "127.0.0.1:19132", 7)
			if err != nil {
				t.Fatal(err)
			}
			<-p.Done()
			start, finished := make(chan struct{}), make(chan error, 1)
			go func() {
				<-start
				conn, err := p.CommitContext(context.Background(), d, "127.0.0.1:19132", 7)
				if conn != nil {
					if conn.ctx.Err() != nil {
						err = errors.New("cleanup closed the committed connection")
					}
					_ = conn.Close()
				}
				finished <- err
			}()
			go func() { <-start; _ = p.Close() }()
			close(start)
			if err := <-finished; err != nil && !errors.Is(err, ErrPreparedDialNotReady) {
				t.Fatal(err)
			}
			_ = p.Close()
			if err := <-network.done; err != nil {
				t.Fatal(err)
			}
			if logins.Load() > 1 {
				t.Fatal("racing ownership sent duplicate Login")
			}
		}
	})
}

func preparedScriptSettings(conn net.Conn) (*packet.Decoder, *packet.Encoder, error) {
	decoder, encoder := packet.NewDecoder(conn), packet.NewEncoder(conn)
	if _, err := preparedScriptRead(decoder, packet.IDRequestNetworkSettings); err != nil {
		return nil, nil, err
	}
	if err := encodeScriptedPackets(encoder, &packet.NetworkSettings{
		CompressionThreshold: 0, CompressionAlgorithm: packet.CompressionAlgorithmSnappy,
	}); err != nil {
		return nil, nil, err
	}
	decoder.EnableCompression(packet.SnappyCompression, math.MaxInt)
	encoder.EnableCompression(packet.SnappyCompression, 0)
	return decoder, encoder, nil
}

func preparedScriptRead(decoder *packet.Decoder, want uint32) (packet.Packet, error) {
	frames, err := decoder.Decode()
	if err != nil {
		return nil, err
	}
	if len(frames) != 1 {
		return nil, fmt.Errorf("got %d packets, want one", len(frames))
	}
	buf := bytes.NewBuffer(frames[0])
	var header packet.Header
	if err := header.Read(buf); err != nil {
		return nil, err
	}
	if header.PacketID != want {
		return nil, fmt.Errorf("got packet %d, want %d", header.PacketID, want)
	}
	pk := DefaultProtocol.Packets(true)[want]()
	pk.Marshal(DefaultProtocol.NewReader(buf, 0, true))
	return pk, nil
}

func preparedScriptFinish(decoder *packet.Decoder, encoder *packet.Encoder) error {
	if err := encodeScriptedPackets(encoder, &packet.PlayStatus{Status: packet.PlayStatusLoginSuccess}, &packet.ResourcePacksInfo{}); err != nil {
		return err
	}
	if _, err := preparedScriptRead(decoder, packet.IDClientCacheStatus); err != nil {
		return err
	}
	if _, err := preparedScriptRead(decoder, packet.IDResourcePackClientResponse); err != nil {
		return err
	}
	if err := encodeScriptedPackets(encoder, &packet.ResourcePackStack{}, &packet.StartGame{}); err != nil {
		return err
	}
	_, err := preparedScriptRead(decoder, packet.IDResourcePackClientResponse)
	return err
}

type preparedTokenSource struct {
	signer   *ecdsa.PrivateKey
	issuer   string
	release  <-chan struct{}
	started  chan struct{}
	delay    time.Duration
	lastKey  *ecdsa.PublicKey
	keys     []*ecdsa.PublicKey
	wrongKey bool
}

func (s *preparedTokenSource) Token() (*oauth2.Token, error) {
	return nil, errors.New("legacy token not expected")
}

func (s *preparedTokenSource) MultiplayerToken(ctx context.Context, key *ecdsa.PublicKey) (string, error) {
	s.lastKey = key
	s.keys = append(s.keys, key)
	if s.started != nil {
		s.started <- struct{}{}
	}
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if s.wrongKey {
		key = &s.signer.PublicKey
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: s.signer}, &jose.SignerOptions{})
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(map[string]any{
		"iss": s.issuer, "aud": "api://auth-minecraft-services/multiplayer",
		"exp": time.Now().Add(time.Hour).Unix(), "cpk": login.MarshalPublicKey(key),
		"xid": "123456789", "xname": "Fixture", "leguuid": uuid.NewString(),
	}).Serialize()
}

func preparedAuthenticationFixture(t testing.TB) (*service.AuthorizationEnvironment, *preparedTokenSource) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/jwks" {
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: string(jose.ES384), Use: "sig", CertificateThumbprintSHA1: make([]byte, 20)}}})
			return
		}
		_ = json.NewEncoder(w).Encode(oidc.ProviderConfig{IssuerURL: issuer, JWKSURL: issuer + "jwks", Algorithms: []string{string(jose.ES384)}})
	}))
	issuer = server.URL + "/"
	u, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	environment := &service.AuthorizationEnvironment{Issuer: u, HTTPClient: server.Client()}
	authEnvCacheMu.Lock()
	previous := authEnvCache
	authEnvCache = environment
	authEnvCacheMu.Unlock()
	t.Cleanup(func() {
		authEnvCacheMu.Lock()
		authEnvCache = previous
		authEnvCacheMu.Unlock()
		server.Close()
	})
	return environment, &preparedTokenSource{signer: key, issuer: issuer, started: make(chan struct{}, 2)}
}
