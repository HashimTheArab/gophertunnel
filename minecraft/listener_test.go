package minecraft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

func TestListenConfigListenNetworkUsesExplicitNetwork(t *testing.T) {
	t.Parallel()

	listener := fakeNetworkListener{addr: &net.UDPAddr{IP: net.IPv4zero, Port: 19132}}
	network := listenTestNetwork{
		listen: func(address string) (NetworkListener, error) {
			if address != "ignored-by-nethernet" {
				t.Fatalf("listen address = %q, want ignored-by-nethernet", address)
			}
			return listener, nil
		},
	}

	got, err := ListenConfig{AuthenticationDisabled: true}.ListenNetwork(network, "ignored-by-nethernet")
	if err != nil {
		t.Fatalf("ListenNetwork: %v", err)
	}
	defer got.Close()
	if got.listener != listener {
		t.Fatalf("underlying listener = %v, want explicit listener", got.listener)
	}
}

func TestListenerDisablePacketEncryption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		disableInConfig        bool
		disableInTransport     bool
		authenticationDisabled bool
		wantDisabled           bool
	}{
		{name: "enabled by default"},
		{name: "disabled by listener config", disableInConfig: true, wantDisabled: true},
		{name: "disabled by transport", disableInTransport: true, authenticationDisabled: true, wantDisabled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()

			listener := &Listener{
				cfg: ListenConfig{
					ErrorLog:                slog.New(internal.DiscardHandler{}),
					StatusProvider:          NewStatusProvider("Minecraft Server", "Gophertunnel"),
					AuthenticationDisabled:  tt.authenticationDisabled,
					DisablePacketEncryption: tt.disableInConfig,
					DisablePacketHandling:   true,
				},
				listener: fakeNetworkListener{addr: &net.UDPAddr{IP: net.IPv4zero, Port: 19132}},
				incoming: make(chan *Conn, 1),
				close:    make(chan struct{}),
			}
			serveAuthenticated(listener, encryptionDisablingConn{Conn: server, disabled: tt.disableInTransport})

			if err := writePacket(client, &packet.ResourcePacksInfo{}); err != nil {
				t.Fatalf("write packet: %v", err)
			}
			conn := acceptConn(t, listener)
			if conn.disableEncryption != tt.wantDisabled {
				t.Fatalf("disableEncryption = %t, want %t", conn.disableEncryption, tt.wantDisabled)
			}
			if conn.authEnabled == tt.authenticationDisabled {
				t.Fatalf("authEnabled = %t, AuthenticationDisabled = %t", conn.authEnabled, tt.authenticationDisabled)
			}
		})
	}
}

func TestListenerPublishesDisablePacketHandlingConnection(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()

	log := slog.New(internal.DiscardHandler{})
	listener := &Listener{
		cfg: ListenConfig{
			ErrorLog:              log,
			StatusProvider:        NewStatusProvider("Minecraft Server", "Gophertunnel"),
			DisablePacketHandling: true,
		},
		listener: fakeNetworkListener{addr: &net.UDPAddr{IP: net.IPv4zero, Port: 19132}},
		incoming: make(chan *Conn, 1),
		close:    make(chan struct{}),
	}
	listener.playerCount.Store(1)

	conn := newConn(server, nil, log, proto{}, -1, true)
	conn.pool = conn.proto.Packets(true)
	conn.disablePacketHandling = true
	conn.handshakeComplete = true
	go listener.handleConn(conn)

	if err := writePacket(client, &packet.ResourcePacksInfo{}); err != nil {
		t.Fatalf("write packet: %v", err)
	}

	select {
	case accepted := <-listener.incoming:
		if accepted != conn {
			t.Fatalf("accepted connection = %p, want %p", accepted, conn)
		}
	case <-time.After(time.Second):
		t.Fatal("listener did not publish passthrough connection")
	}
}

func TestListenerConnHandlerReceivesDisablePacketHandlingConnection(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()

	handled := make(chan *Conn, 1)
	log := slog.New(internal.DiscardHandler{})
	listener := &Listener{
		cfg: ListenConfig{
			ErrorLog:              log,
			StatusProvider:        NewStatusProvider("Minecraft Server", "Gophertunnel"),
			DisablePacketHandling: true,
			ConnHandler: func(conn *Conn) error {
				handled <- conn
				return nil
			},
		},
		listener: fakeNetworkListener{addr: &net.UDPAddr{IP: net.IPv4zero, Port: 19132}},
		incoming: make(chan *Conn, 1),
		close:    make(chan struct{}),
	}
	listener.playerCount.Store(1)

	conn := newConn(server, nil, log, proto{}, -1, true)
	conn.pool = conn.proto.Packets(true)
	conn.disablePacketHandling = true
	conn.handshakeComplete = true
	go listener.handleConn(conn)

	if err := writePacket(client, &packet.ResourcePacksInfo{}); err != nil {
		t.Fatalf("write packet: %v", err)
	}

	select {
	case accepted := <-handled:
		if accepted != conn {
			t.Fatalf("handled connection = %p, want %p", accepted, conn)
		}
	case <-time.After(time.Second):
		t.Fatal("listener did not deliver passthrough connection to ConnHandler")
	}

	select {
	case accepted := <-listener.incoming:
		t.Fatalf("listener published connection %p to Accept despite ConnHandler", accepted)
	default:
	}
}

func TestListenerDisablePacketHandlingConsumesClientHandshake(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()

	log := slog.New(internal.DiscardHandler{})
	listener := &Listener{
		cfg: ListenConfig{
			ErrorLog:              log,
			StatusProvider:        NewStatusProvider("Minecraft Server", "Gophertunnel"),
			DisablePacketHandling: true,
		},
		listener: fakeNetworkListener{addr: &net.UDPAddr{IP: net.IPv4zero, Port: 19132}},
		incoming: make(chan *Conn, 1),
		close:    make(chan struct{}),
	}
	listener.playerCount.Store(1)

	conn := newConn(server, nil, log, proto{}, -1, true)
	conn.pool = conn.proto.Packets(true)
	conn.disablePacketHandling = true
	conn.expect(packet.IDClientToServerHandshake)
	key := [32]byte{1}
	conn.dec.EnableEncryption(key)
	go listener.handleConn(conn)

	frame, err := encodePacket(&packet.ClientToServerHandshake{})
	if err != nil {
		t.Fatalf("encode packet: %v", err)
	}
	enc := packet.NewEncoder(client)
	enc.EnableEncryption(key)
	if err := enc.Encode([][]byte{frame}); err != nil {
		t.Fatalf("write packet: %v", err)
	}

	select {
	case accepted := <-listener.incoming:
		if accepted != conn {
			t.Fatalf("accepted connection = %p, want %p", accepted, conn)
		}
	case <-time.After(time.Second):
		t.Fatal("listener did not publish passthrough connection")
	}

	if err := client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var b [1]byte
	n, err := client.Read(b[:])
	if err == nil || n != 0 {
		t.Fatalf("listener wrote %d byte(s) while consuming client handshake; expected no local response", n)
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read error = %v, want timeout", err)
	}
}

func TestListenerReadBatchPreservesNetworkBatch(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()

	log := slog.New(internal.DiscardHandler{})
	listener := &Listener{
		cfg: ListenConfig{
			ErrorLog:              log,
			StatusProvider:        NewStatusProvider("Minecraft Server", "Gophertunnel"),
			DisablePacketHandling: true,
			EnableBatchReading:    true,
			AllowUnknownPackets:   true,
		},
		listener: fakeNetworkListener{addr: &net.UDPAddr{IP: net.IPv4zero, Port: 19132}},
		incoming: make(chan *Conn, 1),
		close:    make(chan struct{}),
	}
	serveAuthenticated(listener, server)

	if err := writePackets(client,
		&packet.ResourcePacksInfo{},
		&packet.Unknown{PacketID: 777},
	); err != nil {
		t.Fatalf("write packet batch: %v", err)
	}

	var accepted *Conn
	select {
	case accepted = <-listener.incoming:
	case <-time.After(time.Second):
		t.Fatal("listener did not publish passthrough connection")
	}

	packets, err := accepted.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("ReadBatch returned %d packets, want 2", len(packets))
	}
	if packets[0].ID() != packet.IDResourcePacksInfo || packets[1].ID() != 777 {
		t.Fatalf("ReadBatch IDs = [%d %d], want [%d 777]", packets[0].ID(), packets[1].ID(), packet.IDResourcePacksInfo)
	}

	writeErr := make(chan error, 1)
	go func() {
		if err := writePackets(client,
			&packet.Unknown{PacketID: 778},
			&packet.Unknown{PacketID: 779},
		); err != nil {
			writeErr <- err
			return
		}
		writeErr <- writePackets(client, &packet.Unknown{PacketID: 780})
	}()

	first, err := accepted.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch first subsequent batch: %v", err)
	}
	second, err := accepted.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch second subsequent batch: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write subsequent batches: %v", err)
	}
	if ids := packetIDs(first); !slices.Equal(ids, []uint32{778, 779}) {
		t.Fatalf("first subsequent batch IDs = %v, want [778 779]", ids)
	}
	if ids := packetIDs(second); !slices.Equal(ids, []uint32{780}) {
		t.Fatalf("second subsequent batch IDs = %v, want [780]", ids)
	}
}

func TestListenerConnHandlerCanReadPublishedBatch(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	defer client.Close()

	type result struct {
		packets []packet.Packet
		err     error
	}
	resultCh := make(chan result, 1)
	log := slog.New(internal.DiscardHandler{})
	listener := &Listener{
		cfg: ListenConfig{
			ErrorLog:              log,
			StatusProvider:        NewStatusProvider("Minecraft Server", "Gophertunnel"),
			DisablePacketHandling: true,
			EnableBatchReading:    true,
			AllowUnknownPackets:   true,
			ConnHandler: func(conn *Conn) error {
				packets, err := conn.ReadBatch()
				resultCh <- result{packets: packets, err: err}
				return err
			},
		},
		listener: fakeNetworkListener{addr: &net.UDPAddr{IP: net.IPv4zero, Port: 19132}},
		incoming: make(chan *Conn, 1),
		close:    make(chan struct{}),
	}
	serveAuthenticated(listener, server)

	if err := writePackets(client,
		&packet.ResourcePacksInfo{},
		&packet.Unknown{PacketID: 777},
	); err != nil {
		t.Fatalf("write packet batch: %v", err)
	}

	select {
	case got := <-resultCh:
		if got.err != nil {
			t.Fatalf("ReadBatch: %v", got.err)
		}
		if len(got.packets) != 2 {
			t.Fatalf("ReadBatch returned %d packets, want 2", len(got.packets))
		}
	case <-time.After(time.Second):
		t.Fatal("ConnHandler blocked reading the batch that published the connection")
	}
}

// newBatchReadingListener returns a listener in batch-reading passthrough mode serving one connection,
// along with the client side of that connection. mutate, if non-nil, adjusts the config before the
// connection is created.
func newBatchReadingListener(t *testing.T, mutate func(*ListenConfig)) (*Listener, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	listener := &Listener{
		cfg: ListenConfig{
			ErrorLog:              slog.New(internal.DiscardHandler{}),
			StatusProvider:        NewStatusProvider("Minecraft Server", "Gophertunnel"),
			DisablePacketHandling: true,
			EnableBatchReading:    true,
			AllowUnknownPackets:   true,
		},
		listener: fakeNetworkListener{addr: &net.UDPAddr{IP: net.IPv4zero, Port: 19132}},
		incoming: make(chan *Conn, 1),
		close:    make(chan struct{}),
	}
	if mutate != nil {
		mutate(&listener.cfg)
	}
	serveAuthenticated(listener, server)
	return listener, client
}

func acceptConn(t *testing.T, listener *Listener) *Conn {
	t.Helper()
	select {
	case conn := <-listener.incoming:
		return conn
	case <-time.After(time.Second):
		t.Fatal("listener did not publish the connection")
		return nil
	}
}

func TestListenerReadBatchDeliversBatchBeforeMidBatchError(t *testing.T) {
	t.Parallel()

	listener, client := newBatchReadingListener(t, nil)

	valid, err := encodePacket(&packet.ResourcePacksInfo{})
	if err != nil {
		t.Fatalf("encode packet: %v", err)
	}
	// The second frame is an unterminated varuint32, so its header cannot be parsed and the decode
	// loop tears the connection down mid-batch.
	if err := writeRawFrames(client, [][]byte{valid, {0xff, 0xff, 0xff, 0xff, 0xff}}); err != nil {
		t.Fatalf("write raw frames: %v", err)
	}

	accepted := acceptConn(t, listener)
	packets, err := accepted.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if len(packets) != 1 || packets[0].ID() != packet.IDResourcePacksInfo {
		t.Fatalf("ReadBatch IDs = %v, want [%d]", packetIDs(packets), packet.IDResourcePacksInfo)
	}
}

func TestListenerBatchReadingDoesNotStallDecodeLoop(t *testing.T) {
	t.Parallel()

	listener, client := newBatchReadingListener(t, nil)

	const batches = 12
	written := make(chan error, 1)
	go func() {
		// The first batch flips passthrough mode and publishes the connection.
		if err := writePackets(client, &packet.ResourcePacksInfo{}); err != nil {
			written <- err
			return
		}
		for i := range batches {
			if err := writePackets(client, &packet.Unknown{PacketID: uint32(1000 + i)}); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("write batches: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decode loop stalled while batches were left unread")
	}

	accepted := acceptConn(t, listener)
	first, err := accepted.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch publishing batch: %v", err)
	}
	if ids := packetIDs(first); !slices.Equal(ids, []uint32{packet.IDResourcePacksInfo}) {
		t.Fatalf("publishing batch IDs = %v, want [%d]", ids, packet.IDResourcePacksInfo)
	}
	for i := range batches {
		packets, err := accepted.ReadBatch()
		if err != nil {
			t.Fatalf("ReadBatch batch %d: %v", i, err)
		}
		if ids := packetIDs(packets); !slices.Equal(ids, []uint32{uint32(1000 + i)}) {
			t.Fatalf("batch %d IDs = %v, want [%d]", i, ids, 1000+i)
		}
	}
}

func TestListenerDeliversClientDisconnectMissingFromPool(t *testing.T) {
	t.Parallel()

	// Disconnect is not in the client packet pool, so it decodes to *packet.Unknown; the receive path
	// must deliver it like any unknown packet instead of panicking on a *packet.Disconnect assertion.
	listener, client := newBatchReadingListener(t, nil)

	if err := writePackets(client, &packet.ResourcePacksInfo{}); err != nil {
		t.Fatalf("write publishing batch: %v", err)
	}
	accepted := acceptConn(t, listener)
	if _, err := accepted.ReadBatch(); err != nil {
		t.Fatalf("ReadBatch publishing batch: %v", err)
	}

	if err := writePackets(client, &packet.Unknown{PacketID: 777}, &packet.Disconnect{}); err != nil {
		t.Fatalf("write disconnect batch: %v", err)
	}
	packets, err := accepted.ReadBatch()
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if ids := packetIDs(packets); !slices.Equal(ids, []uint32{777, packet.IDDisconnect}) {
		t.Fatalf("batch IDs = %v, want [777 %d]", ids, packet.IDDisconnect)
	}
}

func TestListenerConnHandlerCanBlockReadingBatches(t *testing.T) {
	t.Parallel()

	type result struct {
		first, second []packet.Packet
		err           error
	}
	resultCh := make(chan result, 1)
	ready := make(chan struct{})
	listener, client := newBatchReadingListener(t, func(cfg *ListenConfig) {
		cfg.ConnHandler = func(conn *Conn) error {
			first, err := conn.ReadBatch()
			if err != nil {
				resultCh <- result{err: err}
				return err
			}
			close(ready)
			second, err := conn.ReadBatch()
			resultCh <- result{first: first, second: second, err: err}
			return err
		}
	})
	_ = listener

	if err := writePackets(client, &packet.ResourcePacksInfo{}, &packet.Unknown{PacketID: 777}); err != nil {
		t.Fatalf("write publishing batch: %v", err)
	}
	select {
	case <-ready:
	case got := <-resultCh:
		t.Fatalf("ConnHandler failed reading the publishing batch: %v", got.err)
	case <-time.After(time.Second):
		t.Fatal("ConnHandler never received the publishing batch")
	}

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- writePackets(client, &packet.Unknown{PacketID: 778})
	}()
	select {
	case got := <-resultCh:
		if got.err != nil {
			t.Fatalf("ConnHandler second ReadBatch: %v", got.err)
		}
		if ids := packetIDs(got.first); !slices.Equal(ids, []uint32{packet.IDResourcePacksInfo, 777}) {
			t.Fatalf("first batch IDs = %v, want [%d 777]", ids, packet.IDResourcePacksInfo)
		}
		if ids := packetIDs(got.second); !slices.Equal(ids, []uint32{778}) {
			t.Fatalf("second batch IDs = %v, want [778]", ids)
		}
	case <-time.After(time.Second):
		t.Fatal("ConnHandler blocked reading a second batch: the decode loop is stalled inside the handler")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write second batch: %v", err)
	}
}

func TestListenerPongDataUsesStatusProviderSubtitle(t *testing.T) {
	t.Parallel()

	var pongData []byte
	listener := &Listener{
		cfg: ListenConfig{
			StatusProvider: NewStatusProvider("Minecraft Server", "Provider Subtitle"),
		},
		listener: fakeNetworkListener{
			addr:     &net.UDPAddr{IP: net.IPv4zero, Port: 19132},
			pongData: &pongData,
		},
	}
	listener.updatePongData()

	status := ParsePongData(pongData)
	if status.ServerName != "Minecraft Server" {
		t.Fatalf("server name = %q, want Minecraft Server", status.ServerName)
	}
	if status.ServerSubName != "Provider Subtitle" {
		t.Fatalf("server subtitle = %q, want Provider Subtitle", status.ServerSubName)
	}
}

func writePacket(w io.Writer, pk packet.Packet) error {
	return writePackets(w, pk)
}

func writePackets(w io.Writer, packets ...packet.Packet) error {
	encoded := make([][]byte, 0, len(packets))
	for _, pk := range packets {
		frame, err := encodePacket(pk)
		if err != nil {
			return err
		}
		encoded = append(encoded, frame)
	}
	return writeRawFrames(w, encoded)
}

// encodePacket serialises a packet to the header+payload frame carried inside a network batch.
func encodePacket(pk packet.Packet) ([]byte, error) {
	buf := new(bytes.Buffer)
	header := &packet.Header{PacketID: pk.ID()}
	if err := header.Write(buf); err != nil {
		return nil, err
	}
	pk.Marshal(proto{}.NewWriter(buf, 0))
	return buf.Bytes(), nil
}

// writeRawFrames encodes pre-serialised packet frames as one network batch.
func writeRawFrames(w io.Writer, frames [][]byte) error {
	return packet.NewEncoder(w).Encode(frames)
}

type fakeNetworkListener struct {
	addr     net.Addr
	pongData *[]byte
}

type encryptionDisablingConn struct {
	net.Conn
	disabled bool
}

func (conn encryptionDisablingConn) DisableEncryption() bool { return conn.disabled }

func (f fakeNetworkListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (f fakeNetworkListener) Close() error              { return nil }
func (f fakeNetworkListener) Addr() net.Addr            { return f.addr }
func (fakeNetworkListener) ID() int64                   { return 1 }
func (f fakeNetworkListener) PongData(data []byte) {
	if f.pongData != nil {
		*f.pongData = append((*f.pongData)[:0], data...)
	}
}

type listenTestNetwork struct {
	listen func(string) (NetworkListener, error)
}

func (listenTestNetwork) DialContext(context.Context, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (listenTestNetwork) PingContext(context.Context, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (n listenTestNetwork) Listen(address string) (NetworkListener, error) {
	return n.listen(address)
}

// serveAuthenticated serves netConn as a connection whose login was already verified, so tests of what
// follows can publish it with any post-login packet.
func serveAuthenticated(listener *Listener, netConn net.Conn) {
	conn := listener.newListenerConn(netConn)
	conn.handshakeComplete = true
	listener.playerCount.Add(1)
	go listener.handleConn(conn)
}

// A peer that connects but never logs in must be closed once LoginTimeout passes.
func TestListenerLoginTimeoutClosesSilentConnection(t *testing.T) {
	t.Parallel()

	listener, network := newPipeListener(t, ListenConfig{LoginTimeout: 50 * time.Millisecond}, true)
	peer := network.connect()
	defer peer.Close()

	if !peer.closedWithin(time.Second) {
		t.Fatal("silent connection was not closed after the login timeout")
	}
	waitForCount(t, "player count", 0, listener.PlayerCount)
}

// LoginTimeout ends at authentication: the rest of the login sequence, such as resource packs, is not bounded.
func TestListenerLoginTimeoutEndsAtAuthentication(t *testing.T) {
	t.Parallel()

	_, network := newPipeListener(t, ListenConfig{LoginTimeout: 100 * time.Millisecond}, true)
	peer := network.connect()
	defer peer.Close()
	peer.logIn(t)

	// The client never answers the resource pack offer that follows authentication.
	if peer.closedWithin(300 * time.Millisecond) {
		t.Fatal("authenticated connection was closed by the login timeout")
	}
}

// A handshake batched in plaintext with the Login proves nothing, so the connection must not authenticate.
func TestListenerRejectsHandshakeBatchedWithLogin(t *testing.T) {
	t.Parallel()

	for _, passthrough := range []bool{true, false} {
		listener, network := newPipeListener(t, ListenConfig{DisablePacketHandling: passthrough, EnableBatchReading: passthrough}, false)
		peer := network.connect()
		defer peer.Close()
		peer.logIn(t, &packet.ClientToServerHandshake{}, &packet.ResourcePackClientResponse{Response: packet.PackResponseCompleted})

		if !peer.closedWithin(time.Second) {
			t.Fatalf("passthrough=%v: connection with a plaintext handshake was not closed", passthrough)
		}
		select {
		case conn := <-listener.incoming:
			t.Fatalf("passthrough=%v: published a connection whose login key was never proven (proven=%v)", passthrough, conn.LoginKeyProven())
		default:
		}
	}
}

// newPipeListener returns a listener with authentication disabled served over in-memory pipes. Pipes that
// disable encryption stand in for transports such as NetherNet.
func newPipeListener(t *testing.T, cfg ListenConfig, disableEncryption bool) (*Listener, *pipeTestNetwork) {
	t.Helper()
	network := &pipeTestNetwork{conns: make(chan net.Conn), closed: make(chan struct{}), disableEncryption: disableEncryption}
	cfg.AuthenticationDisabled = true
	cfg.AllowUnknownPackets = true
	listener, err := cfg.ListenNetwork(network, "")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, network
}

// pipeTestNetwork hands in-memory connections to a listener.
type pipeTestNetwork struct {
	conns             chan net.Conn
	closed            chan struct{}
	once              sync.Once
	disableEncryption bool
}

// connect hands a new connection to the listener and returns its client side, which discards what it reads.
func (n *pipeTestNetwork) connect() *pipePeer {
	client, server := net.Pipe()
	n.conns <- encryptionDisablingConn{Conn: server, disabled: n.disableEncryption}
	peer := &pipePeer{Conn: client, closed: make(chan struct{})}
	go func() {
		_, _ = io.Copy(io.Discard, client)
		close(peer.closed)
	}()
	return peer
}

func (n *pipeTestNetwork) DialContext(context.Context, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (n *pipeTestNetwork) PingContext(context.Context, string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (n *pipeTestNetwork) Listen(string) (NetworkListener, error) { return n, nil }

func (n *pipeTestNetwork) Accept() (net.Conn, error) {
	select {
	case c := <-n.conns:
		return c, nil
	case <-n.closed:
		return nil, net.ErrClosed
	}
}

func (n *pipeTestNetwork) Close() error {
	n.once.Do(func() { close(n.closed) })
	return nil
}

func (n *pipeTestNetwork) Addr() net.Addr  { return &net.UDPAddr{IP: net.IPv4zero, Port: 19132} }
func (n *pipeTestNetwork) ID() int64       { return 1 }
func (n *pipeTestNetwork) PongData([]byte) {}

// pipePeer is the client side of a pipeTestNetwork connection.
type pipePeer struct {
	net.Conn
	closed chan struct{}
}

// closedWithin reports whether the listener closed the connection within timeout.
func (p *pipePeer) closedWithin(timeout time.Duration) bool {
	select {
	case <-p.closed:
		return true
	case <-time.After(timeout):
		return false
	}
}

// logIn sends RequestNetworkSettings, then an offline Login batched with extra.
func (p *pipePeer) logIn(t *testing.T, extra ...packet.Packet) {
	t.Helper()
	enc := packet.NewEncoder(p.Conn)
	frame, err := encodePacket(&packet.RequestNetworkSettings{ClientProtocol: protocol.CurrentProtocol})
	if err != nil {
		t.Fatalf("encode RequestNetworkSettings: %v", err)
	}
	if err := enc.Encode([][]byte{frame}); err != nil {
		t.Fatalf("write RequestNetworkSettings: %v", err)
	}
	enc.EnableCompression(packet.DefaultCompression, math.MaxInt)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var identityData login.IdentityData
	defaultIdentityData(&identityData)
	var clientData login.ClientData
	defaultClientData("127.0.0.1:19132", identityData.DisplayName, &clientData)
	frames := make([][]byte, 0, 1+len(extra))
	for _, pk := range append([]packet.Packet{&packet.Login{ClientProtocol: protocol.CurrentProtocol, ConnectionRequest: login.EncodeOffline(identityData, clientData, key)}}, extra...) {
		frame, err := encodePacket(pk)
		if err != nil {
			t.Fatalf("encode %T: %v", pk, err)
		}
		frames = append(frames, frame)
	}
	if err := enc.Encode(frames); err != nil {
		t.Fatalf("write Login: %v", err)
	}
}

// waitForCount waits for count to reach want.
func waitForCount(t *testing.T, what string, want int, count func() int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for count() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s = %d, want %d", what, count(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// A client sending post-login packet IDs before logging in must not be published by a passthrough listener.
func TestListenerPassthroughDoesNotPublishBeforeLogin(t *testing.T) {
	t.Parallel()

	listener, network := newPipeListener(t, ListenConfig{DisablePacketHandling: true, EnableBatchReading: true}, true)
	peer := network.connect()
	defer peer.Close()
	if err := writePackets(peer, &packet.ResourcePacksInfo{}); err != nil {
		t.Fatalf("write packet: %v", err)
	}
	select {
	case conn := <-listener.incoming:
		t.Fatalf("published a connection that never logged in (xuid=%q)", conn.IdentityData().XUID)
	case <-time.After(200 * time.Millisecond):
	}
}

// Work after authentication, such as fetching resource packs, must not run into the login deadline.
func TestListenerLoginTimeoutEndsBeforePostAuthCallbacks(t *testing.T) {
	t.Parallel()

	_, network := newPipeListener(t, ListenConfig{
		LoginTimeout: 50 * time.Millisecond,
		FetchResourcePacks: func(_ login.IdentityData, _ login.ClientData, current []*resource.Pack) []*resource.Pack {
			time.Sleep(200 * time.Millisecond)
			return current
		},
	}, true)
	peer := network.connect()
	defer peer.Close()
	peer.logIn(t)
	if peer.closedWithin(400 * time.Millisecond) {
		t.Fatal("client that authenticated in time was closed while resource packs were fetched")
	}
}
