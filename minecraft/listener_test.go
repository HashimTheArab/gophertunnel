package minecraft

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
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
	go listener.handleConn(conn)

	if err := writePacket(client, &packet.ClientToServerHandshake{}); err != nil {
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
	listener.createConn(server)

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
	listener.createConn(server)

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
	listener.createConn(server)
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
