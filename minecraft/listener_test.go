package minecraft

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

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

func writePacket(w io.Writer, pk packet.Packet) error {
	buf := new(bytes.Buffer)
	header := &packet.Header{PacketID: pk.ID()}
	if err := header.Write(buf); err != nil {
		return err
	}
	pk.Marshal(proto{}.NewWriter(buf, 0))
	return packet.NewEncoder(w).Encode([][]byte{buf.Bytes()})
}

type fakeNetworkListener struct {
	addr net.Addr
}

func (f fakeNetworkListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (f fakeNetworkListener) Close() error              { return nil }
func (f fakeNetworkListener) Addr() net.Addr            { return f.addr }
func (fakeNetworkListener) ID() int64                   { return 1 }
func (fakeNetworkListener) PongData([]byte)             {}
