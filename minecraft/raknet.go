package minecraft

import (
	"context"
	"log/slog"
	"net"

	"github.com/sandertv/go-raknet"
)

// RakNet is an implementation of a RakNet v10 Network.
type RakNet struct {
	l *slog.Logger
	// ServerID is the RakNet server GUID advertised by listeners. If zero, each
	// listener generates its own ID.
	ServerID int64
	// Logger overrides the logger used for RakNet dial and listen errors.
	// If nil, the logger passed by RegisterNetwork is used.
	Logger *slog.Logger
	// UpstreamDialer overrides the dialer used for outbound UDP connections.
	// If nil, RakNet uses the default net.Dialer.
	UpstreamDialer raknet.UpstreamDialer
	// MaxMTU caps both outbound MTU probes and MTU negotiation with incoming clients.
	// If zero, go-raknet uses its default maximum.
	MaxMTU uint16
	// UpstreamPacketListener supplies a pre-bound or customized listener socket.
	// If nil, go-raknet uses net.ListenPacket.
	UpstreamPacketListener raknet.UpstreamPacketListener
}

// DialContext ...
func (r RakNet) DialContext(ctx context.Context, address string) (net.Conn, error) {
	return r.dialer().DialContext(ctx, address)
}

// PingContext ...
func (r RakNet) PingContext(ctx context.Context, address string) (response []byte, err error) {
	return r.dialer().PingContext(ctx, address)
}

// Listen ...
func (r RakNet) Listen(address string) (NetworkListener, error) {
	return r.listenConfig().Listen(address)
}

// listenConfig builds the go-raknet listener configuration shared with tests.
func (r RakNet) listenConfig() raknet.ListenConfig {
	return raknet.ListenConfig{
		ErrorLog:               r.logger().With("net origin", "raknet"),
		ServerID:               r.ServerID,
		MaxMTU:                 r.MaxMTU,
		UpstreamPacketListener: r.UpstreamPacketListener,
	}
}

func (r RakNet) dialer() raknet.Dialer {
	return raknet.Dialer{
		ErrorLog:       r.logger().With("net origin", "raknet"),
		UpstreamDialer: r.UpstreamDialer,
		MaxMTU:         r.MaxMTU,
	}
}

func (r RakNet) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	if r.l != nil {
		return r.l
	}
	return slog.Default()
}

// init registers the RakNet network.
func init() {
	RegisterNetwork("raknet", func(l *slog.Logger) Network { return RakNet{l: l} })
}
