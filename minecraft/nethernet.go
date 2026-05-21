package minecraft

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/df-mc/go-nethernet"
)

// NetherNet is an implementation of a NetherNet network.
type NetherNet struct {
	// Signaling is used to exchange WebRTC signals and ICE credentials.
	// It must be non-nil when dialing or listening.
	Signaling nethernet.Signaling

	// Log is used for dialing and listening when Dialer.Log or ListenConfig.Log is nil.
	Log *slog.Logger

	// Dialer specifies options for establishing connections with DialContext.
	Dialer nethernet.Dialer
	// ListenConfig specifies options for listening for incoming connections with Listen.
	ListenConfig nethernet.ListenConfig
}

// DialContext ...
func (n NetherNet) DialContext(ctx context.Context, address string) (net.Conn, error) {
	if n.Signaling == nil {
		return nil, errors.New("minecraft: NetherNet.DialContext: Signaling is nil")
	}
	d := n.Dialer
	if d.Log == nil {
		d.Log = n.Log
	}
	return d.DialContext(ctx, address, n.Signaling)
}

// PingContext ...
func (n NetherNet) PingContext(context.Context, string) ([]byte, error) {
	return nil, errors.New("minecraft: NetherNet.PingContext: not supported")
}

// Listen ...
func (n NetherNet) Listen(string) (NetworkListener, error) {
	if n.Signaling == nil {
		return nil, errors.New("minecraft: NetherNet.Listen: Signaling is nil")
	}
	conf := n.ListenConfig
	if conf.Log == nil {
		conf.Log = n.Log
	}
	return conf.Listen(n.Signaling)
}
