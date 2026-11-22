package netguard

import (
	"context"
	"net"
	"syscall"

	"github.com/pion/ice/v4"
	"github.com/pion/transport/v5"
	"github.com/pion/transport/v5/stdnet"
	"github.com/pion/webrtc/v4"
)

// RestrictWebRTC limits the ICE, STUN and TURN traffic of connections built from settings to public
// addresses, whatever candidates or servers the peer signals. It replaces any Net already set and
// turns off mDNS and active ICE-TCP, which open sockets outside the Net.
func RestrictWebRTC(settings *webrtc.SettingEngine) error {
	base, err := stdnet.NewNet()
	if err != nil {
		return err
	}
	settings.SetNet(guardedNet{base})
	settings.DisableActiveTCP(true)
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	return nil
}

// guardedNet checks every destination before a socket connects to it or a datagram is sent to it.
type guardedNet struct {
	transport.Net
}

func (n guardedNet) ListenPacket(network, address string) (net.PacketConn, error) {
	conn, err := n.Net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return guardedPacketConn{conn}, nil
}

func (n guardedNet) ListenUDP(network string, laddr *net.UDPAddr) (transport.UDPConn, error) {
	conn, err := n.Net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	return guardedUDPConn{conn}, nil
}

func (n guardedNet) Dial(network, address string) (net.Conn, error) {
	return n.CreateDialer(&net.Dialer{}).Dial(network, address)
}

func (n guardedNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	if err := checkAddr(raddr); err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: raddr, Err: err}
	}
	return n.Net.DialUDP(network, laddr, raddr)
}

func (n guardedNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	if err := checkAddr(raddr); err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: raddr, Err: err}
	}
	return n.Net.DialTCP(network, laddr, raddr)
}

func (n guardedNet) CreateDialer(d *net.Dialer) transport.Dialer {
	guarded := *d
	if next := d.ControlContext; next != nil {
		guarded.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			if err := Control(network, address, c); err != nil {
				return err
			}
			return next(ctx, network, address, c)
		}
	} else {
		next := d.Control
		guarded.Control = func(network, address string, c syscall.RawConn) error {
			if err := Control(network, address, c); err != nil {
				return err
			}
			if next != nil {
				return next(network, address, c)
			}
			return nil
		}
	}
	return n.Net.CreateDialer(&guarded)
}

func (n guardedNet) CreateListenConfig(config *net.ListenConfig) transport.ListenConfig {
	return guardedListenConfig{n.Net.CreateListenConfig(config)}
}

type guardedListenConfig struct {
	transport.ListenConfig
}

func (c guardedListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	conn, err := c.ListenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return guardedPacketConn{conn}, nil
}

type guardedPacketConn struct {
	net.PacketConn
}

func (c guardedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := checkAddr(addr); err != nil {
		return 0, &net.OpError{Op: "write", Net: c.LocalAddr().Network(), Addr: addr, Err: err}
	}
	return c.PacketConn.WriteTo(p, addr)
}

type guardedUDPConn struct {
	transport.UDPConn
}

func (c guardedUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := checkAddr(addr); err != nil {
		return 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: err}
	}
	return c.UDPConn.WriteTo(p, addr)
}

func (c guardedUDPConn) WriteToUDP(p []byte, addr *net.UDPAddr) (int, error) {
	if err := checkAddr(addr); err != nil {
		return 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: err}
	}
	return c.UDPConn.WriteToUDP(p, addr)
}

// WriteMsgUDP checks addr; a nil addr writes to the connected peer, which was checked at dial.
func (c guardedUDPConn) WriteMsgUDP(p, oob []byte, addr *net.UDPAddr) (int, int, error) {
	if addr != nil {
		if err := checkAddr(addr); err != nil {
			return 0, 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: err}
		}
	}
	return c.UDPConn.WriteMsgUDP(p, oob, addr)
}
