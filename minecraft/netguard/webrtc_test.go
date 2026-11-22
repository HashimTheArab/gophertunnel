package netguard

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/transport/v5/stdnet"
	"github.com/pion/webrtc/v4"
)

// A restricted peer never connects to a peer whose only candidates are loopback, as when a remote
// server signals host candidates aimed at services on our machine.
func TestRestrictWebRTCRefusesLoopbackCandidates(t *testing.T) {
	if state := connectLoopbackPeers(t, false); state != webrtc.ICEConnectionStateConnected {
		t.Fatalf("control: unrestricted ICE state = %s, want connected", state)
	}
	if state := connectLoopbackPeers(t, true); state != webrtc.ICEConnectionStateFailed {
		t.Fatalf("restricted ICE state = %s, want failed", state)
	}
}

// connectLoopbackPeers connects two peers that gather only loopback UDP candidates and returns the
// offerer's final ICE state.
func connectLoopbackPeers(t *testing.T, restrict bool) webrtc.ICEConnectionState {
	t.Helper()
	newPeer := func(restricted bool) *webrtc.PeerConnection {
		var settings webrtc.SettingEngine
		if restricted {
			RestrictWebRTC(&settings)
		}
		settings.SetIncludeLoopbackCandidate(true)
		settings.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
		settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
		settings.SetICETimeouts(time.Second, 2*time.Second, 200*time.Millisecond)
		peer, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(webrtc.Configuration{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		return peer
	}
	offerer, answerer := newPeer(restrict), newPeer(false)

	final := make(chan webrtc.ICEConnectionState, 1)
	offerer.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		if state == webrtc.ICEConnectionStateConnected || state == webrtc.ICEConnectionStateFailed {
			select {
			case final <- state:
			default:
			}
		}
	})
	if _, err := offerer.CreateDataChannel("data", nil); err != nil {
		t.Fatal(err)
	}
	exchange(t, offerer, answerer)

	select {
	case state := <-final:
		return state
	case <-time.After(15 * time.Second):
		t.Fatal("ICE neither connected nor failed")
		return 0
	}
}

// exchange completes offer and answer with every candidate gathered up front.
func exchange(t *testing.T, offerer, answerer *webrtc.PeerConnection) {
	t.Helper()
	offer, err := offerer.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(offerer)
	if err := offerer.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	<-gathered
	if err := answerer.SetRemoteDescription(*offerer.LocalDescription()); err != nil {
		t.Fatal(err)
	}
	answer, err := answerer.CreateAnswer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered = webrtc.GatheringCompletePromise(answerer)
	if err := answerer.SetLocalDescription(answer); err != nil {
		t.Fatal(err)
	}
	<-gathered
	if err := offerer.SetRemoteDescription(*answerer.LocalDescription()); err != nil {
		t.Fatal(err)
	}
}

func TestGuardedNetRefusesPrivateDestinations(t *testing.T) {
	n := guardedNet{&stdnet.Net{}}
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}

	conn, err := n.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.WriteTo([]byte{0}, loopback); !errors.Is(err, ErrNotPublic) {
		t.Errorf("UDPConn.WriteTo error = %v, want ErrNotPublic", err)
	}
	if _, err := conn.WriteToUDP([]byte{0}, loopback); !errors.Is(err, ErrNotPublic) {
		t.Errorf("UDPConn.WriteToUDP error = %v, want ErrNotPublic", err)
	}
	if _, _, err := conn.WriteMsgUDP([]byte{0}, nil, loopback); !errors.Is(err, ErrNotPublic) {
		t.Errorf("UDPConn.WriteMsgUDP error = %v, want ErrNotPublic", err)
	}

	packetConn, err := n.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	if _, err := packetConn.WriteTo([]byte{0}, loopback); !errors.Is(err, ErrNotPublic) {
		t.Errorf("PacketConn.WriteTo error = %v, want ErrNotPublic", err)
	}

	if _, err := n.DialUDP("udp4", nil, loopback); !errors.Is(err, ErrNotPublic) {
		t.Errorf("DialUDP error = %v, want ErrNotPublic", err)
	}
	if _, err := n.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}); !errors.Is(err, ErrNotPublic) {
		t.Errorf("DialTCP error = %v, want ErrNotPublic", err)
	}
	if _, err := n.Dial("tcp", "localhost:443"); !errors.Is(err, ErrNotPublic) {
		t.Errorf("Dial error = %v, want ErrNotPublic", err)
	}
}
