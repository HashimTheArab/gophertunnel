package netguard

import (
	"net"
	"testing"
	"time"

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
			Policy{}.RestrictWebRTC(&settings)
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
