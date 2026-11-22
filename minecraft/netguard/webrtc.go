package netguard

import (
	"net"
	"net/netip"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

// RestrictWebRTC makes connections built from settings ignore remote ICE candidates that Check
// refuses, including peer-reflexive ones, so no check or relayed packet is sent to them. mDNS is
// turned off, so .local candidates are never resolved. STUN and TURN servers stay the caller's choice.
func RestrictWebRTC(settings *webrtc.SettingEngine) {
	settings.SetRemoteIPFilter(func(ip net.IP) bool {
		addr, _ := netip.AddrFromSlice(ip)
		return Check(addr) == nil
	})
	settings.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
}
