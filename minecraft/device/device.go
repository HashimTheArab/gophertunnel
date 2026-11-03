// Package device describes the device a client claims at login. A server can compare the claimed
// DeviceOS with the platform of the Xbox title the player signed in as, so the two must agree.
package device

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// Profile is the device a client claims at login. Keep one per install: a device that changes on
// every join looks like a different player to a server.
type Profile struct {
	OS    protocol.DeviceOS `json:"os"`
	Model string            `json:"model"`
	ID    login.DeviceID    `json:"id"`
}

// Apply claims p's device and default input mode in data. Android also supplies the mobile
// platform type when zero; explicit nonzero platform types are preserved.
func (p Profile) Apply(data *login.ClientData) {
	data.DeviceOS = p.OS
	data.DeviceModel = p.Model
	data.DeviceID = p.ID
	data.DefaultInputMode = DefaultInputMode(p.OS)
	if p.OS == protocol.DeviceAndroid && data.PlatformType == login.PlatformTypeDesktop {
		data.PlatformType = login.PlatformTypeMobile
		data.MarkClaims("PlatformType")
	}
	data.MarkClaims("DefaultInputMode", "DeviceId", "DeviceModel", "DeviceOS")
}

// DefaultInputMode returns the input mode a client on os starts in.
func DefaultInputMode(os protocol.DeviceOS) int {
	switch os {
	case protocol.DeviceOSX, protocol.DeviceWin10, protocol.DeviceWin32, protocol.DeviceTVOS, protocol.DeviceLinux: //nolint:staticcheck // Logins may still report tvOS.
		return packet.InputModeMouse
	case protocol.DeviceOrbis, protocol.DeviceNX, protocol.DeviceXBOX:
		return packet.InputModeGamePad
	default:
		return packet.InputModeTouch
	}
}
