package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	HudElementPaperDoll     protocol.HudElement = 0
	HudElementArmour        protocol.HudElement = 1
	HudElementToolTips      protocol.HudElement = 2
	HudElementTouchControls protocol.HudElement = 3
	HudElementCrosshair     protocol.HudElement = 4
	HudElementHotBar        protocol.HudElement = 5
	HudElementHealth        protocol.HudElement = 6
	HudElementProgressBar   protocol.HudElement = 7
	HudElementHunger        protocol.HudElement = 8
	HudElementAirBubbles    protocol.HudElement = 9
	HudElementHorseHealth   protocol.HudElement = 10
	HudElementStatusEffects protocol.HudElement = 11
	HudElementItemText      protocol.HudElement = 12
)

const (
	HudVisibilityHide  protocol.HudVisibility = 0
	HudVisibilityReset protocol.HudVisibility = 1
)

// SetHud is sent by the server to set the visibility of individual HUD elements on the client.
type SetHud struct {
	HudElement []protocol.HudElement
	HudVisible protocol.HudVisibility
}

// Marshal reads or writes SetHud using its canonical wire layout.
func (x *SetHud) Marshal(io protocol.IO) {
	protocol.Slice(io, &x.HudElement)
	x.HudVisible.Marshal(io)
}

// ID returns the protocol ID for SetHud.
func (*SetHud) ID() uint32 { return IDSetHud }
