package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	BossEventColourPink          protocol.BossBarColor = 0
	BossEventColourBlue          protocol.BossBarColor = 1
	BossEventColourRed           protocol.BossBarColor = 2
	BossEventColourGreen         protocol.BossBarColor = 3
	BossEventColourYellow        protocol.BossBarColor = 4
	BossEventColourPurple        protocol.BossBarColor = 5
	BossEventColourRebeccaPurple protocol.BossBarColor = 6
	BossEventColourWhite         protocol.BossBarColor = 7
)

const (
	BossEventOverlayProgress  protocol.BossBarOverlay = 0
	BossEventOverlayNotched6  protocol.BossBarOverlay = 1
	BossEventOverlayNotched10 protocol.BossBarOverlay = 2
	BossEventOverlayNotched12 protocol.BossBarOverlay = 3
	BossEventOverlayNotched20 protocol.BossBarOverlay = 4
)

const (
	BossEventShow                 protocol.BossEventUpdateType = 0
	BossEventRegisterPlayer       protocol.BossEventUpdateType = 1
	BossEventHide                 protocol.BossEventUpdateType = 2
	BossEventUnregisterPlayer     protocol.BossEventUpdateType = 3
	BossEventHealthPercentage     protocol.BossEventUpdateType = 4
	BossEventTitle                protocol.BossEventUpdateType = 5
	BossEventAppearanceProperties protocol.BossEventUpdateType = 6
	BossEventTexture              protocol.BossEventUpdateType = 7
	BossEventRequest              protocol.BossEventUpdateType = 8
)

// BossEvent is sent by the server to make a specific 'boss event' occur in the world. It includes features
// such as showing a boss bar to the player and turning the sky dark.
type BossEvent struct {
	TargetActorID int64
	PlayerID      int64
	// EventType is the type of the event. It is one of the BossEvent constants above.
	EventType     protocol.BossEventUpdateType
	Name          string
	FilteredName  string
	HealthPercent float32
	Colour        protocol.BossBarColor
	// Overlay is the overlay of the boss bar that is shown on top of the boss bar when a player is subscribed. It
	// is one of the BossEventOverlay constants listed above.
	Overlay protocol.BossBarOverlay
}

// Marshal reads or writes BossEvent using its canonical wire layout.
func (x *BossEvent) Marshal(io protocol.IO) {
	io.ActorUniqueID(&x.TargetActorID)
	io.ActorUniqueID(&x.PlayerID)
	x.EventType.Marshal(io)
	io.StringLimits(&x.Name, 0, 256)
	io.StringLimits(&x.FilteredName, 0, 256)
	io.Float32(&x.HealthPercent)
	x.Colour.Marshal(io)
	x.Overlay.Marshal(io)
}

// ID returns the protocol ID for BossEvent.
func (*BossEvent) ID() uint32 { return IDBossEvent }
