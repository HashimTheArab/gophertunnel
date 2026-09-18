package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

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
	// BossEntityUniqueID is the unique ID of the boss entity that the boss event sent involves. By default, the
	// health percentage and title of the boss bar depend on the health and name tag of this entity. If
	// BossEntityUniqueID is the same as the client's entity unique ID, its HealthPercentage and BossBarTitle can
	// be freely altered.
	TargetEntityUniqueID int64
	PlayerEntityUniqueID int64
	// EventType is the type of the event. It is one of the BossEvent constants above.
	EventType    protocol.BossEventUpdateType
	Name         string
	FilteredName string
	// HealthPercentage is the percentage of health that is shown in the boss bar (0.0-1.0). The HealthPercentage
	// may be set to a specific value if the BossEntityUniqueID matches the client's entity unique ID.
	HealthPercent float32
	// Colour is the colour of the boss bar that is shown when a player is subscribed. It is one of the
	// BossEventColour constants listed above.
	Colour protocol.BossBarColor
	// Overlay is the overlay of the boss bar that is shown on top of the boss bar when a player is subscribed. It
	// is one of the BossEventOverlay constants listed above.
	Overlay protocol.BossBarOverlay
}

// ID ...
func (*BossEvent) ID() uint32 {
	return IDBossEvent
}

func (pk *BossEvent) Marshal(io protocol.IO) {
	io.ActorUniqueID(&pk.TargetEntityUniqueID)
	io.ActorUniqueID(&pk.PlayerEntityUniqueID)
	pk.EventType.Marshal(io)
	io.StringLimits(&pk.Name, 0, 256)
	io.StringLimits(&pk.FilteredName, 0, 256)
	io.Float32(&pk.HealthPercent)
	pk.Colour.Marshal(io)
	pk.Overlay.Marshal(io)
}
