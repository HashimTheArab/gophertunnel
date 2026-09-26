package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// UpdateTrade is sent by the server to update the trades offered by a villager to a player. It is sent at the
// moment that a player interacts with a villager.
type UpdateTrade struct {
	ContainerID uint8
	// WindowType is an identifier specifying the type of the window opened. In vanilla, it appears this is always
	// filled out with 15.
	WindowType uint8
	// Size is the amount of trading options that the villager has.
	Size       int32
	TraderTier int32
	// EntityUniqueID is the unique ID of the entity (usually a player) for which the trades are updated. The
	// updated trades may apply only to this entity.
	VillagerUniqueID int64
	// EntityUniqueID is the unique ID of the entity (usually a player) for which the trades are updated. The
	// updated trades may apply only to this entity.
	EntityUniqueID int64
	// DisplayName is the name displayed at the top of the trading UI. It is usually used to represent the
	// profession of the villager in the UI.
	DisplayName       string
	UseNewTradeScreen bool
	UsingEconomyTrade bool
	Data              []byte
}

// ID ...
func (*UpdateTrade) ID() uint32 {
	return IDUpdateTrade
}

func (pk *UpdateTrade) Marshal(io protocol.IO) {
	io.Uint8(&pk.ContainerID)
	io.Uint8(&pk.WindowType)
	io.Varint32(&pk.Size)
	io.Varint32(&pk.TraderTier)
	io.ActorUniqueID(&pk.VillagerUniqueID)
	io.ActorUniqueID(&pk.EntityUniqueID)
	io.String(&pk.DisplayName)
	io.Bool(&pk.UseNewTradeScreen)
	io.Bool(&pk.UsingEconomyTrade)
	io.NBT(&pk.Data, protocol.NBTNetwork)
}
