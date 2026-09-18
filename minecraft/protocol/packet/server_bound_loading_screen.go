package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	LoadingScreenTypeStart protocol.ServerboundLoadingScreenType = 1
	LoadingScreenTypeEnd   protocol.ServerboundLoadingScreenType = 2
)

type ServerboundLoadingScreen struct {
	LoadingScreenPacketType protocol.ServerboundLoadingScreenType
	LoadingScreenID         protocol.Optional[uint32]
}

// Marshal reads or writes ServerboundLoadingScreen using its canonical wire layout.
func (x *ServerboundLoadingScreen) Marshal(io protocol.IO) {
	x.LoadingScreenPacketType.Marshal(io)
	protocol.OptionalFunc(io, &x.LoadingScreenID, io.Uint32)
}

// ID returns the protocol ID for ServerboundLoadingScreen.
func (*ServerboundLoadingScreen) ID() uint32 { return IDServerboundLoadingScreen }
