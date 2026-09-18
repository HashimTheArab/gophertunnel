package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	GraphicsModeSimple    protocol.GraphicsMode = 0
	GraphicsModeFancy     protocol.GraphicsMode = 1
	GraphicsModeAdvanced  protocol.GraphicsMode = 2
	GraphicsModeRayTraced protocol.GraphicsMode = 3
)

// UpdateClientOptions is sent by the client when some of the client's options are updated, such as the
// graphics mode.
type UpdateClientOptions struct {
	// GraphicsModeChange is the graphics mode that the client is using. It is one of the constants above.
	GraphicsMode protocol.Optional[protocol.GraphicsMode]
	// FilterProfanityChange is if the client only uses filtered messages or not.
	FilterProfanity protocol.Optional[bool]
}

// ID returns the protocol ID for UpdateClientOptions.
func (*UpdateClientOptions) ID() uint32 { return IDUpdateClientOptions }

// Marshal reads or writes UpdateClientOptions using its canonical wire layout.
func (pk *UpdateClientOptions) Marshal(io protocol.IO) {
	protocol.OptionalMarshaler(io, &pk.GraphicsMode)
	protocol.OptionalFunc(io, &pk.FilterProfanity, io.Bool)
}
