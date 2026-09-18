package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// OnScreenTextureAnimation is sent by the server to show a certain animation on the screen of the player. The
// packet is used, as an example, for when a raid is triggered and when a raid is defeated.
type OnScreenTextureAnimation struct {
	// EffectID is the type of the animation to show. The packet provides no further extra data to allow modifying
	// the duration or other properties of the animation.
	AnimationType uint32
}

// Marshal reads or writes OnScreenTextureAnimation using its canonical wire layout.
func (x *OnScreenTextureAnimation) Marshal(io protocol.IO) {
	io.Uint32(&x.AnimationType)
}

// ID returns the protocol ID for OnScreenTextureAnimation.
func (*OnScreenTextureAnimation) ID() uint32 { return IDOnScreenTextureAnimation }
