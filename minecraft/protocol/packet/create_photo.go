package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// CreatePhoto is a packet that allows players to export photos from their portfolios into items in
// their inventory. This packet only works on the Education Edition version of Minecraft.
type CreatePhoto struct {
	RawID uint64
	// PhotoName is the name of the photo.
	PhotoName     string
	PhotoItemName string
}

// Marshal reads or writes CreatePhoto using its canonical wire layout.
func (x *CreatePhoto) Marshal(io protocol.IO) {
	io.Uint64(&x.RawID)
	io.String(&x.PhotoName)
	io.String(&x.PhotoItemName)
}

// ID returns the protocol ID for CreatePhoto.
func (*CreatePhoto) ID() uint32 { return IDCreatePhoto }
