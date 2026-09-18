// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package protocol

// PersonaPiece represents a piece of a persona skin. All pieces are sent separately.
type PersonaPieceType uint32

const (
	PieceTypeSkeleton      PersonaPieceType = 1
	PieceTypeBody          PersonaPieceType = 2
	PieceTypeSkin          PersonaPieceType = 3
	PieceTypeBottom        PersonaPieceType = 4
	PieceTypeFeet          PersonaPieceType = 5
	PieceTypeDress         PersonaPieceType = 6
	PieceTypeTop           PersonaPieceType = 7
	PieceTypeHighPants     PersonaPieceType = 8
	PieceTypeHands         PersonaPieceType = 9
	PieceTypeOuterwear     PersonaPieceType = 10
	PieceTypeFacialHair    PersonaPieceType = 11
	PieceTypeMouth         PersonaPieceType = 12
	PieceTypeEyes          PersonaPieceType = 13
	PieceTypeHair          PersonaPieceType = 14
	PieceTypeHood          PersonaPieceType = 15
	PieceTypeBack          PersonaPieceType = 16
	PieceTypeFaceAccessory PersonaPieceType = 17
	PieceTypeHead          PersonaPieceType = 18
	PieceTypeLegs          PersonaPieceType = 19
	PieceTypeLeftLeg       PersonaPieceType = 20
	PieceTypeRightLeg      PersonaPieceType = 21
	PieceTypeArms          PersonaPieceType = 22
	PieceTypeLeftArm       PersonaPieceType = 23
	PieceTypeRightArm      PersonaPieceType = 24
	PieceTypeCapes         PersonaPieceType = 25
	PieceTypeClassicSkin   PersonaPieceType = 26
	PieceTypeEmote         PersonaPieceType = 27
)

// Marshal reads or writes PersonaPieceType through its uint32 wire encoding.
func (x *PersonaPieceType) Marshal(io IO) { io.Uint32((*uint32)(x)) }

type SkinImage struct {
	Width      uint32
	Height     uint32
	ImageBytes []uint8
}

// Marshal reads or writes SkinImage using its canonical wire layout.
func (x *SkinImage) Marshal(io IO) {
	io.Uint32(&x.Width)
	Maximum(io, &x.Width, 4096)
	io.Uint32(&x.Height)
	Maximum(io, &x.Height, 4096)
	FuncSliceLimits(io, &x.ImageBytes, io.Varuint32, 0, 67108864, io.Uint8)
}
