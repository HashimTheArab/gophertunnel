package protocol

import (
	"github.com/google/uuid"
)

type PersonaAnimatedTextureType uint32

const (
	SkinAnimationNone        PersonaAnimatedTextureType = 0
	SkinAnimationHead        PersonaAnimatedTextureType = 1
	SkinAnimationBody32x32   PersonaAnimatedTextureType = 2
	SkinAnimationBody128x128 PersonaAnimatedTextureType = 3
)

// Marshal reads or writes PersonaAnimatedTextureType through its uint32 wire encoding.
func (x *PersonaAnimatedTextureType) Marshal(io IO) { io.Varuint32((*uint32)(x)) }

type PersonaAnimationExpression uint32

const (
	ExpressionTypeLinear   PersonaAnimationExpression = 0
	ExpressionTypeBlinking PersonaAnimationExpression = 1
)

// Marshal reads or writes PersonaAnimationExpression through its uint32 wire encoding.
func (x *PersonaAnimationExpression) Marshal(io IO) { io.Varuint32((*uint32)(x)) }

type PersonaArmSizeType uint8

const (
	ArmSizeSlim PersonaArmSizeType = 0
	ArmSizeWide PersonaArmSizeType = 1
)

// Marshal reads or writes PersonaArmSizeType through its uint8 wire encoding.
func (x *PersonaArmSizeType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

// PersonaPiece represents a piece of a persona skin. All pieces are sent separately.
type PersonaPiece struct {
	// PieceId is a UUID that identifies the piece itself, which is unique for each separate piece.
	PieceID string
	// PieceType holds the type of the piece. This is one of the PieceType constants above.
	PieceType PersonaPieceType
	// PackID is a UUID that identifies the pack that the persona piece belongs to.
	PackID uuid.UUID
	// Default specifies if the piece is one of the default pieces. This is true when the piece is one of those
	// that a Steve or Alex skin have.
	Default bool
	// ProductID is a UUID that identifies the piece when it comes to purchases. It is empty for pieces that have
	// the 'Default' field set to true.
	ProductID string
}

// Marshal reads or writes PersonaPiece using its canonical wire layout.
func (x *PersonaPiece) Marshal(io IO) {
	io.String(&x.PieceID)
	x.PieceType.Marshal(io)
	io.UUID(&x.PackID)
	io.Bool(&x.Default)
	io.String(&x.ProductID)
}

// PersonaPiece represents a piece of a persona skin. All pieces are sent separately.
type PersonaPieceType uint32

const (
	PieceTypeUnknown       PersonaPieceType = 0
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
	PieceTypeUnsupported   PersonaPieceType = 28
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
