package protocol

import (
	"image/color"

	"github.com/go-gl/mathgl/mgl32"
)

type ArrowData struct {
	ArrowEndLocation Optional[mgl32.Vec3]
	ArrowHeadLength  Optional[float32]
	ArrowHeadRadius  Optional[float32]
	Segments         Optional[uint8]
}

func (*ArrowData) tagPrimitiveShapeExtraShapeData() uint32 { return 1 }

// Marshal reads or writes ArrowData using its canonical wire layout.
func (x *ArrowData) Marshal(io IO) {
	OptionalFunc(io, &x.ArrowEndLocation, io.Vec3)
	OptionalFunc(io, &x.ArrowHeadLength, io.Float32)
	OptionalFunc(io, &x.ArrowHeadRadius, io.Float32)
	OptionalFunc(io, &x.Segments, io.Uint8)
}

type ConeData struct {
	Radii       mgl32.Vec2
	Height      float32
	NumSegments uint8
}

func (*ConeData) tagPrimitiveShapeExtraShapeData() uint32 { return 9 }

// Marshal reads or writes ConeData using its canonical wire layout.
func (x *ConeData) Marshal(io IO) {
	io.Vec2(&x.Radii)
	io.Float32(&x.Height)
	io.Uint8(&x.NumSegments)
}

type CylinderData struct {
	RadiusX     mgl32.Vec2
	RadiusZ     mgl32.Vec2
	Height      float32
	NumSegments uint8
}

func (*CylinderData) tagPrimitiveShapeExtraShapeData() uint32 { return 6 }

// Marshal reads or writes CylinderData using its canonical wire layout.
func (x *CylinderData) Marshal(io IO) {
	io.Vec2(&x.RadiusX)
	io.Vec2(&x.RadiusZ)
	io.Float32(&x.Height)
	io.Uint8(&x.NumSegments)
}

type EllipsoidData struct {
	Radii           mgl32.Vec3
	SegmentsPerAxis uint8
}

func (*EllipsoidData) tagPrimitiveShapeExtraShapeData() uint32 { return 8 }

// Marshal reads or writes EllipsoidData using its canonical wire layout.
func (x *EllipsoidData) Marshal(io IO) {
	io.Vec3(&x.Radii)
	io.Uint8(&x.SegmentsPerAxis)
}

// PrimitiveShape defines a single shape to be rendered on the client. Each shape has a unique NetworkID and a
// set of optional parameters depending on its type.
type PrimitiveShape struct {
	// NetworkID is the network ID of the shape.
	NetworkID uint64
	// ShapeType is the optional dimension ID where the shape is rendered.
	ShapeType Optional[ScriptModuleMinecraftScriptPrimitiveShapeType]
	// Location is the location of the shape.
	Location Optional[mgl32.Vec3]
	// Scale is the scale of the shape.
	Scale Optional[float32]
	// Rotation is the rotation of the shape.
	Rotation Optional[mgl32.Vec3]
	// TotalTimeLeft is the total time left of the shape.
	TotalTimeLeft Optional[float32]
	// MaximumRenderDistance is the rotation of the shape.
	MaximumRenderDistance Optional[float32]
	// Color is the total time left of the shape.
	Colour Optional[color.RGBA]
	// DimensionID is the optional dimension ID where the shape is rendered.
	DimensionID Optional[DimensionType]
	// AttachedToEntityID is the optional unique ID of the entity the shape is attached to. Mojang's documentation
	// describes it as a runtime ID, but the field is an ActorUniqueID and the client resolves it as one.
	AttachedToEntityID Optional[int64]
	// ExtraShapeData holding data specific to the type of shape (such as text string for the text shape).
	ExtraShapeData PrimitiveShapeExtraShapeData
}

// Marshal reads or writes PrimitiveShape using its canonical wire layout.
func (x *PrimitiveShape) Marshal(io IO) {
	io.Varuint64(&x.NetworkID)
	OptionalMarshaler(io, &x.ShapeType)
	OptionalFunc(io, &x.Location, io.Vec3)
	OptionalFunc(io, &x.Scale, io.Float32)
	OptionalFunc(io, &x.Rotation, io.Vec3)
	OptionalFunc(io, &x.TotalTimeLeft, io.Float32)
	OptionalFunc(io, &x.MaximumRenderDistance, io.Float32)
	OptionalFunc(io, &x.Colour, io.RGBA)
	OptionalMarshaler(io, &x.DimensionID)
	OptionalFunc(io, &x.AttachedToEntityID, io.ActorUniqueID)
	MarshalPrimitiveShapeExtraShapeData(io, &x.ExtraShapeData)
}

type ScriptModuleMinecraftScriptPrimitiveShapeType uint8

const (
	PrimitiveShapeLine      ScriptModuleMinecraftScriptPrimitiveShapeType = 0
	PrimitiveShapeBox       ScriptModuleMinecraftScriptPrimitiveShapeType = 1
	PrimitiveShapeSphere    ScriptModuleMinecraftScriptPrimitiveShapeType = 2
	PrimitiveShapeCircle    ScriptModuleMinecraftScriptPrimitiveShapeType = 3
	PrimitiveShapeText      ScriptModuleMinecraftScriptPrimitiveShapeType = 4
	PrimitiveShapeArrow     ScriptModuleMinecraftScriptPrimitiveShapeType = 5
	PrimitiveShapeCylinder  ScriptModuleMinecraftScriptPrimitiveShapeType = 6
	PrimitiveShapePyramid   ScriptModuleMinecraftScriptPrimitiveShapeType = 7
	PrimitiveShapeEllipsoid ScriptModuleMinecraftScriptPrimitiveShapeType = 8
	PrimitiveShapeCone      ScriptModuleMinecraftScriptPrimitiveShapeType = 9
)

// Marshal reads or writes ScriptModuleMinecraftScriptPrimitiveShapeType through its uint8 wire encoding.
func (x *ScriptModuleMinecraftScriptPrimitiveShapeType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

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

// TextShape represents a text debug shape.
type TextShape struct {
	// Text is the text of the debug text shape.
	Text string
	// UseRotation is if the text should use the provided rotation, meaning it will be static and does not follow
	// the camera. Use false for default behaviour.
	UseRotation bool
	// BackgroundColor is the RGBA colour to use for the text background. This is a translucent black colour by
	// default.
	BackgroundColour Optional[color.RGBA]
	// DepthTest is whether the text should show through walls. Use true for default behaviour.
	DepthTest bool
	// ShowBackface is if the background should render on the back side of the shape. This only has a visible
	// effect when UseRotation is true since you cannot see the back side of the text otherwise. Use true for
	// default behaviour.
	ShowBackface bool
	// ShowTextBackface is if the text should render on the back side of the shape. This only has a visible effect
	// when UseRotation is true since you cannot see the back side of the text otherwise. Use true for default
	// behaviour.
	ShowTextBackface bool
}

func (*TextShape) tagPrimitiveShapeExtraShapeData() uint32 { return 2 }

// Marshal reads or writes TextShape using its canonical wire layout.
func (x *TextShape) Marshal(io IO) {
	io.String(&x.Text)
	io.Bool(&x.UseRotation)
	OptionalFunc(io, &x.BackgroundColour, io.RGBA)
	io.Bool(&x.DepthTest)
	io.Bool(&x.ShowBackface)
	io.Bool(&x.ShowTextBackface)
}
