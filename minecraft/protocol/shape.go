package protocol

import (
	"image/color"

	"github.com/go-gl/mathgl/mgl32"
)

// ArrowShape represents an arrow debug shape.
type ArrowShape struct {
	// ArrowEndLocation is the arrow end location of the shape.
	ArrowEndLocation Optional[mgl32.Vec3]
	// ArrowHeadLength is the arrow head length of the shape.
	ArrowHeadLength Optional[float32]
	// ArrowHeadRadius is the arrow head radius of the shape.
	ArrowHeadRadius Optional[float32]
	// Segments is the segments that used for the debug arrow's head.
	Segments Optional[uint8]
}

func (*ArrowShape) tagShape() uint32 { return 1 }

// Marshal reads or writes ArrowShape using its canonical wire layout.
func (x *ArrowShape) Marshal(io IO) {
	OptionalFunc(io, &x.ArrowEndLocation, io.Vec3)
	OptionalFunc(io, &x.ArrowHeadLength, io.Float32)
	OptionalFunc(io, &x.ArrowHeadRadius, io.Float32)
	OptionalFunc(io, &x.Segments, io.Uint8)
}

// ConeShape represents a cone debug shape.
type ConeShape struct {
	// Radii are the radii along the X/Z axes of the cone base.
	Radii mgl32.Vec2
	// Height is the height of the cone.
	Height float32
	// NumSegments is the number of segments used for the cone.
	NumSegments uint8
}

func (*ConeShape) tagShape() uint32 { return 9 }

// Marshal reads or writes ConeShape using its canonical wire layout.
func (x *ConeShape) Marshal(io IO) {
	io.Vec2(&x.Radii)
	io.Float32(&x.Height)
	io.Uint8(&x.NumSegments)
}

// CylinderShape represents a cylinder debug shape.
type CylinderShape struct {
	// RadiusX is the radius of the cylinder along the X axis.
	RadiusX mgl32.Vec2
	// RadiusZ is the radius of the cylinder along the Z axis.
	RadiusZ mgl32.Vec2
	// Height is the height of the cylinder.
	Height float32
	// NumSegments is the number of segments used for the cylinder.
	NumSegments uint8
}

func (*CylinderShape) tagShape() uint32 { return 6 }

// Marshal reads or writes CylinderShape using its canonical wire layout.
func (x *CylinderShape) Marshal(io IO) {
	io.Vec2(&x.RadiusX)
	io.Vec2(&x.RadiusZ)
	io.Float32(&x.Height)
	io.Uint8(&x.NumSegments)
}

// EllipsoidShape represents an ellipsoid debug shape.
type EllipsoidShape struct {
	// Radii are the radii of the ellipsoid along the X, Y and Z axes.
	Radii mgl32.Vec3
	// SegmentsPerAxis is the number of segments used per axis for the ellipsoid.
	SegmentsPerAxis uint8
}

func (*EllipsoidShape) tagShape() uint32 { return 8 }

// Marshal reads or writes EllipsoidShape using its canonical wire layout.
func (x *EllipsoidShape) Marshal(io IO) {
	io.Vec3(&x.Radii)
	io.Uint8(&x.SegmentsPerAxis)
}

// PrimitiveShape defines a single shape to be rendered on the client. Each shape has a unique NetworkID and a
// set of optional parameters depending on its type.
type PrimitiveShape struct {
	// NetworkID is the network ID of the shape.
	NetworkID uint64
	// ShapeType is the optional dimension ID where the shape is rendered.
	Type Optional[ScriptModuleMinecraftScriptPrimitiveShapeType]
	// Location is the location of the shape.
	Location Optional[mgl32.Vec3]
	// Scale is the scale of the shape.
	Scale Optional[float32]
	// Rotation is the rotation of the shape.
	Rotation Optional[mgl32.Vec3]
	// TotalTimeLeft is the total time left of the shape.
	TotalTimeLeft Optional[float32]
	// MaximumRenderDistance is the rotation of the shape.
	MaxRenderDistance Optional[float32]
	// Color is the total time left of the shape.
	Colour Optional[color.RGBA]
	// DimensionID is the optional dimension ID where the shape is rendered.
	DimensionID Optional[DimensionType]
	// AttachedToEntityID is the optional unique ID of the entity the shape is attached to. Mojang's documentation
	// describes it as a runtime ID, but the field is an ActorUniqueID and the client resolves it as one.
	AttachedToEntityID Optional[int64]
	// ExtraShapeData holding data specific to the type of shape (such as text string for the text shape).
	ExtraShapeData Shape
}

// Marshal reads or writes PrimitiveShape using its canonical wire layout.
func (x *PrimitiveShape) Marshal(io IO) {
	io.Varuint64(&x.NetworkID)
	OptionalMarshaler(io, &x.Type)
	OptionalFunc(io, &x.Location, io.Vec3)
	OptionalFunc(io, &x.Scale, io.Float32)
	OptionalFunc(io, &x.Rotation, io.Vec3)
	OptionalFunc(io, &x.TotalTimeLeft, io.Float32)
	OptionalFunc(io, &x.MaxRenderDistance, io.Float32)
	OptionalFunc(io, &x.Colour, io.RGBA)
	OptionalMarshaler(io, &x.DimensionID)
	OptionalFunc(io, &x.AttachedToEntityID, io.ActorUniqueID)
	MarshalShape(io, &x.ExtraShapeData)
}

// PyramidShape represents a pyramid debug shape.
type PyramidShape struct {
	// Width is the width along the X axis of the pyramid base.
	Width uint32
	// Height is the height of the pyramid.
	Height     uint32
	ImageBytes []uint8
}

// Marshal reads or writes PyramidShape using its canonical wire layout.
func (x *PyramidShape) Marshal(io IO) {
	io.Uint32(&x.Width)
	Maximum(io, &x.Width, 4096)
	io.Uint32(&x.Height)
	Maximum(io, &x.Height, 4096)
	FuncSliceLimits(io, &x.ImageBytes, io.Varuint32, 0, 67108864, io.Uint8)
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
	ShowBackfaceText bool
}

func (*TextShape) tagShape() uint32 { return 2 }

// Marshal reads or writes TextShape using its canonical wire layout.
func (x *TextShape) Marshal(io IO) {
	io.String(&x.Text)
	io.Bool(&x.UseRotation)
	OptionalFunc(io, &x.BackgroundColour, io.RGBA)
	io.Bool(&x.DepthTest)
	io.Bool(&x.ShowBackface)
	io.Bool(&x.ShowBackfaceText)
}
