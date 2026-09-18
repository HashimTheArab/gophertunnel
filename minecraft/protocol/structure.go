package protocol

import "github.com/go-gl/mathgl/mgl32"

type AnimationMode uint8

const (
	AnimationModeNone   AnimationMode = 0
	AnimationModeLayers AnimationMode = 1
	AnimationModeBlocks AnimationMode = 2
)

// Marshal reads or writes AnimationMode through its uint8 wire encoding.
func (x *AnimationMode) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type Rotation uint8

const (
	StructureRotationNone      Rotation = 0
	StructureRotationRotate90  Rotation = 1
	StructureRotationRotate180 Rotation = 2
	StructureRotationRotate270 Rotation = 3
)

// Marshal reads or writes Rotation through its uint8 wire encoding.
func (x *Rotation) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type StructureBlockType int32

// Marshal reads or writes StructureBlockType through its int32 wire encoding.
func (x *StructureBlockType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type StructureEditorData struct {
	StructureName         BedrockSafetyRedactableString
	DataField             string
	ShouldIncludePlayers  bool
	ShouldShowBoundingBox bool
	StructureBlockType    StructureBlockType
	StructureSettings     StructureSettings
	RedstoneSaveMode      StructureRedstoneSaveMode
}

// Marshal reads or writes StructureEditorData using its canonical wire layout.
func (x *StructureEditorData) Marshal(io IO) {
	x.StructureName.Marshal(io)
	io.String(&x.DataField)
	io.Bool(&x.ShouldIncludePlayers)
	io.Bool(&x.ShouldShowBoundingBox)
	x.StructureBlockType.Marshal(io)
	x.StructureSettings.Marshal(io)
	x.RedstoneSaveMode.Marshal(io)
}

type StructureRedstoneSaveMode uint8

// Marshal reads or writes StructureRedstoneSaveMode through its uint8 wire encoding.
func (x *StructureRedstoneSaveMode) Marshal(io IO) { io.Uint8((*uint8)(x)) }

// StructureSettings is a struct holding settings of a structure block. Its fields may be changed using the
// in-game UI on the client-side.
type StructureSettings struct {
	StructurePaletteName                            string
	ShouldIgnoreEntities                            bool
	ShouldIgnoreBlocks                              bool
	ShouldAllowNonTickingPlayerAndTickingAreaChunks bool
	StructureSize                                   BlockPos
	StructureOffset                                 BlockPos
	LastEditPlayer                                  int64
	// Rotation is the rotation that the structure block should obtain. See the constants above for available
	// options.
	Rotation Rotation
	// Mirror specifies the way the structure should be mirrored. It is either no mirror at all, mirror on the x/z
	// axis or both.
	Mirror Mirror
	// AnimationMode ...
	AnimationMode    AnimationMode
	AnimationSeconds float32
	IntegrityValue   float32
	IntegritySeed    uint32
	RotationPivot    mgl32.Vec3
}

// Marshal reads or writes StructureSettings using its canonical wire layout.
func (x *StructureSettings) Marshal(io IO) {
	io.StringLimits(&x.StructurePaletteName, 0, 256)
	io.Bool(&x.ShouldIgnoreEntities)
	io.Bool(&x.ShouldIgnoreBlocks)
	io.Bool(&x.ShouldAllowNonTickingPlayerAndTickingAreaChunks)
	x.StructureSize.Marshal(io)
	x.StructureOffset.Marshal(io)
	io.ActorUniqueID(&x.LastEditPlayer)
	x.Rotation.Marshal(io)
	x.Mirror.Marshal(io)
	x.AnimationMode.Marshal(io)
	io.Float32(&x.AnimationSeconds)
	io.Float32(&x.IntegrityValue)
	io.Uint32(&x.IntegritySeed)
	io.Vec3(&x.RotationPivot)
}
