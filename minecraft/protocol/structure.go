package protocol

import (
	"github.com/go-gl/mathgl/mgl32"
)

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
	// PaletteName is the name of the palette used in the structure. Currently, it seems that this field is always
	// 'default'.
	PaletteName string
	// IgnoreEntities specifies if the structure should ignore entities or include them. If set to false, entities
	// will also show up in the exported structure.
	IgnoreEntities bool
	// IgnoreBlocks specifies if the structure should ignore blocks or include them. If set to false, blocks will
	// show up in the exported structure.
	IgnoreBlocks bool
	// AllowNonTickingChunks specifies if the structure should allow non-ticking chunks. If set to false, the
	// structure will export non-ticking chunks.
	AllowNonTickingChunks bool
	// Size is the size of the area that is about to be exported. The area exported will start at the Position +
	// Offset, and will extend as far as Size specifies.
	Size BlockPos
	// Offset is the offset position that was set in the structure block. The area exported is offset by this
	// position.
	Offset         BlockPos
	LastEditPlayer int64
	// Rotation is the rotation that the structure block should obtain. See the constants above for available
	// options.
	Rotation Rotation
	// Mirror specifies the way the structure should be mirrored. It is either no mirror at all, mirror on the x/z
	// axis or both.
	Mirror Mirror
	// AnimationMode ...
	AnimationMode AnimationMode
	// AnimationDuration ...
	AnimationDuration float32
	// Integrity is usually 1, but may be set to a number between 0 and 1 to omit blocks randomly, using the Seed
	// that follows.
	Integrity float32
	// Seed is the seed used to omit blocks if Integrity is not equal to one. If the Seed is 0, a random seed is
	// selected to omit blocks.
	Seed uint32
	// Pivot is the pivot around which the structure may be rotated.
	Pivot mgl32.Vec3
}

// Marshal reads or writes StructureSettings using its canonical wire layout.
func (x *StructureSettings) Marshal(io IO) {
	io.StringLimits(&x.PaletteName, 0, 256)
	io.Bool(&x.IgnoreEntities)
	io.Bool(&x.IgnoreBlocks)
	io.Bool(&x.AllowNonTickingChunks)
	x.Size.Marshal(io)
	x.Offset.Marshal(io)
	io.ActorUniqueID(&x.LastEditPlayer)
	x.Rotation.Marshal(io)
	x.Mirror.Marshal(io)
	x.AnimationMode.Marshal(io)
	io.Float32(&x.AnimationDuration)
	io.Float32(&x.Integrity)
	io.Uint32(&x.Seed)
	io.Vec3(&x.Pivot)
}
