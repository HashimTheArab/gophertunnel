package protocol

// VoxelShapesSerializableCells represents a 3D grid of voxel cell data.
type VoxelCells struct {
	// XSize is the size of the grid along the X axis.
	XSize uint8
	// YSize is the size of the grid along the Y axis.
	YSize uint8
	// ZSize is the size of the grid along the Z axis.
	ZSize uint8
	// Storage is the raw cell data stored in the grid.
	Storage []uint8
}

// Marshal reads or writes VoxelCells using its canonical wire layout.
func (x *VoxelCells) Marshal(io IO) {
	io.Uint8(&x.XSize)
	Maximum(io, &x.XSize, 127)
	io.Uint8(&x.YSize)
	Maximum(io, &x.YSize, 127)
	io.Uint8(&x.ZSize)
	Maximum(io, &x.ZSize, 127)
	FuncSliceLimits(io, &x.Storage, io.Varuint32, 0, 256048, io.Uint8)
}

// VoxelShapesSerializableVoxelShape represents a voxel shape with cells and coordinate axes.
type VoxelShape struct {
	// Cells is the grid of cells representing solid and empty regions.
	Cells VoxelCells
	// XCoordinates is a list of X axis coordinates for the shape.
	XCoordinates []float32
	// YCoordinates is a list of Y axis coordinates for the shape.
	YCoordinates []float32
	// ZCoordinates is a list of Z axis coordinates for the shape.
	ZCoordinates []float32
}

// Marshal reads or writes VoxelShape using its canonical wire layout.
func (x *VoxelShape) Marshal(io IO) {
	x.Cells.Marshal(io)
	FuncSliceLimits(io, &x.XCoordinates, io.Varuint32, 1, 128, io.Float32)
	FuncSliceLimits(io, &x.YCoordinates, io.Varuint32, 1, 128, io.Float32)
	FuncSliceLimits(io, &x.ZCoordinates, io.Varuint32, 1, 128, io.Float32)
}

type VoxelShapesRegistryHandle struct {
	Value uint16
}

// Marshal reads or writes VoxelShapesRegistryHandle using its canonical wire layout.
func (x *VoxelShapesRegistryHandle) Marshal(io IO) {
	io.Uint16(&x.Value)
}
