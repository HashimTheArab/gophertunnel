package protocol

type HeightMapDataType uint8

const (
	HeightMapDataNone    HeightMapDataType = 0
	HeightMapDataHasData HeightMapDataType = 1
	HeightMapDataTooHigh HeightMapDataType = 2
	HeightMapDataTooLow  HeightMapDataType = 3
)

// Marshal reads or writes HeightMapDataType through its uint8 wire encoding.
func (x *HeightMapDataType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type SubChunkData struct {
	SubChunkPosOffset     SubChunkPosOffset
	SubChunkRequestResult SubChunkRequestResult
	SerializedSubChunk    Optional[[]byte]
	HeightMapData         HeightmapData
	BlobID                Optional[uint64]
}

// Marshal reads or writes SubChunkData using its canonical wire layout.
func (x *SubChunkData) Marshal(io IO) {
	x.SubChunkPosOffset.Marshal(io)
	x.SubChunkRequestResult.Marshal(io)
	OptionalFunc(io, &x.SerializedSubChunk, io.ByteSlice)
	x.HeightMapData.Marshal(io)
	OptionalFunc(io, &x.BlobID, io.Uint64)
}

type SubChunkMetadata struct {
	BlobID uint64
}

// Marshal reads or writes SubChunkMetadata using its canonical wire layout.
func (x *SubChunkMetadata) Marshal(io IO) {
	io.Uint64(&x.BlobID)
}

type SubChunkPosOffset struct {
	SubchunkOffsetX int8
	SubchunkOffsetY int8
	SubchunkOffsetZ int8
}

// Marshal reads or writes SubChunkPosOffset using its canonical wire layout.
func (x *SubChunkPosOffset) Marshal(io IO) {
	io.Int8(&x.SubchunkOffsetX)
	io.Int8(&x.SubchunkOffsetY)
	io.Int8(&x.SubchunkOffsetZ)
}

type SubChunkRequestResult uint8

const (
	SubChunkResultSuccess          SubChunkRequestResult = 1
	SubChunkResultChunkNotFound    SubChunkRequestResult = 2
	SubChunkResultInvalidDimension SubChunkRequestResult = 3
	SubChunkResultPlayerNotFound   SubChunkRequestResult = 4
	SubChunkResultIndexOutOfBounds SubChunkRequestResult = 5
	SubChunkResultSuccessAllAir    SubChunkRequestResult = 6
)

// Marshal reads or writes SubChunkRequestResult through its uint8 wire encoding.
func (x *SubChunkRequestResult) Marshal(io IO) { io.Uint8((*uint8)(x)) }
