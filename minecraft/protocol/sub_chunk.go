package protocol

const (
	HeightMapDataNone = iota
	HeightMapDataHasData
	HeightMapDataTooHigh
	HeightMapDataTooLow
	HeightMapDataAllCopied
)

const (
	SubChunkResultUndefined = iota
	SubChunkResultSuccess
	SubChunkResultChunkNotFound
	SubChunkResultInvalidDimension
	SubChunkResultPlayerNotFound
	SubChunkResultIndexOutOfBounds
	SubChunkResultSuccessAllAir
)

// SubChunkEntry contains the data of a sub-chunk entry relative to a center sub chunk position, used for the sub-chunk
// requesting system introduced in v1.18.10.
type SubChunkEntry struct {
	// Offset contains the offset between the sub-chunk position and the center position.
	Offset SubChunkOffset
	// Result is always one of the constants defined in the SubChunkResult constants.
	Result byte
	// RawPayload contains the serialized sub-chunk data, if present.
	RawPayload Optional[[]byte]
	// HeightMapType is always one of the constants defined in the HeightMapData constants.
	HeightMapType byte
	// HeightMapData is the data for the height map, if present.
	HeightMapData Optional[HeightMap]
	// RenderHeightMapType is always one of the constants defined in the HeightMapData constants.
	RenderHeightMapType byte
	// RenderHeightMapData is the data for the render height map, if present.
	RenderHeightMapData Optional[HeightMap]
	// BlobHash is the hash of the blob, if present.
	BlobHash Optional[uint64]
}

// SkyStart returns a conservative first block Y above the column's render
// surface. clamped reports a surface below this band: y is then only the band's
// bottom, and a lower boundary observed in another band is more precise. Heights
// above the band, missing maps and copied maps cannot establish an upper bound
// independently, and report ok false. subChunkY is absolute, and x/z are
// coordinates within the column. Callers read every column of an entry, so it
// takes a pointer and reads the height map in place rather than copying either.
func (x *SubChunkEntry) SkyStart(subChunkY int32, blockX, blockZ uint8) (y int32, clamped, ok bool) {
	if blockX >= 16 || blockZ >= 16 || (x.Result != SubChunkResultSuccess && x.Result != SubChunkResultSuccessAllAir) {
		return 0, false, false
	}
	base := subChunkY * 16
	switch x.RenderHeightMapType {
	case HeightMapDataTooLow:
		return base, true, true
	case HeightMapDataHasData:
		if x.RenderHeightMapData.set {
			// -1 marks a column whose surface lies below this band, like
			// HeightMapDataTooLow for the whole map.
			switch h := x.RenderHeightMapData.val[blockZ][blockX]; {
			case h == -1:
				return base, true, true
			case h >= 0 && h < 16:
				return base + int32(h) + 1, false, true
			}
		}
	}
	return 0, false, false
}

// Marshal encodes/decodes a SubChunkEntry.
func (x *SubChunkEntry) Marshal(r IO) {
	Single(r, &x.Offset)
	r.Uint8(&x.Result)
	OptionalFunc(r, &x.RawPayload, r.ByteSlice)
	r.Uint8(&x.HeightMapType)

	OptionalMarshaler(r, &x.HeightMapData)
	r.Uint8(&x.RenderHeightMapType)

	OptionalMarshaler(r, &x.RenderHeightMapData)
	OptionalFunc(r, &x.BlobHash, r.Uint64)
}

// SubChunkOffset represents an offset from the base position of another sub chunk.
type SubChunkOffset [3]int8

// Marshal encodes/decodes a SubChunkOffset.
func (x *SubChunkOffset) Marshal(r IO) {
	r.Int8(&x[0])
	r.Int8(&x[1])
	r.Int8(&x[2])
}

// HeightMap holds the height of every column of a sub-chunk, indexed as [z][x].
type HeightMap [16][16]int8

// Marshal encodes/decodes a HeightMap.
func (x *HeightMap) Marshal(r IO) {
	for z := range x {
		n := uint32(16)
		r.Varuint32(&n)
		if n != 16 {
			r.InvalidValue(n, "height map row", "must hold 16 heights")
			return
		}
		for i := range x[z] {
			r.Int8(&x[z][i])
		}
	}
}
