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

// SkyBoundary is the conservative sky boundary a sub-chunk entry's render height
// map establishes for its block columns: the first block Y above each column's
// render surface. It reads the entry's height map in place, so it is valid only
// while the entry is unchanged.
type SkyBoundary struct {
	base int16
	// heights is nil when every column's surface lies below the band.
	heights *HeightMap
}

// SkyBoundary returns the sky boundary the entry establishes. subChunkY is
// absolute and must lie within the world's height. ok is false when the entry
// establishes no column's boundary: a failed entry, a surface above the band, or
// a missing or copied map. Callers can then skip the entry without reading any
// column.
func (x *SubChunkEntry) SkyBoundary(subChunkY int32) (b SkyBoundary, ok bool) {
	if x.Result != SubChunkResultSuccess && x.Result != SubChunkResultSuccessAllAir {
		return SkyBoundary{}, false
	}
	switch x.RenderHeightMapType {
	case HeightMapDataTooLow:
		return SkyBoundary{base: int16(subChunkY * 16)}, true
	case HeightMapDataHasData:
		if x.RenderHeightMapData.set {
			return SkyBoundary{base: int16(subChunkY * 16), heights: &x.RenderHeightMapData.val}, true
		}
	}
	return SkyBoundary{}, false
}

// Floor reports a band above every column's surface, whose boundaries are all
// bounded only by y, the band's bottom. A lower boundary observed in another
// band is more precise.
func (b SkyBoundary) Floor() (y int16, ok bool) { return b.base, b.heights == nil }

// Merge folds this band's boundaries into starts, one per column indexed
// z*16+x. A surface inside the band gives the column's exact boundary, which
// replaces the one in starts. A surface below the band bounds the column only
// by the band's bottom, which lowers a boundary in starts but adds no precision
// to a lower one observed in another band. A height above the band cannot
// establish an upper bound on its own and leaves the column unchanged.
func (b SkyBoundary) Merge(starts *[256]int16) {
	if b.heights == nil {
		for i := range starts {
			starts[i] = min(starts[i], b.base)
		}
		return
	}
	for i := range starts {
		h, v := b.heights[i>>4][i&15], starts[i]
		// -1 marks a column whose surface lies below this band, like
		// HeightMapDataTooLow for the whole map.
		if h == -1 {
			v = min(v, b.base)
		}
		if uint8(h) < 16 {
			v = b.base + int16(h) + 1
		}
		starts[i] = v
	}
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
