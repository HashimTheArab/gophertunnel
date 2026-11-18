package protocol

import "testing"

// TestSubChunkEntry_SkyBoundary covers exact, clamped and unknown boundaries
// merged over earlier ones.
func TestSubChunkEntry_SkyBoundary(t *testing.T) {
	var heights HeightMap
	heights[2][1] = 5
	heights[0][0] = 16
	heights[3][3] = -1
	const unknown, lower, higher = 320, 40, 60
	for _, test := range []struct {
		name   string
		entry  SubChunkEntry
		x, z   int
		before int16
		want   int16
		ok     bool
	}{
		{"exact height", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataHasData, RenderHeightMapData: Option(heights)}, 1, 2, unknown, 3*16 + 6, true},
		{"exact height replaces a lower boundary", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataHasData, RenderHeightMapData: Option(heights)}, 1, 2, lower, 3*16 + 6, true},
		{"column surface below band", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataHasData, RenderHeightMapData: Option(heights)}, 3, 3, higher, 3 * 16, true},
		{"column surface below band keeps a lower boundary", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataHasData, RenderHeightMapData: Option(heights)}, 3, 3, lower, lower, true},
		{"height above band", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataHasData, RenderHeightMapData: Option(heights)}, 0, 0, unknown, unknown, true},
		{"surface below band", SubChunkEntry{Result: SubChunkResultSuccessAllAir, RenderHeightMapType: HeightMapDataTooLow}, 4, 4, unknown, 3 * 16, true},
		{"surface below band keeps a lower boundary", SubChunkEntry{Result: SubChunkResultSuccessAllAir, RenderHeightMapType: HeightMapDataTooLow}, 4, 4, lower, lower, true},
		{"surface above band", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataTooHigh}, 4, 4, unknown, unknown, false},
		{"no map", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataNone}, 4, 4, unknown, unknown, false},
		{"map type without data", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataHasData}, 4, 4, unknown, unknown, false},
		{"failed entry", SubChunkEntry{Result: SubChunkResultChunkNotFound, RenderHeightMapType: HeightMapDataTooLow}, 4, 4, unknown, unknown, false},
	} {
		var starts [256]int16
		for i := range starts {
			starts[i] = test.before
		}
		sky, ok := test.entry.SkyBoundary(3)
		if ok {
			sky.Merge(&starts)
		}
		if floor, below := sky.Floor(); ok && (below != (test.entry.RenderHeightMapType == HeightMapDataTooLow) || below && floor != 3*16) {
			t.Errorf("%s: Floor = %d, %v", test.name, floor, below)
		}
		if got := starts[test.z*16+test.x]; ok != test.ok || got != test.want {
			t.Errorf("%s: SkyBoundary ok = %v, merged = %d; want %v, %d", test.name, ok, got, test.ok, test.want)
		}
	}
}

// BenchmarkSubChunkEntry_SkyBoundary merges a surface band's boundaries.
func BenchmarkSubChunkEntry_SkyBoundary(b *testing.B) {
	var heights HeightMap
	for z := range heights {
		for x := range heights[z] {
			heights[z][x] = int8((x+z)%18) - 1
		}
	}
	entry := SubChunkEntry{Result: SubChunkResultSuccess, RawPayload: Option(make([]byte, 4096)), RenderHeightMapType: HeightMapDataHasData, RenderHeightMapData: Option(heights)}
	var starts [256]int16
	for b.Loop() {
		sky, _ := entry.SkyBoundary(3)
		sky.Merge(&starts)
	}
}

// BenchmarkSubChunkEntry_SkyBoundaryAboveSurface merges a band above the surface.
func BenchmarkSubChunkEntry_SkyBoundaryAboveSurface(b *testing.B) {
	entry := SubChunkEntry{Result: SubChunkResultSuccessAllAir, RenderHeightMapType: HeightMapDataTooLow}
	var starts [256]int16
	for b.Loop() {
		sky, _ := entry.SkyBoundary(3)
		sky.Merge(&starts)
	}
}
