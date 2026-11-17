package protocol

import "testing"

// TestSubChunkEntry_SkyStart covers exact, clamped and unknown boundaries.
func TestSubChunkEntry_SkyStart(t *testing.T) {
	var heights HeightMap
	heights[2][1] = 5
	heights[0][0] = 16
	heights[3][3] = -1
	for _, test := range []struct {
		name        string
		entry       SubChunkEntry
		x, z        uint8
		y           int32
		clamped, ok bool
	}{
		{"exact height", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataHasData, RenderHeightMapData: Option(heights)}, 1, 2, 3*16 + 6, false, true},
		{"column surface below band", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataHasData, RenderHeightMapData: Option(heights)}, 3, 3, 3 * 16, true, true},
		{"height above band", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataHasData, RenderHeightMapData: Option(heights)}, 0, 0, 0, false, false},
		{"surface below band", SubChunkEntry{Result: SubChunkResultSuccessAllAir, RenderHeightMapType: HeightMapDataTooLow}, 4, 4, 3 * 16, true, true},
		{"surface above band", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataTooHigh}, 4, 4, 0, false, false},
		{"no map", SubChunkEntry{Result: SubChunkResultSuccess, RenderHeightMapType: HeightMapDataNone}, 4, 4, 0, false, false},
		{"failed entry", SubChunkEntry{Result: SubChunkResultChunkNotFound, RenderHeightMapType: HeightMapDataTooLow}, 4, 4, 0, false, false},
		{"column outside", SubChunkEntry{Result: SubChunkResultSuccessAllAir, RenderHeightMapType: HeightMapDataTooLow}, 16, 0, 0, false, false},
	} {
		y, clamped, ok := test.entry.SkyStart(3, test.x, test.z)
		if y != test.y || clamped != test.clamped || ok != test.ok {
			t.Errorf("%s: SkyStart = %d, %v, %v; want %d, %v, %v", test.name, y, clamped, ok, test.y, test.clamped, test.ok)
		}
	}
}
