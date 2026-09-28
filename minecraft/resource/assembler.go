package resource

import (
	"fmt"
)

// ChunkCount returns how many chunks of chunkSize carry a pack of size bytes.
// It reports false for a zero chunk size or a count the protocol cannot index.
func ChunkCount(size uint64, chunkSize uint32) (uint32, bool) {
	if chunkSize == 0 {
		return 0, false
	}
	count := size / uint64(chunkSize)
	if size%uint64(chunkSize) != 0 {
		count++
	}
	if count > uint64(1)<<31 {
		return 0, false
	}
	return uint32(count), true
}

// Assembler rebuilds a pack from ResourcePackChunkData observed in transit, such
// as a proxy watching a server send a pack to its client. Chunks may arrive in
// any order; duplicates are ignored.
type Assembler struct {
	data      []byte
	chunkSize uint32
	received  []bool
	missing   uint32
}

// NewAssembler returns an Assembler for the pack a ResourcePackDataInfo announced.
// It allocates size bytes, so callers must bound the size a server claims.
func NewAssembler(size uint64, chunkSize uint32) (*Assembler, error) {
	count, ok := ChunkCount(size, chunkSize)
	if !ok || size > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("invalid pack size %v with chunk size %v", size, chunkSize)
	}
	return &Assembler{data: make([]byte, size), chunkSize: chunkSize, received: make([]bool, count), missing: count}, nil
}

// Add stores one chunk and reports whether every chunk has now arrived.
func (a *Assembler) Add(index uint32, data []byte) (bool, error) {
	if index >= uint32(len(a.received)) {
		return false, fmt.Errorf("chunk index %v exceeds chunk count %v", index, len(a.received))
	}
	offset := uint64(index) * uint64(a.chunkSize)
	want := min(uint64(a.chunkSize), uint64(len(a.data))-offset)
	if uint64(len(data)) != want {
		return false, fmt.Errorf("chunk %v has %v bytes, expected %v", index, len(data), want)
	}
	if !a.received[index] {
		copy(a.data[offset:], data)
		a.received[index] = true
		a.missing--
	}
	return a.missing == 0, nil
}

// Pack parses the assembled archive. It fails until every chunk has arrived.
func (a *Assembler) Pack() (*Pack, error) {
	if a.missing != 0 {
		return nil, fmt.Errorf("%v chunks missing", a.missing)
	}
	return ReadBytes(a.data)
}
