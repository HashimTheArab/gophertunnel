package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// ResourcePackChunkRequest is sent by the client to request a chunk of data from a particular resource pack,
// that it has obtained information about in a ResourcePackDataInfo packet.
type ResourcePackChunkRequest struct {
	// ResourceName is the unique ID of the resource pack that the chunk of data is requested from.
	UUID string
	// Chunk is the requested chunk index of the chunk. It is a number that starts at 0 and is incremented for
	// each resource pack data chunk requested.
	ChunkIndex int32
}

// ID ...
func (*ResourcePackChunkRequest) ID() uint32 {
	return IDResourcePackChunkRequest
}

func (pk *ResourcePackChunkRequest) Marshal(io protocol.IO) {
	io.String(&pk.UUID)
	protocol.Pattern(io, &pk.UUID, "A string in the format of <uuid>_<semver>, where <uuid> is a valid UUID and <semver> is a valid semantic version")
	io.Int32(&pk.ChunkIndex)
	protocol.Minimum(io, &pk.ChunkIndex, 0)
}
