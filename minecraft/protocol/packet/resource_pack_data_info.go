// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// ResourcePackDataInfo is sent by the server to the client to inform the client about the data
// contained in one of the resource packs that are about to be sent.
type ResourcePackDataInfo struct {
	UUID          string
	DataChunkSize uint32
	ChunkCount    uint32
	Size          uint64
	Hash          []byte
	Premium       bool
	// PackType is the type of the resource pack. It is one of the resource pack types that may be found
	// in the constants above.
	PackType uint8
}

// Marshal reads or writes ResourcePackDataInfo using its canonical wire layout.
func (x *ResourcePackDataInfo) Marshal(io protocol.IO) {
	io.String(&x.UUID)
	io.Uint32(&x.DataChunkSize)
	io.Uint32(&x.ChunkCount)
	io.Uint64(&x.Size)
	io.Bytes(&x.Hash)
	io.Bool(&x.Premium)
	io.Uint8(&x.PackType)
}

// ID returns the protocol ID for ResourcePackDataInfo.
func (*ResourcePackDataInfo) ID() uint32 { return IDResourcePackDataInfo }
