package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

// ClientCacheBlobStatus is part of the blob cache protocol. It is sent by the client to let the
// server know what blobs it needs and which blobs it already has, in an ACK type system.
type ClientCacheBlobStatus struct {
	// MissingIds is a list of blob hashes that the client does not have a blob available for. The
	// server should send the blobs matching these hashes as soon as possible.
	MissHashes []uint64
	// FoundIds is a list of blob hashes that the client has a blob available for. The blobs hashes here
	// mean that the client already has them: The server does not need to send the blobs anymore.
	HitHashes []uint64
}

// Marshal reads or writes ClientCacheBlobStatus using its canonical wire layout.
func (x *ClientCacheBlobStatus) Marshal(io protocol.IO) {
	protocol.FuncSliceLimits(io, &x.MissHashes, io.Varuint32, 0, 4095, io.Uint64)
	protocol.FuncSliceLimits(io, &x.HitHashes, io.Varuint32, 0, 4095, io.Uint64)
}

// ID returns the protocol ID for ClientCacheBlobStatus.
func (*ClientCacheBlobStatus) ID() uint32 { return IDClientCacheBlobStatus }
