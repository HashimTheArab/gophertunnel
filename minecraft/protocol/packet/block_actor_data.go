package packet

import (
	"github.com/sandertv/gophertunnel/minecraft/nbt"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// BlockActorData is sent by the server to update data of a block entity client-side, for example the data of
// a chest.
type BlockActorData struct {
	// Position is the position of the block that holds the block entity. If no block entity is at this
	// position, the packet is ignored by the client.
	Position protocol.BlockPos
	// NBTData is the new data of the block that will be encoded to NBT and applied client-side, so that the
	// client can see the block update. The NBTData should contain all properties of the block, not just
	// properties that were changed.
	NBTData map[string]any

	decodeNBTLazily bool
	rawNBTData      nbt.RawMessage
}

// NewLazyBlockActorData returns a BlockActorData that retains decoded NBT in
// its original wire form until NBTData is materialised. Generated packets and
// normal decoded packets continue to use NBTData directly.
func NewLazyBlockActorData() *BlockActorData {
	return &BlockActorData{decodeNBTLazily: true}
}

// NBTFields returns only the requested top-level NBT fields. It avoids
// materialising other fields when the packet was decoded lazily. Treat the
// returned values as read-only: nested maps and slices may alias an already
// materialised NBTData map. Call MaterialiseNBT and mutate NBTData directly to
// change data that should be encoded.
func (pk *BlockActorData) NBTFields(fields ...string) (map[string]any, error) {
	if pk.NBTData != nil {
		selected := make(map[string]any, len(fields))
		for _, field := range fields {
			if value, ok := pk.NBTData[field]; ok {
				selected[field] = value
			}
		}
		return selected, nil
	}
	return pk.rawNBTData.DecodeFields(nbt.NetworkLittleEndian, fields...)
}

// MaterialiseNBT decodes the complete raw NBT value into NBTData. Subsequent
// mutations to NBTData are encoded normally.
func (pk *BlockActorData) MaterialiseNBT() error {
	if pk.NBTData != nil {
		return nil
	}
	if err := pk.rawNBTData.Unmarshal(&pk.NBTData, nbt.NetworkLittleEndian); err != nil {
		return err
	}
	pk.decodeNBTLazily = false
	pk.rawNBTData = nbt.RawMessage{}
	return nil
}

// ID ...
func (*BlockActorData) ID() uint32 {
	return IDBlockActorData
}

func (pk *BlockActorData) Marshal(io protocol.IO) {
	io.BlockPos(&pk.Position)
	if pk.decodeNBTLazily && pk.NBTData == nil {
		io.RawNBT(&pk.rawNBTData, nbt.NetworkLittleEndian)
		return
	}
	io.NBT(&pk.NBTData, nbt.NetworkLittleEndian)
}
