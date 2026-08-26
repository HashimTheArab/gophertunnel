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
	// RawNBT holds the original NetworkLittleEndian NBT of an inbound packet. When set, it takes precedence
	// over NBTData while encoding so proxies can forward the compound without decoding and re-encoding it.
	RawNBT []byte
}

// ID ...
func (*BlockActorData) ID() uint32 {
	return IDBlockActorData
}

func (pk *BlockActorData) Marshal(io protocol.IO) {
	io.BlockPos(&pk.Position)
	if rawIO, ok := io.(interface {
		NBTWithRaw(*[]byte, *map[string]any, nbt.Encoding)
	}); ok {
		rawIO.NBTWithRaw(&pk.RawNBT, &pk.NBTData, nbt.NetworkLittleEndian)
		return
	}
	io.NBT(&pk.NBTData, nbt.NetworkLittleEndian)
}

// FilterNBT decodes only root compound entries accepted by keep. Inbound packets use RawNBT; packets created
// with NBTData are filtered directly without a needless encode/decode cycle.
func (pk *BlockActorData) FilterNBT(keep func(string) bool) (map[string]any, error) {
	if len(pk.RawNBT) != 0 {
		var filtered map[string]any
		if err := nbt.UnmarshalNetworkFiltered(pk.RawNBT, &filtered, keep); err != nil {
			return nil, err
		}
		return filtered, nil
	}
	var filtered map[string]any
	for key, value := range pk.NBTData {
		if keep != nil && keep(key) {
			if filtered == nil {
				filtered = make(map[string]any)
			}
			filtered[key] = value
		}
	}
	return filtered, nil
}
