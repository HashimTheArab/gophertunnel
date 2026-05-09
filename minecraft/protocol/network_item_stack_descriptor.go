package protocol

import (
	"bytes"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/nbt"
)

const (
	NetworkItemStackNetIDVariantStack uint32 = iota
	NetworkItemStackNetIDVariantItemStackRequest
	NetworkItemStackNetIDVariantLegacyRequest
)

// NetworkItemStackNetIDVariant identifies which net-ID space produced a descriptor net ID.
type NetworkItemStackNetIDVariant struct {
	Type  uint32
	Value int32
}

// Marshal encodes or decodes x.
func (x *NetworkItemStackNetIDVariant) Marshal(r IO) {
	r.Varuint32(&x.Type)
	r.Varint32(&x.Value)
}

// NetworkItemStackDescriptor is the 1.26.20 network item stack descriptor used by MobEquipment and
// InventorySlot.
type NetworkItemStackDescriptor struct {
	NetworkID      int16
	Count          uint16
	MetadataValue  uint32
	NetIDVariant   Optional[NetworkItemStackNetIDVariant]
	BlockRuntimeID uint32
	UserDataBuffer string
}

// Marshal encodes or decodes x.
func (x *NetworkItemStackDescriptor) Marshal(r IO) {
	r.Int16(&x.NetworkID)
	r.Uint16(&x.Count)
	r.Varuint32(&x.MetadataValue)
	OptionalMarshaler[NetworkItemStackNetIDVariant, *NetworkItemStackNetIDVariant](r, &x.NetIDVariant)
	r.Varuint32(&x.BlockRuntimeID)
	r.String(&x.UserDataBuffer)
}

// InstanceToDescriptor converts a legacy ItemInstance into a NetworkItemStackDescriptor.
func InstanceToDescriptor(i ItemInstance, shieldID int32) NetworkItemStackDescriptor {
	x := i.Stack
	if x.NetworkID == 0 {
		return NetworkItemStackDescriptor{}
	}
	d := NetworkItemStackDescriptor{
		NetworkID:      int16(x.NetworkID),
		Count:          x.Count,
		MetadataValue:  x.MetadataValue,
		BlockRuntimeID: uint32(x.BlockRuntimeID),
		UserDataBuffer: string(marshalNetworkItemUserData(x, shieldID)),
	}
	if i.StackNetworkID != 0 {
		d.NetIDVariant = Option(NetworkItemStackNetIDVariant{
			Type:  i.StackNetworkIDVariant,
			Value: i.StackNetworkID,
		})
	}
	return d
}

// DescriptorToInstance converts a NetworkItemStackDescriptor into a legacy ItemInstance.
func DescriptorToInstance(d NetworkItemStackDescriptor, shieldID int32) ItemInstance {
	i, err := SafeDescriptorToInstance(d, shieldID)
	if err != nil {
		panic(err)
	}
	return i
}

// SafeDescriptorToInstance converts a NetworkItemStackDescriptor into a legacy ItemInstance, returning an
// error if its user data buffer is malformed.
func SafeDescriptorToInstance(d NetworkItemStackDescriptor, shieldID int32) (i ItemInstance, err error) {
	defer func() {
		if recoveredErr := recover(); recoveredErr != nil {
			err = recoveredErr.(error)
		}
	}()
	return descriptorToInstance(d, shieldID, true), nil
}

func descriptorToInstance(d NetworkItemStackDescriptor, shieldID int32, enableLimits bool) ItemInstance {
	if d.NetworkID == 0 {
		return ItemInstance{}
	}
	i := ItemInstance{
		Stack: ItemStack{
			ItemType: ItemType{
				NetworkID:     int32(d.NetworkID),
				MetadataValue: d.MetadataValue,
			},
			BlockRuntimeID: int32(d.BlockRuntimeID),
			Count:          d.Count,
			HasNetworkID:   true,
		},
	}
	if v, ok := d.NetIDVariant.Value(); ok {
		i.StackNetworkID, i.StackNetworkIDVariant = v.Value, v.Type
	}
	unmarshalNetworkItemUserData(&i.Stack, d.UserDataBuffer, shieldID, enableLimits)
	return i
}

func marshalNetworkItemUserData(x ItemStack, shieldID int32) []byte {
	buf := internal.BufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		buf.Reset()
		internal.BufferPool.Put(buf)
	}()

	w := NewWriter(buf, shieldID)
	var length int16
	if len(x.NBTData) != 0 {
		length = -1
		version := uint8(1)
		w.Int16(&length)
		w.Uint8(&version)
		w.NBT(&x.NBTData, nbt.LittleEndian)
	} else {
		w.Int16(&length)
	}
	FuncSliceUint32Length(w, &x.CanBePlacedOn, w.StringUTF)
	FuncSliceUint32Length(w, &x.CanBreak, w.StringUTF)
	if x.NetworkID == shieldID {
		w.Int64(&x.BlockingTick)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func unmarshalNetworkItemUserData(x *ItemStack, data string, shieldID int32, enableLimits bool) {
	if data == "" {
		x.NBTData, x.CanBePlacedOn, x.CanBreak = nil, nil, nil
		x.BlockingTick = 0
		return
	}
	r := NewReader(bytes.NewBufferString(data), shieldID, enableLimits)

	var length int16
	r.Int16(&length)
	switch {
	case length == -1:
		var version uint8
		r.Uint8(&version)
		switch version {
		case 1:
			r.NBT(&x.NBTData, nbt.LittleEndian)
		default:
			r.UnknownEnumOption(version, "item user data version")
			return
		}
	case length > 0:
		r.NBT(&x.NBTData, nbt.LittleEndian)
	default:
		x.NBTData = nil
	}

	FuncSliceUint32Length(r, &x.CanBePlacedOn, r.StringUTF)
	FuncSliceUint32Length(r, &x.CanBreak, r.StringUTF)
	if x.NetworkID == shieldID {
		r.Int64(&x.BlockingTick)
	} else {
		x.BlockingTick = 0
	}
}
