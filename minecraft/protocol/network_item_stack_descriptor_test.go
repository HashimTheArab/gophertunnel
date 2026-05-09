package protocol_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestNetworkItemStackDescriptorRoundTripsShieldBlockingTick(t *testing.T) {
	const shieldID int32 = 512
	in := protocol.ItemInstance{
		StackNetworkID: 77,
		Stack: protocol.ItemStack{
			ItemType: protocol.ItemType{
				NetworkID:     shieldID,
				MetadataValue: 4,
			},
			BlockRuntimeID: 1234,
			Count:          2,
			NBTData: map[string]any{
				"display": map[string]any{"Name": "guard"},
			},
			CanBePlacedOn: []string{"minecraft:stone"},
			CanBreak:      []string{"minecraft:dirt"},
			HasNetworkID:  true,
			BlockingTick:  987654321,
		},
	}

	desc := protocol.InstanceToDescriptor(in, shieldID)
	out := protocol.DescriptorToInstance(desc, shieldID)

	if !reflect.DeepEqual(out, in) {
		t.Fatalf("descriptor round trip mismatch:\nin:  %#v\nout: %#v", in, out)
	}
}

func TestNetworkItemStackDescriptorOmitsBlockingTickForNonShield(t *testing.T) {
	const shieldID int32 = 512
	in := protocol.ItemInstance{
		StackNetworkID: 78,
		Stack: protocol.ItemStack{
			ItemType: protocol.ItemType{
				NetworkID:     42,
				MetadataValue: 1,
			},
			BlockRuntimeID: 555,
			Count:          3,
			HasNetworkID:   true,
			BlockingTick:   987654321,
		},
	}

	desc := protocol.InstanceToDescriptor(in, shieldID)
	out := protocol.DescriptorToInstance(desc, shieldID)

	if out.Stack.BlockingTick != 0 {
		t.Fatalf("non-shield blocking tick = %v, want 0", out.Stack.BlockingTick)
	}
	if out.Stack.NetworkID != in.Stack.NetworkID || out.Stack.Count != in.Stack.Count {
		t.Fatalf("non-shield descriptor changed item identity: in=%#v out=%#v", in, out)
	}
}

func TestNetworkItemStackDescriptorRoundTripsEmptyItem(t *testing.T) {
	const shieldID int32 = 512
	out := protocol.DescriptorToInstance(protocol.InstanceToDescriptor(protocol.ItemInstance{}, shieldID), shieldID)
	if !reflect.DeepEqual(out, protocol.ItemInstance{}) {
		t.Fatalf("empty descriptor round trip = %#v, want empty ItemInstance", out)
	}
}

func TestMobEquipmentUsesNetworkItemStackDescriptor(t *testing.T) {
	const shieldID int32 = 512
	in := protocol.ItemInstance{
		StackNetworkID: 79,
		Stack: protocol.ItemStack{
			ItemType: protocol.ItemType{
				NetworkID:     shieldID,
				MetadataValue: 0,
			},
			Count:        1,
			HasNetworkID: true,
			BlockingTick: 123,
		},
	}
	pk := &packet.MobEquipment{
		EntityRuntimeID: 1,
		NewItem:         protocol.InstanceToDescriptor(in, shieldID),
		InventorySlot:   0,
		HotBarSlot:      0,
		WindowID:        protocol.WindowIDInventory,
	}

	var buf bytes.Buffer
	pk.Marshal(protocol.NewWriter(&buf, shieldID))

	var decoded packet.MobEquipment
	decoded.Marshal(protocol.NewReader(bytes.NewBuffer(buf.Bytes()), shieldID, true))
	out := protocol.DescriptorToInstance(decoded.NewItem, shieldID)

	if out.Stack.BlockingTick != in.Stack.BlockingTick {
		t.Fatalf("decoded blocking tick = %v, want %v", out.Stack.BlockingTick, in.Stack.BlockingTick)
	}
}
