package packet

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

// wireGolden pins the encoded bytes of packets whose entity ID fields moved to semantic
// IO methods, with fixtures covering every non-canonical encoding variant. The hex was
// generated with the encoder as of the commit preceding the migration, so a semantic
// method that delegates to a different primitive than the one it replaced fails here.
var wireGolden = map[string]string{
	"AddVolumeEntity":                 "848688080a000000000000000000000000",
	"CameraInstruction":               "0000000100080706050403020100000001080706050403020100",
	"CommandRequest":                  "0006706c61796572000000000000000000000000000000000008070605040302010000",
	"EventEntityInteract":             "8a9098a0200200018a9098a02000000000",
	"MovePlayer":                      "85888c9010000000000000000000000000000000000000000000000000000085888c901000",
	"NPCDialogue":                     "08070605040302010000000000",
	"PlayerAuthInputPredictedVehicle": "00000000000000000000000000000000000000000000000000000000000000008080808080800800000000000000000000000000000000000000000000000000000000000000008a9098a02000000000000000000000000000000000000000000000000000000000",
	"RemoveVolumeEntity":              "8486880800",
	"UpdateAbilities":                 "0807060504030201000000",
	"UpdateBlockSynced":               "00000000000085888c901000",
	"UpdateSubChunkBlocks":            "00000001000000000085888c90100000",
}

func wireGoldenFixtures() map[string]Packet {
	input := &PlayerAuthInput{InputData: protocol.NewBitset(PlayerAuthInputBitsetSize), ClientPredictedVehicle: 0x0102030405}
	input.InputData.Set(InputFlagClientPredictedVehicle)
	return map[string]Packet{
		"PlayerAuthInputPredictedVehicle": input,
		"NPCDialogue":                     &NPCDialogue{EntityUniqueID: 0x0102030405060708},
		"AddVolumeEntity":                 &AddVolumeEntity{EntityRuntimeID: 0x01020304, EntityMetadata: map[string]any{}},
		"RemoveVolumeEntity":              &RemoveVolumeEntity{EntityRuntimeID: 0x01020304},
		"UpdateBlockSynced":               &UpdateBlockSynced{EntityUniqueID: 0x0102030405},
		"UpdateSubChunkBlocks":            &UpdateSubChunkBlocks{Blocks: []protocol.BlockChangeEntry{{SyncedUpdateEntityUniqueID: 0x0102030405}}},
		"EventEntityInteract":             &Event{EntityRuntimeID: 0x0102030405, Event: &protocol.EntityInteractEvent{InteractedEntityID: 0x0102030405}},
		"UpdateAbilities":                 &UpdateAbilities{AbilityData: protocol.AbilityData{EntityUniqueID: 0x0102030405060708}},
		"CommandRequest":                  &CommandRequest{CommandOrigin: protocol.CommandOrigin{PlayerUniqueID: 0x0102030405060708}},
		"CameraInstruction": &CameraInstruction{
			Target:         protocol.Option(protocol.CameraInstructionTarget{EntityUniqueID: 0x0102030405060708}),
			AttachToEntity: protocol.Option(int64(0x0102030405060708)),
		},
		"MovePlayer": &MovePlayer{EntityRuntimeID: 0x0102030405, RiddenEntityRuntimeID: 0x0102030405},
	}
}

func TestTranslateEntityIDsWireFormatUnchanged(t *testing.T) {
	for name, pk := range wireGoldenFixtures() {
		t.Run(name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			pk.Marshal(protocol.NewWriter(buf, 0))
			if got := hex.EncodeToString(buf.Bytes()); got != wireGolden[name] {
				t.Errorf("wire format changed:\n got %v\nwant %v", got, wireGolden[name])
			}
		})
	}
}
