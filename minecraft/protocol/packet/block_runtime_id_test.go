package packet

import (
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

func TestTransformBlockRuntimeIDs(t *testing.T) {
	stack := func() protocol.ItemStack {
		return protocol.ItemStack{BlockRuntimeID: 1}
	}
	instance := func() protocol.ItemInstance {
		return protocol.ItemInstance{Stack: stack()}
	}
	request := func() protocol.ItemStackRequest {
		return protocol.ItemStackRequest{Actions: []protocol.StackRequestAction{
			&protocol.CraftResultsDeprecatedStackRequestAction{
				ResultItems: []protocol.ItemStack{stack()},
			},
		}}
	}
	inputData := protocol.NewBitset(PlayerAuthInputBitsetSize)
	inputData.Set(InputFlagPerformItemInteraction)
	inputData.Set(InputFlagPerformItemStackRequest)

	tests := []struct {
		name      string
		pk        Packet
		wantCalls int
	}{
		{
			name:      "add item actor",
			pk:        &AddItemActor{Item: instance()},
			wantCalls: 1,
		},
		{
			name:      "add player",
			pk:        &AddPlayer{HeldItem: instance()},
			wantCalls: 1,
		},
		{
			name: "creative content",
			pk: &CreativeContent{
				Groups: []protocol.CreativeGroup{{Icon: stack()}},
				Items:  []protocol.CreativeItem{{Item: stack()}},
			},
			wantCalls: 2,
		},
		{
			name: "crafting data",
			pk: &CraftingData{Recipes: []protocol.Recipe{
				&protocol.ShapelessRecipe{Output: []protocol.ItemStack{stack()}},
				&protocol.ShulkerBoxRecipe{
					ShapelessRecipe: protocol.ShapelessRecipe{
						Output: []protocol.ItemStack{stack()},
					},
				},
				&protocol.ShapelessChemistryRecipe{
					ShapelessRecipe: protocol.ShapelessRecipe{
						Output: []protocol.ItemStack{stack()},
					},
				},
				&protocol.ShapedRecipe{Output: []protocol.ItemStack{stack()}},
				&protocol.ShapedChemistryRecipe{
					ShapedRecipe: protocol.ShapedRecipe{
						Output: []protocol.ItemStack{stack()},
					},
				},
				&protocol.SmithingTransformRecipe{Result: stack()},
			}},
			wantCalls: 6,
		},
		{
			name: "inventory content",
			pk: &InventoryContent{
				Content:     []protocol.ItemInstance{instance()},
				StorageItem: instance(),
			},
			wantCalls: 2,
		},
		{
			name: "inventory slot",
			pk: &InventorySlot{
				NewItem:     instance(),
				StorageItem: protocol.Option(instance()),
			},
			wantCalls: 2,
		},
		{
			name: "use item transaction",
			pk: &InventoryTransaction{
				Actions: []protocol.InventoryAction{{
					OldItem: instance(),
					NewItem: instance(),
				}},
				TransactionData: &protocol.UseItemTransactionData{
					HeldItem:       instance(),
					BlockRuntimeID: 1,
				},
			},
			wantCalls: 4,
		},
		{
			name: "use item on entity transaction",
			pk: &InventoryTransaction{
				TransactionData: &protocol.UseItemOnEntityTransactionData{
					HeldItem: instance(),
				},
			},
			wantCalls: 1,
		},
		{
			name: "release item transaction",
			pk: &InventoryTransaction{
				TransactionData: &protocol.ReleaseItemTransactionData{
					HeldItem: instance(),
				},
			},
			wantCalls: 1,
		},
		{
			name:      "item stack request",
			pk:        &ItemStackRequest{Requests: []protocol.ItemStackRequest{request()}},
			wantCalls: 1,
		},
		{
			name: "mob armour equipment",
			pk: &MobArmourEquipment{
				Helmet:     instance(),
				Chestplate: instance(),
				Leggings:   instance(),
				Boots:      instance(),
				Body:       instance(),
			},
			wantCalls: 5,
		},
		{
			name:      "mob equipment",
			pk:        &MobEquipment{NewItem: instance()},
			wantCalls: 1,
		},
		{
			name: "player auth input",
			pk: &PlayerAuthInput{
				InputData: inputData,
				ItemInteractionData: protocol.UseItemTransactionData{
					HeldItem:       instance(),
					BlockRuntimeID: 1,
				},
				ItemStackRequest: request(),
			},
			wantCalls: 3,
		},
		{
			name: "falling block metadata",
			pk: &AddActor{
				EntityType: fallingBlockEntityType,
				EntityMetadata: protocol.EntityMetadata{
					protocol.EntityDataKeyVariant: int32(1),
				},
			},
			wantCalls: 1,
		},
		{
			name: "enderman metadata",
			pk: &AddActor{
				EntityType: endermanEntityType,
				EntityMetadata: protocol.EntityMetadata{
					protocol.EntityDataKeyCarryBlockRuntimeID: uint32(1),
				},
			},
			wantCalls: 1,
		},
		{
			name: "display block metadata",
			pk: &AddActor{
				EntityType: "minecraft:minecart",
				EntityMetadata: protocol.EntityMetadata{
					protocol.EntityDataKeyDisplayTileRuntimeID: int32(1),
				},
			},
			wantCalls: 1,
		},
		{
			name: "biome definition list",
			pk: &BiomeDefinitionList{BiomeDefinitions: []protocol.BiomeDefinition{{
				ChunkGeneration: protocol.Option(protocol.BiomeChunkGeneration{
					MountainParameters: protocol.Option(protocol.BiomeMountainParameters{
						SteepBlock: 1,
					}),
					SurfaceMaterialAdjustments: protocol.Option([]protocol.BiomeElementData{{
						AdjustedMaterials: biomeSurfaceMaterial(1),
					}}),
					SurfaceMaterials: protocol.Option(biomeSurfaceMaterial(1)),
					MesaSurface: protocol.Option(protocol.BiomeMesaSurface{
						ClayMaterial: 1, HardClayMaterial: 1,
					}),
					CappedSurface: protocol.Option(biomeCappedSurface(1)),
					SurfaceBuilder: protocol.Option(protocol.BiomeSurfaceBuilder{
						SurfaceMaterials: protocol.Option(biomeSurfaceMaterial(1)),
						MesaSurface: protocol.Option(protocol.BiomeMesaSurface{
							ClayMaterial: 1, HardClayMaterial: 1,
						}),
						CappedSurface: protocol.Option(biomeCappedSurface(1)),
						NoiseGradientSurface: protocol.Option(protocol.BiomeNoiseGradientSurface{
							NonReplaceableBlocks: []uint32{1},
							GradientBlocks:       []protocol.NoiseBlockSpecifier{{Block: 1}},
						}),
					}),
				}),
			}}},
			wantCalls: 32,
		},
		{
			name: "waxed copper event",
			pk: &Event{
				Event: &protocol.WaxedOrUnwaxedCopperEvent{CopperBlockID: 1},
			},
			wantCalls: 1,
		},
		{
			name:      "level event",
			pk:        &LevelEvent{EventType: LevelEventParticlesDestroyBlock, EventData: 1},
			wantCalls: 1,
		},
		{
			name:      "level sound event",
			pk:        &LevelSoundEvent{SoundType: SoundEventPlace, ExtraData: 1},
			wantCalls: 1,
		},
		{
			name:      "step sound event",
			pk:        &LevelSoundEvent{SoundType: SoundEventStep, ExtraData: 1},
			wantCalls: 1,
		},
		{
			name:      "block break sound event",
			pk:        &LevelSoundEvent{SoundType: SoundEventBreak, ExtraData: 1},
			wantCalls: 1,
		},
		{
			name:      "update block",
			pk:        &UpdateBlock{NewBlockRuntimeID: 1},
			wantCalls: 1,
		},
		{
			name:      "update block synced",
			pk:        &UpdateBlockSynced{NewBlockRuntimeID: 1},
			wantCalls: 1,
		},
		{
			name: "update sub-chunk blocks",
			pk: &UpdateSubChunkBlocks{
				Blocks: []protocol.BlockChangeEntry{{BlockRuntimeID: 1}},
				Extra:  []protocol.BlockChangeEntry{{BlockRuntimeID: 1}},
			},
			wantCalls: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertTransformCalls(t, test.pk, 1, test.wantCalls, func(id uint32) uint32 {
				return id + 1
			})
			assertTransformCalls(t, test.pk, 2, test.wantCalls, func(id uint32) uint32 {
				return id
			})
		})
	}
}

func biomeSurfaceMaterial(runtimeID int32) protocol.BiomeSurfaceMaterial {
	return protocol.BiomeSurfaceMaterial{
		TopBlock:        runtimeID,
		MidBlock:        runtimeID,
		SeaFloorBlock:   runtimeID,
		FoundationBlock: runtimeID,
		SeaBlock:        runtimeID,
	}
}

func biomeCappedSurface(runtimeID uint32) protocol.BiomeCappedSurface {
	return protocol.BiomeCappedSurface{
		FloorBlocks:     []int32{int32(runtimeID)},
		CeilingBlocks:   []int32{int32(runtimeID)},
		SeaBlock:        protocol.Option(runtimeID),
		FoundationBlock: protocol.Option(runtimeID),
		BeachBlock:      protocol.Option(runtimeID),
	}
}

func TestTransformBlockRuntimeIDs_IgnoresAbsentAndUnrelatedValues(t *testing.T) {
	tests := []Packet{
		&AddActor{
			EntityType: "minecraft:zombie",
			EntityMetadata: protocol.EntityMetadata{
				protocol.EntityDataKeyVariant: int32(1),
			},
		},
		&LevelEvent{EventType: LevelEventSoundClick, EventData: 1},
		&LevelSoundEvent{SoundType: SoundEventNote, ExtraData: 1},
		&LevelSoundEvent{SoundType: SoundEventBreak, ExtraData: -1},
		&AddItemActor{Item: protocol.ItemInstance{
			Stack: protocol.ItemStack{BlockRuntimeID: 0},
		}},
		&PlayerAuthInput{
			InputData: protocol.NewBitset(PlayerAuthInputBitsetSize),
			ItemInteractionData: protocol.UseItemTransactionData{
				HeldItem:       protocol.ItemInstance{Stack: protocol.ItemStack{BlockRuntimeID: 1}},
				BlockRuntimeID: 1,
			},
			ItemStackRequest: protocol.ItemStackRequest{
				Actions: []protocol.StackRequestAction{
					&protocol.CraftResultsDeprecatedStackRequestAction{
						ResultItems: []protocol.ItemStack{{BlockRuntimeID: 1}},
					},
				},
			},
		},
	}
	for _, pk := range tests {
		TransformBlockRuntimeIDs(pk, func(uint32) uint32 {
			t.Fatalf("transform called for %T", pk)
			return 0
		})
	}
}

func TestTransformBlockRuntimeIDs_LevelEvents(t *testing.T) {
	eventTypes := []int32{
		LevelEventParticlesDestroyBlock,
		LevelEventParticlesCropEaten,
		LevelEventParticlesCrackBlock,
		LevelEventParticlesDestroyArmorStand,
		LevelEventParticlesDestroyBlockNoSound,
		LevelEventParticlesCrackBlockDown,
		LevelEventParticlesCrackBlockUp,
		LevelEventParticlesCrackBlockNorth,
		LevelEventParticlesCrackBlockSouth,
		LevelEventParticlesCrackBlockWest,
		LevelEventParticlesCrackBlockEast,
		LevelEventParticleLegacyEvent | 20,
		LevelEventParticleLegacyEvent | 32,
		LevelEventParticleLegacyEvent | 85,
	}
	for _, eventType := range eventTypes {
		pk := &LevelEvent{EventType: eventType, EventData: 1}
		TransformBlockRuntimeIDs(pk, func(id uint32) uint32 {
			if id != 1 {
				t.Fatalf("transform input = %d, want 1", id)
			}
			return 2
		})
		if pk.EventData != 2 {
			t.Fatalf("event data = %d, want 2", pk.EventData)
		}
	}
}

func TestTransformBlockRuntimeIDs_PreservesCrackBlockFace(t *testing.T) {
	pk := &LevelEvent{
		EventType: LevelEventParticlesCrackBlock,
		EventData: int32(uint32(3)<<24 | 1),
	}
	TransformBlockRuntimeIDs(pk, func(id uint32) uint32 {
		if id != 1 {
			t.Fatalf("transform input = %d, want 1", id)
		}
		return 2
	})
	if pk.EventType != LevelEventParticlesCrackBlock {
		t.Fatalf("event type = %d, want %d", pk.EventType, LevelEventParticlesCrackBlock)
	}
	if got, want := uint32(pk.EventData), uint32(3)<<24|2; got != want {
		t.Fatalf("event data = %#x, want %#x", got, want)
	}
}

func TestTransformBlockRuntimeIDs_ConvertsHashedCrackBlockEvent(t *testing.T) {
	pk := &LevelEvent{
		EventType: LevelEventParticlesCrackBlock,
		EventData: int32(uint32(3)<<24 | 1),
	}
	const blockHash = uint32(0xdeadbeef)
	TransformBlockRuntimeIDs(pk, func(uint32) uint32 {
		return blockHash
	})
	if pk.EventType != LevelEventParticlesCrackBlockSouth {
		t.Fatalf("event type = %d, want %d", pk.EventType, LevelEventParticlesCrackBlockSouth)
	}
	if got := uint32(pk.EventData); got != blockHash {
		t.Fatalf("event data = %#x, want %#x", got, blockHash)
	}
}

func TestTransformBlockRuntimeIDs_TransformsZeroInMandatoryFields(t *testing.T) {
	pk := &UpdateBlock{}
	TransformBlockRuntimeIDs(pk, func(id uint32) uint32 {
		if id != 0 {
			t.Fatalf("transform input = %d, want 0", id)
		}
		return 42
	})
	if pk.NewBlockRuntimeID != 42 {
		t.Fatalf("block runtime ID = %d, want 42", pk.NewBlockRuntimeID)
	}
}

func assertTransformCalls(
	t *testing.T,
	pk Packet,
	wantInput uint32,
	wantCalls int,
	transform func(uint32) uint32,
) {
	t.Helper()
	calls := 0
	TransformBlockRuntimeIDs(pk, func(id uint32) uint32 {
		calls++
		if id != wantInput {
			t.Errorf("transform input = %d, want %d", id, wantInput)
		}
		return transform(id)
	})
	if calls != wantCalls {
		t.Fatalf("transform calls = %d, want %d", calls, wantCalls)
	}
}
