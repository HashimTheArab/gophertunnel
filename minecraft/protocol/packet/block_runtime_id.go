package packet

import "github.com/sandertv/gophertunnel/minecraft/protocol"

const (
	fallingBlockEntityType = "minecraft:falling_block"
	endermanEntityType     = "minecraft:enderman"
)

// TransformBlockRuntimeIDs applies transform to structured block runtime ID fields in pk. It mutates pk and its
// nested data in place. Encoded chunk payloads are not rewritten. For SetActorData, use
// TransformEntityMetadataBlockRuntimeIDs with the actor's entity type.
func TransformBlockRuntimeIDs(pk Packet, transform func(uint32) uint32) {
	transformPacketItemBlockRuntimeIDs(pk, transform)

	switch pk := pk.(type) {
	case *AddActor:
		TransformEntityMetadataBlockRuntimeIDs(pk.EntityType, pk.EntityMetadata, transform)
	case *BiomeDefinitionList:
		transformBiomeDefinitionBlockRuntimeIDs(pk.BiomeDefinitions, transform)
	case *Event:
		if event, ok := pk.Event.(*protocol.WaxedOrUnwaxedCopperEvent); ok {
			transformSignedBlockRuntimeID(&event.CopperBlockID, transform)
		}
	case *InventoryTransaction:
		if data, ok := pk.TransactionData.(*protocol.UseItemTransactionData); ok {
			transformBlockRuntimeID(&data.BlockRuntimeID, transform)
		}
	case *LevelEvent:
		if pk.EventType == LevelEventParticlesCrackBlock {
			transformCrackBlockEvent(pk, transform)
		} else if levelEventUsesBlockRuntimeID(pk.EventType) {
			transformSignedBlockRuntimeID(&pk.EventData, transform)
		}
	case *LevelSoundEvent:
		if levelSoundEventUsesBlockRuntimeID(pk.SoundType) &&
			!(pk.SoundType == SoundEventBreak && pk.ExtraData == -1) {
			transformSignedBlockRuntimeID(&pk.ExtraData, transform)
		}
	case *PlayerAuthInput:
		if inputFlagSet(pk, InputFlagPerformItemInteraction) {
			transformBlockRuntimeID(&pk.ItemInteractionData.BlockRuntimeID, transform)
		}
	case *UpdateBlock:
		transformBlockRuntimeID(&pk.NewBlockRuntimeID, transform)
	case *UpdateBlockSynced:
		transformBlockRuntimeID(&pk.NewBlockRuntimeID, transform)
	case *UpdateSubChunkBlocks:
		transformBlockChanges(pk.Blocks, transform)
		transformBlockChanges(pk.Extra, transform)
	}
}

// TransformEntityMetadataBlockRuntimeIDs applies transform to block runtime IDs whose meaning depends on
// entityType. It mutates metadata in place.
func TransformEntityMetadataBlockRuntimeIDs(
	entityType string, metadata protocol.EntityMetadata, transform func(uint32) uint32,
) {
	transformEntityMetadataBlockRuntimeID(
		metadata, protocol.EntityDataKeyDisplayTileRuntimeID, transform,
	)

	var key uint32
	switch entityType {
	case fallingBlockEntityType:
		key = protocol.EntityDataKeyVariant
	case endermanEntityType:
		key = protocol.EntityDataKeyCarryBlockRuntimeID
	default:
		return
	}
	transformEntityMetadataBlockRuntimeID(metadata, key, transform)
}

func transformEntityMetadataBlockRuntimeID(
	metadata protocol.EntityMetadata, key uint32, transform func(uint32) uint32,
) {
	value, ok := metadata[key]
	if !ok {
		return
	}
	switch value := value.(type) {
	case int32:
		metadata[key] = int32(transform(uint32(value)))
	case uint32:
		metadata[key] = transform(value)
	}
}

func transformBiomeDefinitionBlockRuntimeIDs(
	definitions []protocol.BiomeDefinition, transform func(uint32) uint32,
) {
	for i := range definitions {
		generation, ok := definitions[i].ChunkGeneration.Value()
		if !ok {
			continue
		}
		transformBiomeChunkGenerationBlockRuntimeIDs(&generation, transform)
		definitions[i].ChunkGeneration = protocol.Option(generation)
	}
}

func transformBiomeChunkGenerationBlockRuntimeIDs(
	generation *protocol.BiomeChunkGeneration, transform func(uint32) uint32,
) {
	if mountain, ok := generation.MountainParameters.Value(); ok {
		transformSignedBlockRuntimeID(&mountain.SteepBlock, transform)
		generation.MountainParameters = protocol.Option(mountain)
	}
	if adjustments, ok := generation.SurfaceMaterialAdjustments.Value(); ok {
		for i := range adjustments {
			transformBiomeSurfaceMaterialBlockRuntimeIDs(&adjustments[i].AdjustedMaterials, transform)
		}
		generation.SurfaceMaterialAdjustments = protocol.Option(adjustments)
	}
	if material, ok := generation.SurfaceMaterials.Value(); ok {
		transformBiomeSurfaceMaterialBlockRuntimeIDs(&material, transform)
		generation.SurfaceMaterials = protocol.Option(material)
	}
	if mesa, ok := generation.MesaSurface.Value(); ok {
		transformBiomeMesaSurfaceBlockRuntimeIDs(&mesa, transform)
		generation.MesaSurface = protocol.Option(mesa)
	}
	if capped, ok := generation.CappedSurface.Value(); ok {
		transformBiomeCappedSurfaceBlockRuntimeIDs(&capped, transform)
		generation.CappedSurface = protocol.Option(capped)
	}
	if builder, ok := generation.SurfaceBuilder.Value(); ok {
		transformBiomeSurfaceBuilderBlockRuntimeIDs(&builder, transform)
		generation.SurfaceBuilder = protocol.Option(builder)
	}
	if builder, ok := generation.SubsurfaceBuilder.Value(); ok {
		transformBiomeSurfaceBuilderBlockRuntimeIDs(&builder, transform)
		generation.SubsurfaceBuilder = protocol.Option(builder)
	}
}

func transformBiomeSurfaceBuilderBlockRuntimeIDs(
	builder *protocol.BiomeSurfaceBuilder, transform func(uint32) uint32,
) {
	if material, ok := builder.SurfaceMaterials.Value(); ok {
		transformBiomeSurfaceMaterialBlockRuntimeIDs(&material, transform)
		builder.SurfaceMaterials = protocol.Option(material)
	}
	if mesa, ok := builder.MesaSurface.Value(); ok {
		transformBiomeMesaSurfaceBlockRuntimeIDs(&mesa, transform)
		builder.MesaSurface = protocol.Option(mesa)
	}
	if capped, ok := builder.CappedSurface.Value(); ok {
		transformBiomeCappedSurfaceBlockRuntimeIDs(&capped, transform)
		builder.CappedSurface = protocol.Option(capped)
	}
	if noise, ok := builder.NoiseGradientSurface.Value(); ok {
		for i := range noise.NonReplaceableBlocks {
			transformBlockRuntimeID(&noise.NonReplaceableBlocks[i], transform)
		}
		for i := range noise.GradientBlocks {
			transformBlockRuntimeID(&noise.GradientBlocks[i].Block, transform)
		}
		builder.NoiseGradientSurface = protocol.Option(noise)
	}
}

func transformBiomeSurfaceMaterialBlockRuntimeIDs(
	material *protocol.BiomeSurfaceMaterial, transform func(uint32) uint32,
) {
	transformSignedBlockRuntimeID(&material.TopBlock, transform)
	transformSignedBlockRuntimeID(&material.MidBlock, transform)
	transformSignedBlockRuntimeID(&material.SeaFloorBlock, transform)
	transformSignedBlockRuntimeID(&material.FoundationBlock, transform)
	transformSignedBlockRuntimeID(&material.SeaBlock, transform)
}

func transformBiomeMesaSurfaceBlockRuntimeIDs(
	mesa *protocol.BiomeMesaSurface, transform func(uint32) uint32,
) {
	transformBlockRuntimeID(&mesa.ClayMaterial, transform)
	transformBlockRuntimeID(&mesa.HardClayMaterial, transform)
}

func transformBiomeCappedSurfaceBlockRuntimeIDs(
	capped *protocol.BiomeCappedSurface, transform func(uint32) uint32,
) {
	for i := range capped.FloorBlocks {
		transformSignedBlockRuntimeID(&capped.FloorBlocks[i], transform)
	}
	for i := range capped.CeilingBlocks {
		transformSignedBlockRuntimeID(&capped.CeilingBlocks[i], transform)
	}
	transformOptionalBlockRuntimeID(&capped.SeaBlock, transform)
	transformOptionalBlockRuntimeID(&capped.FoundationBlock, transform)
	transformOptionalBlockRuntimeID(&capped.BeachBlock, transform)
}

func transformOptionalBlockRuntimeID(
	runtimeID *protocol.Optional[uint32], transform func(uint32) uint32,
) {
	if value, ok := runtimeID.Value(); ok {
		*runtimeID = protocol.Option(transform(value))
	}
}

func transformPacketItemBlockRuntimeIDs(pk Packet, transform func(uint32) uint32) {
	transformItemStack := func(stack *protocol.ItemStack) {
		if stack.BlockRuntimeID != 0 {
			transformSignedBlockRuntimeID(&stack.BlockRuntimeID, transform)
		}
	}

	switch pk := pk.(type) {
	case *AddItemActor:
		transformItemStack(&pk.Item.Stack)
	case *AddPlayer:
		transformItemStack(&pk.HeldItem.Stack)
	case *CreativeContent:
		for i := range pk.Groups {
			transformItemStack(&pk.Groups[i].Icon)
		}
		for i := range pk.Items {
			transformItemStack(&pk.Items[i].Item)
		}
	case *CraftingData:
		transformRecipeItemBlockRuntimeIDs(pk.Recipes, transformItemStack)
	case *InventoryContent:
		for i := range pk.Content {
			transformItemStack(&pk.Content[i].Stack)
		}
		transformItemStack(&pk.StorageItem.Stack)
	case *InventorySlot:
		transformItemStack(&pk.NewItem.Stack)
		if storage, ok := pk.StorageItem.Value(); ok {
			transformItemStack(&storage.Stack)
			pk.StorageItem = protocol.Option(storage)
		}
	case *InventoryTransaction:
		transformInventoryTransactionItemBlockRuntimeIDs(pk, transformItemStack)
	case *ItemStackRequest:
		transformStackRequestItemBlockRuntimeIDs(pk.Requests, transformItemStack)
	case *MobArmourEquipment:
		transformItemStack(&pk.Helmet.Stack)
		transformItemStack(&pk.Chestplate.Stack)
		transformItemStack(&pk.Leggings.Stack)
		transformItemStack(&pk.Boots.Stack)
		transformItemStack(&pk.Body.Stack)
	case *MobEquipment:
		transformItemStack(&pk.NewItem.Stack)
	case *PlayerAuthInput:
		if inputFlagSet(pk, InputFlagPerformItemInteraction) {
			transformItemStack(&pk.ItemInteractionData.HeldItem.Stack)
		}
		if inputFlagSet(pk, InputFlagPerformItemStackRequest) {
			transformStackRequestItemBlockRuntimeIDs(
				[]protocol.ItemStackRequest{pk.ItemStackRequest}, transformItemStack,
			)
		}
	}
}

func transformInventoryTransactionItemBlockRuntimeIDs(
	pk *InventoryTransaction, transform func(*protocol.ItemStack),
) {
	for i := range pk.Actions {
		transform(&pk.Actions[i].OldItem.Stack)
		transform(&pk.Actions[i].NewItem.Stack)
	}
	switch data := pk.TransactionData.(type) {
	case *protocol.UseItemTransactionData:
		transform(&data.HeldItem.Stack)
	case *protocol.UseItemOnEntityTransactionData:
		transform(&data.HeldItem.Stack)
	case *protocol.ReleaseItemTransactionData:
		transform(&data.HeldItem.Stack)
	}
}

func transformStackRequestItemBlockRuntimeIDs(
	requests []protocol.ItemStackRequest, transform func(*protocol.ItemStack),
) {
	for i := range requests {
		for _, action := range requests[i].Actions {
			if results, ok := action.(*protocol.CraftResultsDeprecatedStackRequestAction); ok {
				for j := range results.ResultItems {
					transform(&results.ResultItems[j])
				}
			}
		}
	}
}

func transformRecipeItemBlockRuntimeIDs(
	recipes []protocol.Recipe, transform func(*protocol.ItemStack),
) {
	transformOutput := func(output []protocol.ItemStack) {
		for i := range output {
			transform(&output[i])
		}
	}
	for _, recipe := range recipes {
		switch recipe := recipe.(type) {
		case *protocol.ShapelessRecipe:
			transformOutput(recipe.Output)
		case *protocol.ShulkerBoxRecipe:
			transformOutput(recipe.Output)
		case *protocol.ShapelessChemistryRecipe:
			transformOutput(recipe.Output)
		case *protocol.ShapedRecipe:
			transformOutput(recipe.Output)
		case *protocol.ShapedChemistryRecipe:
			transformOutput(recipe.Output)
		case *protocol.SmithingTransformRecipe:
			transform(&recipe.Result)
		}
	}
}

func transformBlockChanges(entries []protocol.BlockChangeEntry, transform func(uint32) uint32) {
	for i := range entries {
		transformBlockRuntimeID(&entries[i].BlockRuntimeID, transform)
	}
}

func transformBlockRuntimeID(runtimeID *uint32, transform func(uint32) uint32) {
	*runtimeID = transform(*runtimeID)
}

func transformSignedBlockRuntimeID(runtimeID *int32, transform func(uint32) uint32) {
	*runtimeID = int32(transform(uint32(*runtimeID)))
}

func transformCrackBlockEvent(pk *LevelEvent, transform func(uint32) uint32) {
	const runtimeIDMask = uint32(0x00ffffff)

	data := uint32(pk.EventData)
	face, runtimeID := uint8(data>>24), data&runtimeIDMask
	transformed := transform(runtimeID)
	if transformed <= runtimeIDMask {
		pk.EventData = int32(uint32(face)<<24 | transformed)
		return
	}
	if eventType, ok := crackBlockEventType(face); ok {
		pk.EventType = eventType
		pk.EventData = int32(transformed)
	}
}

func crackBlockEventType(face uint8) (int32, bool) {
	switch face {
	case 0:
		return LevelEventParticlesCrackBlockDown, true
	case 1:
		return LevelEventParticlesCrackBlockUp, true
	case 2:
		return LevelEventParticlesCrackBlockNorth, true
	case 3:
		return LevelEventParticlesCrackBlockSouth, true
	case 4:
		return LevelEventParticlesCrackBlockWest, true
	case 5:
		return LevelEventParticlesCrackBlockEast, true
	default:
		return 0, false
	}
}

func inputFlagSet(pk *PlayerAuthInput, flag int) bool {
	return pk.InputData.Len() > flag && pk.InputData.Load(flag)
}

func levelEventUsesBlockRuntimeID(eventType int32) bool {
	const (
		legacyParticleTerrain     = LevelEventParticleLegacyEvent | 20
		legacyParticleFallingDust = LevelEventParticleLegacyEvent | 32
		legacyParticleBrushDust   = LevelEventParticleLegacyEvent | 85
	)

	switch eventType {
	case LevelEventParticlesDestroyBlock,
		LevelEventParticlesCropEaten,
		LevelEventParticlesDestroyArmorStand,
		LevelEventParticlesDestroyBlockNoSound,
		LevelEventParticlesCrackBlockDown,
		LevelEventParticlesCrackBlockUp,
		LevelEventParticlesCrackBlockNorth,
		LevelEventParticlesCrackBlockSouth,
		LevelEventParticlesCrackBlockWest,
		LevelEventParticlesCrackBlockEast,
		legacyParticleTerrain,
		legacyParticleFallingDust,
		legacyParticleBrushDust:
		return true
	default:
		return false
	}
}

func levelSoundEventUsesBlockRuntimeID(soundType string) bool {
	switch soundType {
	case SoundEventStep, SoundEventBreak, SoundEventLand,
		SoundEventDoorOpen, SoundEventDoorClose,
		SoundEventTrapdoorOpen, SoundEventTrapdoorClose,
		SoundEventFenceGateOpen, SoundEventFenceGateClose,
		SoundEventPlace, SoundEventHit, SoundEventItemUseOn:
		return true
	default:
		return false
	}
}
