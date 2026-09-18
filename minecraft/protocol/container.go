package protocol

type ContainerEnumName uint8

const (
	ContainerAnvilInput                      ContainerEnumName = 0
	ContainerAnvilMaterial                   ContainerEnumName = 1
	ContainerAnvilResultPreview              ContainerEnumName = 2
	ContainerSmithingTableInput              ContainerEnumName = 3
	ContainerSmithingTableMaterial           ContainerEnumName = 4
	ContainerSmithingTableResultPreview      ContainerEnumName = 5
	ContainerArmor                           ContainerEnumName = 6
	ContainerLevelEntity                     ContainerEnumName = 7
	ContainerBeaconPayment                   ContainerEnumName = 8
	ContainerBrewingStandInput               ContainerEnumName = 9
	ContainerBrewingStandResult              ContainerEnumName = 10
	ContainerBrewingStandFuel                ContainerEnumName = 11
	ContainerCombinedHotBarAndInventory      ContainerEnumName = 12
	ContainerCraftingInput                   ContainerEnumName = 13
	ContainerCraftingOutputPreview           ContainerEnumName = 14
	ContainerRecipeConstruction              ContainerEnumName = 15
	ContainerRecipeNature                    ContainerEnumName = 16
	ContainerRecipeItems                     ContainerEnumName = 17
	ContainerRecipeSearch                    ContainerEnumName = 18
	ContainerRecipeSearchBar                 ContainerEnumName = 19
	ContainerRecipeEquipment                 ContainerEnumName = 20
	ContainerRecipeBook                      ContainerEnumName = 21
	ContainerEnchantingInput                 ContainerEnumName = 22
	ContainerEnchantingMaterial              ContainerEnumName = 23
	ContainerFurnaceFuel                     ContainerEnumName = 24
	ContainerFurnaceIngredient               ContainerEnumName = 25
	ContainerFurnaceResult                   ContainerEnumName = 26
	ContainerHorseEquip                      ContainerEnumName = 27
	ContainerHotBar                          ContainerEnumName = 28
	ContainerInventory                       ContainerEnumName = 29
	ContainerShulkerBox                      ContainerEnumName = 30
	ContainerTradeIngredientOne              ContainerEnumName = 31
	ContainerTradeIngredientTwo              ContainerEnumName = 32
	ContainerTradeResultPreview              ContainerEnumName = 33
	ContainerOffhand                         ContainerEnumName = 34
	ContainerCompoundCreatorInput            ContainerEnumName = 35
	ContainerCompoundCreatorOutputPreview    ContainerEnumName = 36
	ContainerElementConstructorOutputPreview ContainerEnumName = 37
	ContainerMaterialReducerInput            ContainerEnumName = 38
	ContainerMaterialReducerOutput           ContainerEnumName = 39
	ContainerLabTableInput                   ContainerEnumName = 40
	ContainerLoomInput                       ContainerEnumName = 41
	ContainerLoomDye                         ContainerEnumName = 42
	ContainerLoomMaterial                    ContainerEnumName = 43
	ContainerLoomResultPreview               ContainerEnumName = 44
	ContainerBlastFurnaceIngredient          ContainerEnumName = 45
	ContainerSmokerIngredient                ContainerEnumName = 46
	ContainerTradeTwoIngredientOne           ContainerEnumName = 47
	ContainerTradeTwoIngredientTwo           ContainerEnumName = 48
	ContainerTradeTwoResultPreview           ContainerEnumName = 49
	ContainerGrindstoneInput                 ContainerEnumName = 50
	ContainerGrindstoneAdditional            ContainerEnumName = 51
	ContainerGrindstoneResultPreview         ContainerEnumName = 52
	ContainerStonecutterInput                ContainerEnumName = 53
	ContainerStonecutterResultPreview        ContainerEnumName = 54
	ContainerCartographyInput                ContainerEnumName = 55
	ContainerCartographyAdditional           ContainerEnumName = 56
	ContainerCartographyResultPreview        ContainerEnumName = 57
	ContainerBarrel                          ContainerEnumName = 58
	ContainerCursor                          ContainerEnumName = 59
	ContainerCreatedOutput                   ContainerEnumName = 60
	ContainerSmithingTableTemplate           ContainerEnumName = 61
	ContainerCrafterLevelEntity              ContainerEnumName = 62
	ContainerDynamic                         ContainerEnumName = 63
	ContainerRecipeFood                      ContainerEnumName = 64
	ContainerRecipeBlocks                    ContainerEnumName = 65
	ContainerRecipeFurnaceItems              ContainerEnumName = 66
)

// Marshal reads or writes ContainerEnumName through its uint8 wire encoding.
func (x *ContainerEnumName) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type ContainerMixDataEntry struct {
	FromItemID    int32
	ReagentItemID int32
	ToItemID      int32
}

// Marshal reads or writes ContainerMixDataEntry using its canonical wire layout.
func (x *ContainerMixDataEntry) Marshal(io IO) {
	io.Varint32(&x.FromItemID)
	io.Varint32(&x.ReagentItemID)
	io.Varint32(&x.ToItemID)
}

// FullContainerName contains information required to identify a container in a
// StackRequestSlotInfo.
type FullContainerName struct {
	// ContainerName is the ID of the container that the slot was in.
	ContainerName ContainerEnumName
	// DynamicID is the ID of the container if it is dynamic. If the container is not dynamic, this
	// field should be left empty. A non-optional value of 0 is assumed to be non-empty.
	DynamicID Optional[uint32]
}

// Marshal reads or writes FullContainerName using its canonical wire layout.
func (x *FullContainerName) Marshal(io IO) {
	x.ContainerName.Marshal(io)
	OptionalFunc(io, &x.DynamicID, io.Uint32)
}
