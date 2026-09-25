package protocol

// BellUsedEvent is the event data sent when a bell is used.
type BellUsedEvent struct {
	// ItemID ...
	ItemID int32
}

func (*BellUsedEvent) tagEventData() uint32 { return 12 }

// Marshal reads or writes BellUsedEvent using its canonical wire layout.
func (x *BellUsedEvent) Marshal(io IO) {
	io.Varint32(&x.ItemID)
}

// BossKilledEvent is the event data sent when a boss dies.
type BossKilledEvent struct {
	// BossEntityUniqueID ...
	BossEntityUniqueID int64
	// PlayerPartySize ...
	PlayerPartySize int32
	// InteractionEntityType ...
	InteractionEntityType int32
}

func (*BossKilledEvent) tagEventData() uint32 { return 7 }

// Marshal reads or writes BossKilledEvent using its canonical wire layout.
func (x *BossKilledEvent) Marshal(io IO) {
	io.ActorUniqueID(&x.BossEntityUniqueID)
	io.Varint32(&x.PlayerPartySize)
	io.Varint32(&x.InteractionEntityType)
}

// CauldronInteractEvent is the event data sent when a cauldron is interacted with.
type CauldronInteractEvent struct {
	// BlockInteractionType ...
	BlockInteractionType MinecraftEventingPOIBlockInteractionType
	// ItemID ...
	ItemID int32
}

func (*CauldronInteractEvent) tagEventData() uint32 { return 10 }

// Marshal reads or writes CauldronInteractEvent using its canonical wire layout.
func (x *CauldronInteractEvent) Marshal(io IO) {
	x.BlockInteractionType.Marshal(io)
	io.Varint32(&x.ItemID)
}

// CauldronUsedEvent is the event data sent when a cauldron is used.
type CauldronUsedEvent struct {
	// Colour ...
	Colour uint32
	// PotionID ...
	PotionID int32
	// FillLevel ...
	FillLevel int32
}

func (*CauldronUsedEvent) tagEventData() uint32 { return 5 }

// Marshal reads or writes CauldronUsedEvent using its canonical wire layout.
func (x *CauldronUsedEvent) Marshal(io IO) {
	io.Varuint32(&x.Colour)
	io.Varint32(&x.PotionID)
	io.Varint32(&x.FillLevel)
}

// CodeBuilderRuntimeActionEvent is an event sent by the server when a code builder runtime action is
// performed.
type CodeBuilderRuntimeActionEvent struct {
	// Action ...
	Action string
}

func (*CodeBuilderRuntimeActionEvent) tagEventData() uint32 { return 18 }

// Marshal reads or writes CodeBuilderRuntimeActionEvent using its canonical wire layout.
func (x *CodeBuilderRuntimeActionEvent) Marshal(io IO) {
	io.StringLimits(&x.Action, 0, 16)
}

// CodeBuilderScoreboardEvent is an event sent by the server when a code builder scoreboard is updated.
type CodeBuilderScoreboardEvent struct {
	// ObjectiveName ...
	ObjectiveName string
	// Score ...
	Score int32
}

func (*CodeBuilderScoreboardEvent) tagEventData() uint32 { return 19 }

// Marshal reads or writes CodeBuilderScoreboardEvent using its canonical wire layout.
func (x *CodeBuilderScoreboardEvent) Marshal(io IO) {
	io.StringLimits(&x.ObjectiveName, 0, 256)
	io.Varint32(&x.Score)
}

// ComposterInteractEvent is the event data sent when a composter is interacted with.
type ComposterInteractEvent struct {
	// BlockInteractionType ...
	BlockInteractionType MinecraftEventingPOIBlockInteractionType
	// ItemID ...
	ItemID int32
}

func (*ComposterInteractEvent) tagEventData() uint32 { return 11 }

// Marshal reads or writes ComposterInteractEvent using its canonical wire layout.
func (x *ComposterInteractEvent) Marshal(io IO) {
	x.BlockInteractionType.Marshal(io)
	io.Varint32(&x.ItemID)
}

// ItemUsedEvent is when a player right clicks a item.
type ItemUsedEvent struct {
	ItemID    int16
	ItemAux   int32
	UseMethod int32
	UseCount  int32
}

func (*ItemUsedEvent) tagEventData() uint32 { return 20 }

// Marshal reads or writes ItemUsedEvent using its canonical wire layout.
func (x *ItemUsedEvent) Marshal(io IO) {
	io.Int16(&x.ItemID)
	io.Int32(&x.ItemAux)
	io.Int32(&x.UseMethod)
	io.Int32(&x.UseCount)
}

type LegacyTelemetryType int32

const (
	EventTypeAchievementAwarded             LegacyTelemetryType = 0
	EventTypeEntityInteract                 LegacyTelemetryType = 1
	EventTypePortalBuilt                    LegacyTelemetryType = 2
	EventTypePortalUsed                     LegacyTelemetryType = 3
	EventTypeMobKilled                      LegacyTelemetryType = 4
	EventTypeCauldronUsed                   LegacyTelemetryType = 5
	EventTypePlayerDied                     LegacyTelemetryType = 6
	EventTypeBossKilled                     LegacyTelemetryType = 7
	EventTypeAgentCommand                   LegacyTelemetryType = 8
	EventTypeAgentCreated                   LegacyTelemetryType = 9
	EventTypePatternRemoved                 LegacyTelemetryType = 10
	EventTypeSlashCommandExecuted           LegacyTelemetryType = 11
	EventTypeFishBucketed                   LegacyTelemetryType = 12
	EventTypeMobBorn                        LegacyTelemetryType = 13
	EventTypePetDied                        LegacyTelemetryType = 14
	EventTypeCauldronInteract               LegacyTelemetryType = 15
	EventTypeComposterInteract              LegacyTelemetryType = 16
	EventTypeBellUsed                       LegacyTelemetryType = 17
	EventTypeEntityDefinitionTrigger        LegacyTelemetryType = 18
	EventTypeRaidUpdate                     LegacyTelemetryType = 19
	EventTypeMovementAnomaly                LegacyTelemetryType = 20
	EventTypeMovementCorrected              LegacyTelemetryType = 21
	EventTypeExtractHoney                   LegacyTelemetryType = 22
	EventTypeTargetBlockHit                 LegacyTelemetryType = 23
	EventTypePiglinBarter                   LegacyTelemetryType = 24
	EventTypePlayerWaxedOrUnwaxedCopper     LegacyTelemetryType = 25
	EventTypeCodeBuilderRuntimeAction       LegacyTelemetryType = 26
	EventTypeCodeBuilderScoreboard          LegacyTelemetryType = 27
	EventTypeStriderRiddenInLavaInOverworld LegacyTelemetryType = 28
	EventTypeSneakCloseToSculkSensor        LegacyTelemetryType = 29
	EventTypeCarefulRestoration             LegacyTelemetryType = 30
	EventTypeItemUsed                       LegacyTelemetryType = 31
)

// Marshal reads or writes LegacyTelemetryType through its int32 wire encoding.
func (x *LegacyTelemetryType) Marshal(io IO) { io.Varint32((*int32)(x)) }

// MobBornEvent is the event data sent when a mob is born.
type MobBornEvent struct {
	// EntityType ...
	EntityType int32
	// Variant ...
	Variant int32
	// Colour ...
	Colour uint8
}

func (*MobBornEvent) tagEventData() uint32 { return 9 }

// Marshal reads or writes MobBornEvent using its canonical wire layout.
func (x *MobBornEvent) Marshal(io IO) {
	io.Varint32(&x.EntityType)
	io.Varint32(&x.Variant)
	io.Uint8(&x.Colour)
}

// MobKilledEvent is the event data sent when a mob is killed.
type MobKilledEvent struct {
	// KillerEntityUniqueID ...
	KillerEntityUniqueID int64
	// VictimEntityUniqueID ...
	VictimEntityUniqueID int64
	// KillerEntityType ...
	KillerEntityType ActorType
	// EntityDamageCause ...
	EntityDamageCause int32
	// VillagerTradeTier -1 if not a trading actor.
	VillagerTradeTier int32
	// VillagerDisplayName Empty if not a trading actor.
	VillagerDisplayName string
}

func (*MobKilledEvent) tagEventData() uint32 { return 4 }

// Marshal reads or writes MobKilledEvent using its canonical wire layout.
func (x *MobKilledEvent) Marshal(io IO) {
	io.ActorUniqueID(&x.KillerEntityUniqueID)
	io.ActorUniqueID(&x.VictimEntityUniqueID)
	x.KillerEntityType.Marshal(io)
	io.Varint32(&x.EntityDamageCause)
	io.Varint32(&x.VillagerTradeTier)
	io.StringLimits(&x.VillagerDisplayName, 0, 128)
}

// PiglinBarterEvent is called when a player drops gold ingots to a piglin to initiate a trade for an item.
type PiglinBarterEvent struct {
	// ItemID ...
	ItemID int32
	// WasTargetingBarteringPlayer ...
	WasTargetingBarteringPlayer bool
}

func (*PiglinBarterEvent) tagEventData() uint32 { return 16 }

// Marshal reads or writes PiglinBarterEvent using its canonical wire layout.
func (x *PiglinBarterEvent) Marshal(io IO) {
	io.Varint32(&x.ItemID)
	io.Bool(&x.WasTargetingBarteringPlayer)
}

// PlayerDiedEvent is the event data sent when a player dies.
type PlayerDiedEvent struct {
	// AttackerEntityID ...
	AttackerEntityID int32
	// AttackerVariant ...
	AttackerVariant int32
	// EntityDamageCause ...
	EntityDamageCause int32
	// InRaid ...
	InRaid bool
}

func (*PlayerDiedEvent) tagEventData() uint32 { return 6 }

// Marshal reads or writes PlayerDiedEvent using its canonical wire layout.
func (x *PlayerDiedEvent) Marshal(io IO) {
	io.Varint32(&x.AttackerEntityID)
	io.Varint32(&x.AttackerVariant)
	io.Varint32(&x.EntityDamageCause)
	io.Bool(&x.InRaid)
}

// PortalUsedEvent is the event data sent when a portal is used.
type PortalUsedEvent struct {
	// FromDimensionID ...
	FromDimensionID int32
	// ToDimensionID ...
	ToDimensionID int32
}

func (*PortalUsedEvent) tagEventData() uint32 { return 3 }

// Marshal reads or writes PortalUsedEvent using its canonical wire layout.
func (x *PortalUsedEvent) Marshal(io IO) {
	io.Varint32(&x.FromDimensionID)
	io.Varint32(&x.ToDimensionID)
}

// RaidUpdateEvent is an event used to update a raids progress client side.
type RaidUpdateEvent struct {
	// CurrentRaidWave ...
	CurrentRaidWave int32
	// TotalRaidWaves ...
	TotalRaidWaves int32
	// WonRaid ...
	WonRaid bool
}

func (*RaidUpdateEvent) tagEventData() uint32 { return 14 }

// Marshal reads or writes RaidUpdateEvent using its canonical wire layout.
func (x *RaidUpdateEvent) Marshal(io IO) {
	io.Varint32(&x.CurrentRaidWave)
	io.Varint32(&x.TotalRaidWaves)
	io.Bool(&x.WonRaid)
}

// TargetBlockHitEvent is an event used when a target block is hit by a arrow.
type TargetBlockHitEvent struct {
	// RedstoneLevel ...
	RedstoneLevel int32
}

func (*TargetBlockHitEvent) tagEventData() uint32 { return 15 }

// Marshal reads or writes TargetBlockHitEvent using its canonical wire layout.
func (x *TargetBlockHitEvent) Marshal(io IO) {
	io.Varint32(&x.RedstoneLevel)
}
