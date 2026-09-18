package protocol

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

// Event represents an object that holds data specific to an event. The data it holds depends on the type.
type EventData interface {
	Marshaler
	tagEventData() uint32
}

// MarshalEventData reads or writes the EventData union using its canonical wire layout.
func MarshalEventData(io IO, x *EventData) {
	Union(io, x, io.Varuint32, EventData.tagEventData, func(tag uint32) EventData {
		switch tag {
		case 0:
			return new(Achievement)
		case 1:
			return new(Interaction)
		case 2:
			return new(PortalCreated)
		case 3:
			return new(PortalUsed)
		case 4:
			return new(MobKilled)
		case 5:
			return new(CauldronUsed)
		case 6:
			return new(PlayerDied)
		case 7:
			return new(BossKilled)
		case 8:
			return new(SlashCommand)
		case 9:
			return new(MobBorn)
		case 10:
			return new(CauldronInteractEvent)
		case 11:
			return new(ComposterInteractEvent)
		case 12:
			return new(BellUsed)
		case 13:
			return new(ActorDefinition)
		case 14:
			return new(RaidUpdate)
		case 15:
			return new(TargetBlockHit)
		case 16:
			return new(PiglinBarterEvent)
		case 17:
			return new(PlayerWaxedOrUnwaxedCopper)
		case 18:
			return new(CodeBuilderRuntimeAction)
		case 19:
			return new(CodeBuilderScoreboardEvent)
		case 20:
			return new(ItemUsedEvent)
		case 21:
			return new(Empty)
		}
		return nil
	})
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
