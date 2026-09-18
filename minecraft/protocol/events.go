// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package protocol

type CodeBuilderScoreboard struct {
	ObjectiveName string
	Score         int32
}

func (*CodeBuilderScoreboard) tagEventData() uint32 { return 19 }

// Marshal reads or writes CodeBuilderScoreboard using its canonical wire layout.
func (x *CodeBuilderScoreboard) Marshal(io IO) {
	io.StringLimits(&x.ObjectiveName, 0, 256)
	io.Varint32(&x.Score)
}

type ComposterUsed struct {
	BlockInteractionType MinecraftEventingPOIBlockInteractionType
	ItemID               int32
}

func (*ComposterUsed) tagEventData() uint32 { return 11 }

// Marshal reads or writes ComposterUsed using its canonical wire layout.
func (x *ComposterUsed) Marshal(io IO) {
	x.BlockInteractionType.Marshal(io)
	io.Varint32(&x.ItemID)
}

// Event represents an object that holds data specific to an event. The data it holds depends on the
// type.
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
			return new(POICauldronUsed)
		case 11:
			return new(ComposterUsed)
		case 12:
			return new(BellUsed)
		case 13:
			return new(ActorDefinition)
		case 14:
			return new(RaidUpdate)
		case 15:
			return new(TargetBlockHit)
		case 16:
			return new(PiglinBarter)
		case 17:
			return new(PlayerWaxedOrUnwaxedCopper)
		case 18:
			return new(CodeBuilderRuntimeAction)
		case 19:
			return new(CodeBuilderScoreboard)
		case 20:
			return new(ItemUsed)
		case 21:
			return new(Empty)
		}
		return nil
	})
}

type ItemUsed struct {
	ItemID    int16
	ItemAux   int32
	UseMethod int32
	UseCount  int32
}

func (*ItemUsed) tagEventData() uint32 { return 20 }

// Marshal reads or writes ItemUsed using its canonical wire layout.
func (x *ItemUsed) Marshal(io IO) {
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

type POICauldronUsed struct {
	BlockInteractionType MinecraftEventingPOIBlockInteractionType
	ItemID               int32
}

func (*POICauldronUsed) tagEventData() uint32 { return 10 }

// Marshal reads or writes POICauldronUsed using its canonical wire layout.
func (x *POICauldronUsed) Marshal(io IO) {
	x.BlockInteractionType.Marshal(io)
	io.Varint32(&x.ItemID)
}

type PiglinBarter struct {
	ItemID                      int32
	WasTargetingBarteringPlayer bool
}

func (*PiglinBarter) tagEventData() uint32 { return 16 }

// Marshal reads or writes PiglinBarter using its canonical wire layout.
func (x *PiglinBarter) Marshal(io IO) {
	io.Varint32(&x.ItemID)
	io.Bool(&x.WasTargetingBarteringPlayer)
}
