package protocol

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
