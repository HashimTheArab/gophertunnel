package protocol

// ArmorSlotAndDamagePair represents an entry for a single piece of armour that should be damaged.
type ArmorSlotAndDamagePair struct {
	// ArmourSlot is the index of the armour slot to damage.
	ArmourSlot LegacyArmorSlot
	// Damage is the amount of damage to apply to the armour in the specified slot.
	Damage int16
}

// Marshal reads or writes ArmorSlotAndDamagePair using its canonical wire layout.
func (x *ArmorSlotAndDamagePair) Marshal(io IO) {
	x.ArmourSlot.Marshal(io)
	io.Int16(&x.Damage)
}

type PlayerActionType int32

const (
	PlayerActionTypeUnknown                PlayerActionType = -1
	PlayerActionStartBreak                 PlayerActionType = 0
	PlayerActionAbortBreak                 PlayerActionType = 1
	PlayerActionStopBreak                  PlayerActionType = 2
	PlayerActionGetUpdatedBlock            PlayerActionType = 3
	PlayerActionDropItem                   PlayerActionType = 4
	PlayerActionStartSleeping              PlayerActionType = 5
	PlayerActionStopSleeping               PlayerActionType = 6
	PlayerActionRespawn                    PlayerActionType = 7
	PlayerActionJump                       PlayerActionType = 8
	PlayerActionStartSprint                PlayerActionType = 9
	PlayerActionStopSprint                 PlayerActionType = 10
	PlayerActionStartSneak                 PlayerActionType = 11
	PlayerActionStopSneak                  PlayerActionType = 12
	PlayerActionCreativePlayerDestroyBlock PlayerActionType = 13
	PlayerActionDimensionChangeDone        PlayerActionType = 14
	PlayerActionStartGlide                 PlayerActionType = 15
	PlayerActionStopGlide                  PlayerActionType = 16
	PlayerActionBuildDenied                PlayerActionType = 17
	PlayerActionCrackBreak                 PlayerActionType = 18
	PlayerActionChangeSkin                 PlayerActionType = 19
	PlayerActionSetEnchantmentSeed         PlayerActionType = 20
	PlayerActionStartSwimming              PlayerActionType = 21
	PlayerActionStopSwimming               PlayerActionType = 22
	PlayerActionStartSpinAttack            PlayerActionType = 23
	PlayerActionStopSpinAttack             PlayerActionType = 24
	PlayerActionInteractWithBlock          PlayerActionType = 25
	PlayerActionPredictDestroyBlock        PlayerActionType = 26
	PlayerActionContinueDestroyBlock       PlayerActionType = 27
	PlayerActionStartItemUseOn             PlayerActionType = 28
	PlayerActionStopItemUseOn              PlayerActionType = 29
	PlayerActionHandledTeleport            PlayerActionType = 30
	PlayerActionMissedSwing                PlayerActionType = 31
	PlayerActionStartCrawling              PlayerActionType = 32
	PlayerActionStopCrawling               PlayerActionType = 33
	PlayerActionStartFlying                PlayerActionType = 34
	PlayerActionStopFlying                 PlayerActionType = 35
	PlayerActionReceivedServerData         PlayerActionType = 36
	PlayerActionStartUsingItem             PlayerActionType = 37
	PlayerActionInternalUpdate             PlayerActionType = 38
	PlayerActionCount                      PlayerActionType = 39
)

// Marshal reads or writes PlayerActionType through its int32 wire encoding.
func (x *PlayerActionType) Marshal(io IO) { io.Varint32((*int32)(x)) }

// PlayerBlockAction ...
type PlayerBlockActionData struct {
	// Action is the action to be performed, and is one of the constants listed above.
	Action PlayerActionType
	// BlockPos is the position of the block that was interacted with.
	BlockPos BlockPos
	// Face is the face of the block that was interacted with.
	Face int32
}

// Marshal reads or writes PlayerBlockActionData using its canonical wire layout.
func (x *PlayerBlockActionData) Marshal(io IO) {
	x.Action.Marshal(io)
	x.BlockPos.Marshal(io)
	io.Varint32(&x.Face)
}

type PlayerDied struct {
	InstigatorEntityID   int32
	InstigatorMobVariant int32
	DamageSource         int32
	DiedInRaid           bool
}

func (*PlayerDied) tagEventData() uint32 { return 6 }

// Marshal reads or writes PlayerDied using its canonical wire layout.
func (x *PlayerDied) Marshal(io IO) {
	io.Varint32(&x.InstigatorEntityID)
	io.Varint32(&x.InstigatorMobVariant)
	io.Varint32(&x.DamageSource)
	io.Bool(&x.DiedInRaid)
}

type PlayerListData interface {
	Marshaler
	tagPlayerListData() uint32
}

// MarshalPlayerListData reads or writes the PlayerListData union using its canonical wire layout.
func MarshalPlayerListData(io IO, x *PlayerListData) {
	Union(io, x, io.Varuint32, PlayerListData.tagPlayerListData, func(tag uint32) PlayerListData {
		switch tag {
		case 0:
			return new(RemoveEntry)
		case 1:
			return new(AddEntry)
		}
		return nil
	})
}

type PlayerListPacketType uint8

const (
	PlayerListActionRemove PlayerListPacketType = 1
)

// Marshal reads or writes PlayerListPacketType through its uint8 wire encoding.
func (x *PlayerListPacketType) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type PlayerLocationData interface {
	Marshaler
	tagPlayerLocationData() uint32
}

// MarshalPlayerLocationData reads or writes the PlayerLocationData union using its canonical wire layout.
func MarshalPlayerLocationData(io IO, x *PlayerLocationData) {
	Union(io, x, io.Varuint32, PlayerLocationData.tagPlayerLocationData, func(tag uint32) PlayerLocationData {
		switch tag {
		case 0:
			return new(CoordinatesLocation)
		case 1:
			return new(HiddenLocation)
		}
		return nil
	})
}

type PlayerLocationType int32

// Marshal reads or writes PlayerLocationType through its int32 wire encoding.
func (x *PlayerLocationType) Marshal(io IO) { io.Varint32((*int32)(x)) }

type PlayerPartyInfo struct {
	PartyID       string
	IsPartyLeader bool
}

// Marshal reads or writes PlayerPartyInfo using its canonical wire layout.
func (x *PlayerPartyInfo) Marshal(io IO) {
	io.StringLimits(&x.PartyID, 0, 49)
	io.Bool(&x.IsPartyLeader)
}

type PlayerPermissionLevel int8

// Marshal reads or writes PlayerPermissionLevel through its int8 wire encoding.
func (x *PlayerPermissionLevel) Marshal(io IO) { io.Int8((*int8)(x)) }

type PlayerPositionModeComponentPositionMode uint8

// Marshal reads or writes PlayerPositionModeComponentPositionMode through its uint8 wire encoding.
func (x *PlayerPositionModeComponentPositionMode) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type PlayerRespawnState uint8

// Marshal reads or writes PlayerRespawnState through its uint8 wire encoding.
func (x *PlayerRespawnState) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type PlayerScoreboardID struct {
	PlayerUniqueID int64
}

// Marshal reads or writes PlayerScoreboardID using its canonical wire layout.
func (x *PlayerScoreboardID) Marshal(io IO) {
	io.Varint64(&x.PlayerUniqueID)
}

type PlayerUpdateEntityOverridesData interface {
	Marshaler
	tagPlayerUpdateEntityOverridesData() uint8
}

// MarshalPlayerUpdateEntityOverridesData reads or writes the PlayerUpdateEntityOverridesData union using its canonical wire layout.
func MarshalPlayerUpdateEntityOverridesData(io IO, x *PlayerUpdateEntityOverridesData) {
	Union(io, x, io.Uint8, PlayerUpdateEntityOverridesData.tagPlayerUpdateEntityOverridesData, func(tag uint8) PlayerUpdateEntityOverridesData {
		switch tag {
		case 0:
			return new(ClearOverride)
		case 1:
			return new(RemoveOverride)
		case 2:
			return new(IntOverride)
		case 3:
			return new(FloatOverride)
		}
		return nil
	})
}

type PlayerVideoCaptureData interface {
	Marshaler
	tagPlayerVideoCaptureData() uint8
}

// MarshalPlayerVideoCaptureData reads or writes the PlayerVideoCaptureData union using its canonical wire layout.
func MarshalPlayerVideoCaptureData(io IO, x *PlayerVideoCaptureData) {
	Union(io, x, io.Uint8, PlayerVideoCaptureData.tagPlayerVideoCaptureData, func(tag uint8) PlayerVideoCaptureData {
		switch tag {
		case 0:
			return new(StopVideoCapture)
		case 1:
			return new(StartVideoCapture)
		}
		return nil
	})
}

type PlayerWaxedOrUnwaxedCopper struct {
	PlayerWaxedOrUnwaxedCopperBlockID int32
}

func (*PlayerWaxedOrUnwaxedCopper) tagEventData() uint32 { return 17 }

// Marshal reads or writes PlayerWaxedOrUnwaxedCopper using its canonical wire layout.
func (x *PlayerWaxedOrUnwaxedCopper) Marshal(io IO) {
	io.Varint32(&x.PlayerWaxedOrUnwaxedCopperBlockID)
}

// SyncedPlayerMovementSettings represents the different server authoritative movement settings. These control
// how the client will provide input to the server.
type SyncedPlayerMovementSettings struct {
	// RewindHistorySize is the amount of history to keep at maximum.
	RewindHistorySize int32
	// ServerAuthoritativeBlockBreaking specifies if block breaking should be sent through packet.PlayerAuthInput
	// or not.
	ServerAuthoritativeBlockBreaking bool
}

// Marshal reads or writes SyncedPlayerMovementSettings using its canonical wire layout.
func (x *SyncedPlayerMovementSettings) Marshal(io IO) {
	io.Varint32(&x.RewindHistorySize)
	io.Bool(&x.ServerAuthoritativeBlockBreaking)
}
