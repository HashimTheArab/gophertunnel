package packet

import (
	"github.com/go-gl/mathgl/mgl32"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const (
	ActorEventTypeNone                             protocol.ActorEventType = 0
	ActorEventJump                                 protocol.ActorEventType = 1
	ActorEventHurt                                 protocol.ActorEventType = 2
	ActorEventDeath                                protocol.ActorEventType = 3
	ActorEventStartAttacking                       protocol.ActorEventType = 4
	ActorEventStopAttacking                        protocol.ActorEventType = 5
	ActorEventTamingFailed                         protocol.ActorEventType = 6
	ActorEventTamingSucceeded                      protocol.ActorEventType = 7
	ActorEventShakeWetness                         protocol.ActorEventType = 8
	ActorEventEatGrass                             protocol.ActorEventType = 10
	ActorEventFishhookBubble                       protocol.ActorEventType = 11
	ActorEventFishhookFishPosition                 protocol.ActorEventType = 12
	ActorEventFishhookHookTime                     protocol.ActorEventType = 13
	ActorEventFishhookTease                        protocol.ActorEventType = 14
	ActorEventSquidFleeing                         protocol.ActorEventType = 15
	ActorEventZombieConverting                     protocol.ActorEventType = 16
	ActorEventPlayAmbient                          protocol.ActorEventType = 17
	ActorEventSpawnAlive                           protocol.ActorEventType = 18
	ActorEventStartOfferFlower                     protocol.ActorEventType = 19
	ActorEventStopOfferFlower                      protocol.ActorEventType = 20
	ActorEventLoveHearts                           protocol.ActorEventType = 21
	ActorEventVillagerAngry                        protocol.ActorEventType = 22
	ActorEventVillagerHappy                        protocol.ActorEventType = 23
	ActorEventWitchHatMagic                        protocol.ActorEventType = 24
	ActorEventFireworksExplode                     protocol.ActorEventType = 25
	ActorEventInLoveHearts                         protocol.ActorEventType = 26
	ActorEventSilverfishMergeAnimation             protocol.ActorEventType = 27
	ActorEventGuardianAttackSound                  protocol.ActorEventType = 28
	ActorEventDrinkPotion                          protocol.ActorEventType = 29
	ActorEventThrowPotion                          protocol.ActorEventType = 30
	ActorEventCartWithPrimeTNT                     protocol.ActorEventType = 31
	ActorEventPrimeCreeper                         protocol.ActorEventType = 32
	ActorEventAirSupply                            protocol.ActorEventType = 33
	ActorEventAddPlayerLevels                      protocol.ActorEventType = 34
	ActorEventGuardianMiningFatigue                protocol.ActorEventType = 35
	ActorEventAgentSwingArm                        protocol.ActorEventType = 36
	ActorEventDragonStartDeathAnim                 protocol.ActorEventType = 37
	ActorEventGroundDust                           protocol.ActorEventType = 38
	ActorEventShake                                protocol.ActorEventType = 39
	ActorEventTypeFeed                             protocol.ActorEventType = 57
	ActorEventTypeBabyAge                          protocol.ActorEventType = 60
	ActorEventTypeInstantDeath                     protocol.ActorEventType = 61
	ActorEventTypeNotifyTrade                      protocol.ActorEventType = 62
	ActorEventTypeLeashDestroyed                   protocol.ActorEventType = 63
	ActorEventTypeCaravanUpdated                   protocol.ActorEventType = 64
	ActorEventTypeTalismanActivate                 protocol.ActorEventType = 65
	ActorEventTypeDeprecatedUpdateStructureFeature protocol.ActorEventType = 66
	ActorEventTypePlayerSpawnedMob                 protocol.ActorEventType = 67
	ActorEventTypePuke                             protocol.ActorEventType = 68
	ActorEventTypeUpdateStackSize                  protocol.ActorEventType = 69
	ActorEventTypeStartSwimming                    protocol.ActorEventType = 70
	ActorEventTypeBalloonPop                       protocol.ActorEventType = 71
	ActorEventTypeTreasureHunt                     protocol.ActorEventType = 72
	ActorEventTypeSummonAgent                      protocol.ActorEventType = 73
	ActorEventTypeFinishedChargingItem             protocol.ActorEventType = 74
	ActorEventTypeActorGrowUp                      protocol.ActorEventType = 76
	ActorEventTypeVibrationDetected                protocol.ActorEventType = 77
	ActorEventTypeDrinkMilk                        protocol.ActorEventType = 78
	ActorEventTypeShakeWetnessStop                 protocol.ActorEventType = 79
	ActorEventTypeKineticDamageDealt               protocol.ActorEventType = 80
	ActorEventTypeHurtWithoutReceivingDamage       protocol.ActorEventType = 81
)

// ActorEvent is sent by the server when a particular event happens that has to do with an entity. Some of
// these events are entity-specific, for example a wolf shaking itself dry, but others are used for each
// entity, such as dying.
type ActorEvent struct {
	// EntityRuntimeID is the runtime ID of the entity. The runtime ID is unique for each world session, and
	// entities are generally identified in packets using this runtime ID.
	EntityRuntimeID uint64
	// EntityRuntimeID is the runtime ID of the entity. The runtime ID is unique for each world session, and
	// entities are generally identified in packets using this runtime ID.
	EventType protocol.ActorEventType
	// EventType is the ID of the event to be called. It is one of the constants that can be found above.
	EventData int32
	// FireAtPosition is the position in the same world at which the event should fire. If this is not present,
	// the position entity will be used instead.
	FireAtPosition protocol.Optional[mgl32.Vec3]
}

// ID ...
func (*ActorEvent) ID() uint32 {
	return IDActorEvent
}

func (pk *ActorEvent) Marshal(io protocol.IO) {
	io.ActorRuntimeID(&pk.EntityRuntimeID)
	pk.EventType.Marshal(io)
	io.Varint32(&pk.EventData)
	protocol.OptionalFunc(io, &pk.FireAtPosition, io.Vec3)
}
