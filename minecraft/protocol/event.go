package protocol

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
			return new(PortalUsedEvent)
		case 4:
			return new(MobKilledEvent)
		case 5:
			return new(CauldronUsedEvent)
		case 6:
			return new(PlayerDiedEvent)
		case 7:
			return new(BossKilledEvent)
		case 8:
			return new(SlashCommand)
		case 9:
			return new(MobBornEvent)
		case 10:
			return new(CauldronInteractEvent)
		case 11:
			return new(ComposterInteractEvent)
		case 12:
			return new(BellUsedEvent)
		case 13:
			return new(ActorDefinition)
		case 14:
			return new(RaidUpdateEvent)
		case 15:
			return new(TargetBlockHitEvent)
		case 16:
			return new(PiglinBarterEvent)
		case 17:
			return new(PlayerWaxedOrUnwaxedCopper)
		case 18:
			return new(CodeBuilderRuntimeActionEvent)
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
