package protocol

import (
	"github.com/google/uuid"
)

// ServerConfigurationGatheringsConfigurationJoinInfo contains information about the gathering (experience)
// the player is joining.
type GatheringJoinInfo struct {
	// ExperienceID is the UUID of the experience.
	ExperienceID uuid.UUID
	// ExperienceName is the name of the experience.
	ExperienceName string
	// ExperienceWorldID is the UUID of the experience world.
	ExperienceWorldID Optional[uuid.UUID]
	// ExperienceWorldName is the world name of the experience.
	ExperienceWorldName Optional[string]
	// CreatorID is the ID of the creator.
	CreatorID string
	// TargetID is the session ID of the experience.
	TargetID Optional[uuid.UUID]
	// ScenarioID is the scenario ID of experience.
	ScenarioID Optional[string]
	// ServerID is the server identifier.
	ServerID Optional[string]
}

// Marshal reads or writes GatheringJoinInfo using its canonical wire layout.
func (x *GatheringJoinInfo) Marshal(io IO) {
	io.UUID(&x.ExperienceID)
	io.StringLimits(&x.ExperienceName, 1, 29)
	OptionalFunc(io, &x.ExperienceWorldID, io.UUID)
	OptionalFunc(io, &x.ExperienceWorldName, func(value *string) {
		io.StringLimits(value, 1, 29)
	})
	io.StringLimits(&x.CreatorID, 1, 60)
	OptionalFunc(io, &x.TargetID, io.UUID)
	OptionalFunc(io, &x.ScenarioID, func(value *string) {
		io.StringLimits(value, 1, 100)
	})
	OptionalFunc(io, &x.ServerID, func(value *string) {
		io.StringLimits(value, 1, 100)
	})
}

// ServerConfigurationClientStoreEntryPointConfiguration contains information about the store entry point.
type StoreEntryPointInfo struct {
	// StoreID is the store identifier.
	StoreID string
	// StoreName is the store name.
	StoreName string
}

// Marshal reads or writes StoreEntryPointInfo using its canonical wire layout.
func (x *StoreEntryPointInfo) Marshal(io IO) {
	io.String(&x.StoreID)
	io.String(&x.StoreName)
}
