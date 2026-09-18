// Code generated from canonical protocol manifest v2. DO NOT EDIT.

package protocol

import "github.com/google/uuid"

type ServerConfigurationClientStoreEntryPointConfiguration struct {
	StoreID   string
	StoreName string
}

// Marshal reads or writes ServerConfigurationClientStoreEntryPointConfiguration using its canonical wire layout.
func (x *ServerConfigurationClientStoreEntryPointConfiguration) Marshal(io IO) {
	io.String(&x.StoreID)
	io.String(&x.StoreName)
}

type ServerConfigurationGatheringsConfigurationJoinInfo struct {
	ExperienceID        uuid.UUID
	ExperienceName      string
	ExperienceWorldID   Optional[uuid.UUID]
	ExperienceWorldName Optional[string]
	CreatorID           string
	TargetID            Optional[uuid.UUID]
	ScenarioID          Optional[string]
	ServerID            Optional[string]
}

// Marshal reads or writes ServerConfigurationGatheringsConfigurationJoinInfo using its canonical wire layout.
func (x *ServerConfigurationGatheringsConfigurationJoinInfo) Marshal(io IO) {
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
