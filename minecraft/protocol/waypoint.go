package protocol

import (
	"image/color"

	"github.com/go-gl/mathgl/mgl32"
	"github.com/google/uuid"
)

// LocatorBarWaypoint represents a waypoint entry in the locator bar packet.
type LocatorBarWaypoint struct {
	// GroupHandle is the UUID handle for the waypoint group.
	GroupHandle WaypointGroupWaypointHandle
	// Waypoint contains the waypoint data.
	Waypoint ServerWaypoint
	// Action determines the action for this waypoint. It is one of the WaypointAction constants.
	Action ServerWaypointGroupAction
}

// Marshal reads or writes LocatorBarWaypoint using its canonical wire layout.
func (x *LocatorBarWaypoint) Marshal(io IO) {
	x.GroupHandle.Marshal(io)
	x.Waypoint.Marshal(io)
	x.Action.Marshal(io)
}

// ServerWaypoint holds optional data for a locator bar waypoint.
type ServerWaypoint struct {
	// UpdateFlag is a bitmask indicating which optional fields are set.
	UpdateFlag uint32
	// Visible determines whether the waypoint is shown.
	Visible Optional[bool]
	// WorldPosition is the position and dimension of the waypoint.
	WorldPosition Optional[WorldPosition]
	// TexturePath is the resource path for the waypoint icon texture.
	TexturePath Optional[string]
	// IconSize is the size of the waypoint icon.
	IconSize Optional[mgl32.Vec2]
	// Colour is the RGB colour used to tint the waypoint icon.
	Colour Optional[color.RGBA]
	// ClientPositionAuthority determines whether the client has authority over the waypoint position.
	ClientPositionAuthority Optional[bool]
	// ActorUniqueID is the unique ID of the entity the waypoint tracks.
	ActorUniqueID Optional[int64]
}

// Marshal reads or writes ServerWaypoint using its canonical wire layout.
func (x *ServerWaypoint) Marshal(io IO) {
	io.Uint32(&x.UpdateFlag)
	OptionalFunc(io, &x.Visible, io.Bool)
	OptionalMarshaler(io, &x.WorldPosition)
	OptionalFunc(io, &x.TexturePath, io.String)
	OptionalFunc(io, &x.IconSize, io.Vec2)
	OptionalFunc(io, &x.Colour, io.RGBA)
	OptionalFunc(io, &x.ClientPositionAuthority, io.Bool)
	OptionalFunc(io, &x.ActorUniqueID, io.ActorUniqueID)
}

type ServerWaypointGroupAction uint8

const (
	WaypointActionNone   ServerWaypointGroupAction = 0
	WaypointActionAdd    ServerWaypointGroupAction = 1
	WaypointActionRemove ServerWaypointGroupAction = 2
	WaypointActionUpdate ServerWaypointGroupAction = 3
)

// Marshal reads or writes ServerWaypointGroupAction through its uint8 wire encoding.
func (x *ServerWaypointGroupAction) Marshal(io IO) { io.Uint8((*uint8)(x)) }

type WaypointGroupWaypointHandle struct {
	UUID uuid.UUID
}

// Marshal reads or writes WaypointGroupWaypointHandle using its canonical wire layout.
func (x *WaypointGroupWaypointHandle) Marshal(io IO) {
	io.UUID(&x.UUID)
}
