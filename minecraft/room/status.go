package room

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/p2p"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type Status struct {
	Joinability             string               `json:"Joinability,omitempty"`
	HostName                string               `json:"hostName,omitempty"`
	OwnerID                 string               `json:"ownerId,omitempty"`
	RakNetGUID              string               `json:"rakNetGUID"`
	Version                 string               `json:"version"`
	LevelID                 string               `json:"levelId"`
	WorldName               string               `json:"worldName"`
	WorldType               string               `json:"worldType"`
	Protocol                int32                `json:"protocol"`
	MemberCount             int                  `json:"MemberCount"`
	MaxMemberCount          int                  `json:"MaxMemberCount"`
	BroadcastSetting        p2p.BroadcastSetting `json:"BroadcastSetting"`
	LanGame                 bool                 `json:"LanGame"`
	IsEditorWorld           bool                 `json:"isEditorWorld"`
	TransportLayer          int                  `json:"TransportLayer"`
	OnlineCrossPlatformGame bool                 `json:"OnlineCrossPlatformGame"`
	CrossPlayDisabled       bool                 `json:"CrossPlayDisabled"`
	TitleID                 int64                `json:"TitleId"`
	SupportedConnections    []Connection         `json:"SupportedConnections"`
}

type Connection struct {
	ConnectionType int             `json:"ConnectionType"`
	HostIPAddress  string          `json:"HostIpAddress"`
	HostPort       uint16          `json:"HostPort"`
	NetherNetID    p2p.NetherNetID `json:"NetherNetId"`
	RakNetGUID     string          `json:"RakNetGUID,omitempty"`
	PmsgID         uuid.UUID       `json:"PmsgId,omitempty"`
}

// MarshalJSON encodes the discriminator-dependent connection shape used by
// vanilla Bedrock. Direct WebSocket signaling stores its network ID in the
// legacy RakNetGUID field, while JSON-RPC signaling uses NetherNetId and
// PmsgId.
func (c Connection) MarshalJSON() ([]byte, error) {
	type wireConnection struct {
		ConnectionType int              `json:"ConnectionType"`
		HostIPAddress  string           `json:"HostIpAddress"`
		HostPort       uint16           `json:"HostPort"`
		NetherNetID    *p2p.NetherNetID `json:"NetherNetId,omitempty"`
		RakNetGUID     string           `json:"RakNetGUID,omitempty"`
		PmsgID         *uuid.UUID       `json:"PmsgId,omitempty"`
	}
	wire := wireConnection{
		ConnectionType: c.ConnectionType,
		HostIPAddress:  c.HostIPAddress,
		HostPort:       c.HostPort,
	}
	switch c.ConnectionType {
	case p2p.ConnectionTypeSignalingOverWebSocket:
		wire.RakNetGUID = string(c.NetherNetID)
	case p2p.ConnectionTypeSignalingOverJSONRPC:
		wire.NetherNetID = &c.NetherNetID
		if c.PmsgID != uuid.Nil {
			wire.PmsgID = &c.PmsgID
		}
	default:
		if c.NetherNetID != "" {
			wire.NetherNetID = &c.NetherNetID
		}
		wire.RakNetGUID = c.RakNetGUID
		if c.PmsgID != uuid.Nil {
			wire.PmsgID = &c.PmsgID
		}
	}
	return json.Marshal(wire)
}

const (
	WorldTypeCreative = "Creative"
)

const (
	ConnectionTypeUPNP = 6
)

type StatusProvider interface {
	RoomStatus() Status
}

func NewStatusProvider(status Status) StatusProvider {
	return statusProvider{status: status}
}

type statusProvider struct{ status Status }

func (p statusProvider) RoomStatus() Status {
	return p.status
}

func DefaultStatus() Status {
	levelID := make([]byte, 8)
	_, _ = rand.Read(levelID)

	return Status{
		Joinability:             p2p.JoinabilityFriends,
		HostName:                "Gophertunnel",
		Version:                 protocol.CurrentVersion,
		LevelID:                 base64.StdEncoding.EncodeToString(levelID),
		WorldName:               "Room Listener",
		WorldType:               WorldTypeCreative,
		Protocol:                protocol.CurrentProtocol,
		BroadcastSetting:        p2p.BroadcastSettingFriendsOfFriends,
		LanGame:                 true,
		OnlineCrossPlatformGame: true,
		CrossPlayDisabled:       false,
		TitleID:                 0,
	}
}
