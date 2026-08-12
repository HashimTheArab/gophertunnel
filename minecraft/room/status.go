package room

import (
	"crypto/rand"
	"encoding/base64"

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
	Protocol                int                  `json:"protocol"`
	MemberCount             int                  `json:"MemberCount"`
	MaxMemberCount          int                  `json:"MaxMemberCount"`
	BroadcastSetting        p2p.BroadcastSetting `json:"BroadcastSetting"`
	LANGame                 bool                 `json:"LanGame"`
	EditorWorld             bool                 `json:"isEditorWorld"`
	Hardcore                bool                 `json:"isHardcore"`
	TransportLayer          int                  `json:"TransportLayer"`
	OnlineCrossPlatformGame bool                 `json:"OnlineCrossPlatformGame"`
	CrossPlayDisabled       bool                 `json:"CrossPlayDisabled"`
	TitleID                 int                  `json:"TitleId"`
	SupportedConnections    []p2p.Connection     `json:"SupportedConnections"`
	Nonces                  map[string]string    `json:"nonces"`
}

const (
	WorldTypeCreative = "Creative"
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
		LANGame:                 true,
		OnlineCrossPlatformGame: true,
		CrossPlayDisabled:       false,
		TitleID:                 0,
	}
}
