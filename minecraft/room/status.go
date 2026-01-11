package room

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

type Status struct {
	Joinability             string       `json:"Joinability,omitempty"`
	HostName                string       `json:"hostName,omitempty"`
	OwnerID                 string       `json:"ownerId,omitempty"`
	RakNetGUID              string       `json:"rakNetGUID"`
	Version                 string       `json:"version"`
	LevelID                 string       `json:"levelId"`
	WorldName               string       `json:"worldName"`
	WorldType               string       `json:"worldType"`
	Protocol                int32        `json:"protocol"`
	MemberCount             int          `json:"MemberCount"`
	MaxMemberCount          int          `json:"MaxMemberCount"`
	BroadcastSetting        int32        `json:"BroadcastSetting"`
	LanGame                 bool         `json:"LanGame"`
	IsEditorWorld           bool         `json:"isEditorWorld"`
	TransportLayer          int32        `json:"TransportLayer"`
	OnlineCrossPlatformGame bool         `json:"OnlineCrossPlatformGame"`
	CrossPlayDisabled       bool         `json:"CrossPlayDisabled"`
	TitleID                 int64        `json:"TitleId"`
	SupportedConnections    []Connection `json:"SupportedConnections"`
}

// NetherNetID is a NetherNet connection ID. MPSD custom properties sometimes encode this as a JSON
// number and sometimes as a JSON string, so we accept both and normalize to a decimal string.
type NetherNetID string

func (id *NetherNetID) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*id = ""
		return nil
	}
	// Regular string
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*id = NetherNetID(s)
		return nil
	}
	// Uint64 number, parse as a string
	u, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		return err
	}
	*id = NetherNetID(strconv.FormatUint(u, 10))
	return nil
}

type Connection struct {
	ConnectionType uint32      `json:"ConnectionType"`
	HostIPAddress  string      `json:"HostIpAddress"`
	HostPort       uint16      `json:"HostPort"`
	NetherNetID    NetherNetID `json:"NetherNetId"`
	RakNetGUID     string      `json:"RakNetGUID,omitempty"`
}

const (
	JoinabilityInviteOnly        = "invite_only"
	JoinabilityJoinableByFriends = "joinable_by_friends"
)

const (
	WorldTypeCreative = "Creative"
)

const (
	BroadcastSettingInviteOnly int32 = iota + 1
	BroadcastSettingFriendsOnly
	BroadcastSettingFriendsOfFriends
)

const (
	TransportLayerRakNet int32 = iota
	_
	TransportLayerNetherNet
)

const (
	ConnectionTypeWebSocketsWebRTCSignaling uint32 = 3
	ConnectionTypeUPNP                      uint32 = 6
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
		Joinability:             JoinabilityJoinableByFriends,
		HostName:                "Gophertunnel",
		Version:                 protocol.CurrentVersion,
		LevelID:                 base64.StdEncoding.EncodeToString(levelID),
		WorldName:               "Room Listener",
		WorldType:               WorldTypeCreative,
		Protocol:                protocol.CurrentProtocol,
		BroadcastSetting:        BroadcastSettingFriendsOfFriends,
		LanGame:                 true,
		OnlineCrossPlatformGame: true,
		CrossPlayDisabled:       false,
		TitleID:                 0,
	}
}

func (status Status) NetherNetID() (string, bool) {
	for _, c := range status.SupportedConnections {
		if c.ConnectionType == ConnectionTypeWebSocketsWebRTCSignaling {
			id := string(c.NetherNetID)
			if id != "" && id != "0" {
				return id, true
			}
		}
	}
	return "", false
}
