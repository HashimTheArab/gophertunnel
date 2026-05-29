package room

import (
	"strconv"

	"github.com/google/uuid"
)

// NetherNetConnection is the parsed join target extracted from MPSD room status data.
type NetherNetConnection struct {
	RawID          uint64
	MessagingID    uuid.UUID
	ConnectionType uint32
}

// DialID returns the string identifier to use when dialing this NetherNet connection.
func (c NetherNetConnection) DialID() string {
	switch c.ConnectionType {
	case ConnectionTypeJSONRPCSignaling:
		// JSONRPC sessions are signaled through the messaging service and use a UUID player ID.
		if c.MessagingID == uuid.Nil {
			return ""
		}
		return c.MessagingID.String()
	case ConnectionTypeWebSocketsWebRTCSignaling:
		// WebRTC sessions are signaled through the signaling service and use a numeric NetherNet ID.
		if c.RawID == 0 {
			return ""
		}
		return strconv.FormatUint(c.RawID, 10)
	default:
		return ""
	}
}

// NetherNetConnectionInfo extracts the best available NetherNet connection details from a room status.
func NetherNetConnectionInfo(status Status) (NetherNetConnection, bool) {
	for _, c := range status.SupportedConnections {
		if c.ConnectionType != ConnectionTypeWebSocketsWebRTCSignaling && c.ConnectionType != ConnectionTypeJSONRPCSignaling {
			continue
		}
		parsed, err := strconv.ParseUint(string(c.NetherNetID), 10, 64)
		if err != nil || parsed == 0 {
			continue
		}
		conn := NetherNetConnection{
			RawID:          parsed,
			MessagingID:    c.PmsgID,
			ConnectionType: c.ConnectionType,
		}
		if conn.DialID() == "" {
			continue
		}
		return conn, true
	}
	return NetherNetConnection{}, false
}
