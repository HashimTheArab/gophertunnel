package gatherings

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/df-mc/go-playfab/v2/catalog"
	"github.com/google/uuid"
)

// Experience represents a playable experience returned by the gatherings
// service.
//
// An Experience is decoded from the [catalog.Item.DisplayProperties] field. It
// populates the same display fields as [FeaturedServer], but it does not
// contain a public host or port. Instead, the caller needs to call [Experience.Join]
// to resolve the nearest server [Address].
type Experience struct {
	experience

	// ID identifies the experience in the gatherings service. It is used by
	// [Experience.Join] and [Client.JoinExperience] to resolve a server address.
	ID uuid.UUID `json:"experienceId"`

	// client is the API Client bound to this experience. It is used by
	// [Experience.Join] to resolve the server address.
	client *Client
}

// Valid reports whether [Experience] has the ID required to join the server.
func (e *Experience) Valid() bool {
	return e != nil && e.ID != uuid.Nil
}

// experience represents the basic structure of the DisplayProperties field shared
// by [Experience] and [FeaturedServer].
//
// These fields describe how the experience or featured server is displayed in
// the client. Data outside DisplayProperties, such as the title, description and
// images, is stored in the Item field.
type experience struct {
	// Item is the [catalog.Item] that contains describes this experience
	// or featured server. It holds service-defined metadata outside DisplayProperties,
	// such as localized titles, descriptions, and image URLs.
	Item catalog.Item `json:"-"`

	// AvailableGame lists the activities, modes or games advertised by the
	// experience or featured server.
	AvailableGames []AvailableGame `json:"availableGames"`
	// CreatorName is the display name of the creator offering the experience or
	// featured server.
	CreatorName string `json:"creatorName"`
	// MaxClientVersion is the maximum client version advertised by the
	// experience or featured server. Most values are "9.9.99", so callers should
	// not treat this as a precise protocol limit.
	MaxClientVersion string `json:"maxClientVersion"`
	// MinClientVersion is the minimum client version advertised by the
	// experience or featured server. The client does not validate this value
	// during connection, so it is purely informational.
	MinClientVersion string `json:"minClientVersion"`
	// News is the full body text of the news entry shown in the server panel.
	News string `json:"news"`
	// NewsTitle is the headline of the news entry displayed at the bottom of
	// the server panel.
	NewsTitle string `json:"newsTitle"`
	// OriginalCreatorID identifies the creator offering the experience.
	// Decimal values appear to be XUIDs. The meaning of non-decimal values
	// is unknown.
	OriginalCreatorID string `json:"originalCreatorId"`
	// RequireXBL is a string-encoded boolean indicating whether joining requires
	// an Xbox Live account.
	RequireXBL string `json:"requireXBL"`
	// StorePageID identifies the Marketplace page opened from the in-game store
	// button for the experience or featured server.
	StorePageID string `json:"storePageId"`
	// WhiteListURL is an optional host or pattern. It may be used to limit
	// which host the client is allowed to connect.
	WhiteListURL string `json:"whitelistUrl"`
	// AllowListURL is an optional host or pattern. It may be used to limit
	// which host the client is allowed to connect.
	AllowListURL string `json:"allowListUrl"`
	// Rank is the order assigned by the service for this experience.
	// It appears, if this field is present, the experience will be
	// displayed as 'Featured experiences' in the servers tab. Otherwise,
	// the experience will be displayed as 'Creator experiences'.
	Rank int `json:"rank"`
}

// UnmarshalJSON implements [json.Unmarshaler] for [Experience].
func (e *Experience) UnmarshalJSON(b []byte) (err error) {
	type Alias Experience
	data := struct {
		*Alias
		ID string `json:"experienceId"`
	}{Alias: (*Alias)(e)}
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	if data.ID != "" {
		e.ID, err = uuid.Parse(data.ID)
		if err != nil {
			return fmt.Errorf("service/gatherings: parse Experience.ID: %w", err)
		}
	}
	return nil
}

// Join resolves the server [Address] for the [Experience] through the gatherings service.
//
// It is equivalent of calling [Client.JoinExperience] with [Experience.ID].
// The resulting Address may locate to the nearest server to the caller.
func (e *Experience) Join(ctx context.Context) (*Address, error) {
	return e.client.JoinExperience(ctx, e.ID)
}

// Address contains the network information returned by [Experience.Join].
type Address struct {
	// NetworkProtocol names the transport expected by the experience server.
	// Most experiences use [NetworkProtocolDefault] at the moment.
	NetworkProtocol NetworkProtocol `json:"networkProtocol"`
	// IPv4Address is the IPv4 address of a RakNet server. For NetherNet
	// assignments, the service overloads this field with the NetherNet network
	// ID instead.
	IPv4Address string `json:"ipV4Address"`
	// Port is the UDP port of the resolved server.
	Port uint16 `json:"port"`
	// DestinationInfo contains additional identifiers for the resolved
	// destination.
	DestinationInfo DestinationInfo `json:"destinationInfo"`
	unknownFields   []string
}

// UnmarshalJSON records unknown top-level assignment fields for a temporary,
// redacted live diagnostic. It must not remain in the committed implementation.
func (a *Address) UnmarshalJSON(data []byte) error {
	type address Address
	var decoded address
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"networkProtocol", "ipV4Address", "port", "destinationInfo"} {
		delete(fields, name)
	}
	for name := range fields {
		decoded.unknownFields = append(decoded.unknownFields, name)
	}
	sort.Strings(decoded.unknownFields)
	*a = Address(decoded)
	return nil
}

// DialAddress returns the address expected by the transport selected through
// [Address.NetworkProtocol]. RakNet assignments use host:port, while NetherNet
// assignments use the network ID returned in [Address.IPv4Address].
func (a Address) DialAddress() (string, error) {
	switch ParseNetworkProtocol(string(a.NetworkProtocol)) {
	case NetworkProtocolDefault:
		if strings.TrimSpace(a.IPv4Address) == "" || a.Port == 0 {
			return "", fmt.Errorf("service/gatherings: invalid RakNet experience address")
		}
		return net.JoinHostPort(a.IPv4Address, strconv.Itoa(int(a.Port))), nil
	case NetworkProtocolNetherNet, NetworkProtocolNetherNetJSONRPC:
		if address := strings.TrimSpace(a.IPv4Address); address != "" {
			return address, nil
		}
		return "", fmt.Errorf("service/gatherings: invalid NetherNet experience address (other fields: %v)", a.unknownFields)
	default:
		return "", fmt.Errorf("service/gatherings: unsupported experience network protocol %q", a.NetworkProtocol)
	}
}

// String returns the dial address, or an empty string if the assignment is
// invalid or uses an unsupported network protocol. Call [Address.DialAddress]
// when the error is relevant.
func (a Address) String() string {
	address, _ := a.DialAddress()
	return address
}

// NetworkProtocol is the transport protocol returned by the Gatherings join
// service.
type NetworkProtocol string

// ParseNetworkProtocol normalizes a Gatherings network protocol value.
func ParseNetworkProtocol(protocol string) NetworkProtocol {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "DEFAULT":
		return NetworkProtocolDefault
	case "NETHERNET":
		return NetworkProtocolNetherNet
	case "NETHERNET_JSONRPC":
		return NetworkProtocolNetherNetJSONRPC
	default:
		return NetworkProtocol(strings.TrimSpace(protocol))
	}
}

// Valid reports whether the protocol is supported by Gatherings address
// resolution.
func (p NetworkProtocol) Valid() bool {
	switch ParseNetworkProtocol(string(p)) {
	case NetworkProtocolDefault, NetworkProtocolNetherNet, NetworkProtocolNetherNetJSONRPC:
		return true
	default:
		return false
	}
}

// NetherNet reports whether the protocol uses a NetherNet network ID rather
// than a RakNet host and port.
func (p NetworkProtocol) NetherNet() bool {
	switch ParseNetworkProtocol(string(p)) {
	case NetworkProtocolNetherNet, NetworkProtocolNetherNetJSONRPC:
		return true
	default:
		return false
	}
}

// Constants for [Address.NetworkProtocol].
const (
	// NetworkProtocolDefault indicates that the experience should be
	// contacted using the default transport of the Bedrock Edition, RakNet.
	NetworkProtocolDefault NetworkProtocol = "Default"
	// NetworkProtocolNetherNet indicates that the experience should be
	// contacted through NetherNet using WebSocket signaling.
	NetworkProtocolNetherNet NetworkProtocol = "NetherNet"
	// NetworkProtocolNetherNetJSONRPC indicates that the experience should be
	// contacted through NetherNet using JSON-RPC messaging signaling.
	NetworkProtocolNetherNetJSONRPC NetworkProtocol = "NetherNet_JsonRpc"
)

// DestinationInfo describes the destination selected by [Experience.Join].
//
// These identifiers are returned alongside an [Address] and can be used for
// telemetry, diagnostics or publishing a presence to the social friends of the caller.
type DestinationInfo struct {
	// CreatorID identifies the creator which is offering the experience. It is usually the
	// same value as [Experience.OriginalCreatorID].
	CreatorID string `json:"creatorId"`
	// ExperienceID identifies the experience that was joined.
	ExperienceID uuid.UUID `json:"experienceId"`
	// ExperienceName is the display name of the experience that was joined.
	ExperienceName string `json:"experienceName"`
	// ScenarioID is an identifier used for telemetry purposes.
	ScenarioID uuid.UUID `json:"scenarioId"`
	// MPSASScenarioID is unknown.
	MPSASScenarioID string `json:"mpsasScenarioId"`
	// ServerID identifies the server selected for the join request.
	ServerID string `json:"serverId"`
	// TargetID is unknown.
	TargetID string `json:"targetId"`
	// WorldID identifies the world selected for the join request.
	WorldID uuid.UUID `json:"worldId"`
	// WorldName is the display name of the selected world.
	WorldName string `json:"worldName"`
}

// AvailableGame describes one activity, mode or game advertised by an
// [Experience] or [FeaturedServer].
type AvailableGame struct {
	// Description is the long description of the game.
	Description string `json:"description"`
	// ImageTag selects the [catalog.Image] in [catalog.Item] used as
	// the thumbnail for the game.
	ImageTag string `json:"imageTag"`
	// Subtitle is the short description shown with [AvailableGame.Title].
	Subtitle string `json:"subtitle"`
	// Title is the display title of the game.
	Title string `json:"title"`
}

// FeaturedServer represents a featured server returned by the gatherings service.
//
// A FeaturedServer is decoded from the [catalog.Item.DisplayProperties] field.
// It populates the same display fields as [Experience], and also contains a public
// host and port. Use [FeaturedServer.Address] directly when dialing.
type FeaturedServer struct {
	experience

	// Port is the UDP port used to connect to the featured server.
	Port uint16 `json:"port"`
	// Host is the public host name or IP address of the featured server.
	Host string `json:"url"`
}

// Valid reports whether [FeaturedServer] has the host and port required to join the server.
func (s FeaturedServer) Valid() bool {
	return s.Host != "" && s.Port != 0
}

// Address returns a combination of [FeaturedServer.Host] and [FeaturedServer.Port].
func (s FeaturedServer) Address() string {
	return net.JoinHostPort(s.Host, strconv.Itoa(int(s.Port)))
}
