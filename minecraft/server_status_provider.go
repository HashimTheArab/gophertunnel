package minecraft

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sandertv/go-raknet"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// ServerStatusProvider represents a type that is able to provide the visual status of a server, in specific
// its MOTD, the amount of online players and the player limit displayed in the server list.
// These providers may be used to display different information in the server list. Although they overwrite
// the maximum players and online players maintained by a Listener in the server list, these values are not
// changed and will still be used internally to check if players are able to be connected. Players will still
// be disconnected if the maximum player count as set in the ListenConfig.MaximumPlayers field of a Listener
// is reached (unless ListenConfig.MaximumPlayers is 0).
type ServerStatusProvider interface {
	// ServerStatus returns the server status which includes the MOTD/server name, amount of online players
	// and the amount of maximum players.
	// The player count and max players of the minecraft.Listener that calls this method is passed.
	ServerStatus(playerCount, maxPlayers int) ServerStatus
}

// ServerStatus holds the information shown in the Minecraft server list. They have no impact on the listener
// functionality-wise.
type ServerStatus struct {
	// ServerName is the name or MOTD of the server, as shown in the server list.
	ServerName string
	// ServerName is the sub-name or sub-MOTD of the server, as shown in the friend list.
	ServerSubName string
	// PlayerCount is the current amount of players displayed in the list.
	PlayerCount int
	// MaxPlayers is the maximum amount of players in the server. If set to 0, MaxPlayers is set to
	// PlayerCount + 1.
	MaxPlayers int
	// GameType is the default game mode of the server, as shown in the friend list. It is one of
	// packet.GameTypeSurvival, packet.GameTypeCreative, packet.GameTypeAdventure or packet.GameTypeSpectator;
	// any other value is advertised as Survival.
	GameType int
}

// ListenerStatusProvider is the default ServerStatusProvider of a Listener. It displays a static server name/
// MOTD and displays the player count and maximum amount of players of the server.
type ListenerStatusProvider struct {
	// name is the name of the server, or the MOTD, that is displayed in the server list.
	name string
	// subName is the sub-name of the server, or the MOTD, that is displayed in the friend list.
	subName string
	// GameType is advertised as the pong game mode; it is one of the packet.GameType constants.
	GameType int
}

// NewStatusProvider creates a ListenerStatusProvider that displays the server name passed.
func NewStatusProvider(serverName, serverSubName string) ListenerStatusProvider {
	return ListenerStatusProvider{name: serverName, subName: serverSubName}
}

// ServerStatus ...
func (l ListenerStatusProvider) ServerStatus(playerCount, maxPlayers int) ServerStatus {
	return ServerStatus{
		ServerName:    l.name,
		ServerSubName: l.subName,
		PlayerCount:   playerCount,
		MaxPlayers:    maxPlayers,
		GameType:      l.GameType,
	}
}

// ForeignStatusProvider is a ServerStatusProvider that provides the status of a target server to the Listener
// so that the MOTD, player count etc. is copied.
type ForeignStatusProvider struct {
	addr string

	mu     sync.Mutex
	status ServerStatus

	once   sync.Once
	closed chan struct{}
}

// NewForeignStatusProvider creates a ForeignStatusProvider that uses the status of the server running at the
// target address. An error is returned if the address is invalid.
// Close must be called if the ForeignStatusProvider is discarded.
func NewForeignStatusProvider(addr string) (*ForeignStatusProvider, error) {
	if _, err := net.ResolveUDPAddr("udp", addr); err != nil {
		return nil, err
	}
	f := &ForeignStatusProvider{addr: addr, closed: make(chan struct{})}
	go f.update()
	return f, nil
}

// ServerStatus returns the ServerStatus of the target server.
func (f *ForeignStatusProvider) ServerStatus(int, int) ServerStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

// Close closes the ForeignStatusProvider and stops polling it. Close always returns nil.
func (f *ForeignStatusProvider) Close() error {
	f.once.Do(func() {
		close(f.closed)
	})
	return nil
}

// update updates the status every second and cancels when Close is called.
func (f *ForeignStatusProvider) update() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			data, err := raknet.Ping(f.addr)
			if err != nil {
				continue
			}
			f.mu.Lock()
			f.status = ParsePongData(data)
			f.mu.Unlock()
		case <-f.closed:
			return
		}
	}
}

// ParsePongData parses the unconnected pong data passed into the relevant fields of a ServerStatus struct.
// Malformed data yields a ServerStatus whose ServerName describes the problem; use [ParsePong] to get an error.
func ParsePongData(pong []byte) ServerStatus {
	status, err := ParsePong(pong)
	if err != nil {
		// Keep the existing display text while ParsePong returns conventional lowercase errors.
		message := err.Error()
		return ServerStatus{ServerName: strings.ToUpper(message[:1]) + message[1:]}
	}
	return status
}

// ParsePong parses unconnected pong data into a ServerStatus, or returns an error when the pong lacks
// the name, player count or max player count fields.
func ParsePong(pong []byte) (ServerStatus, error) {
	advertisement, err := parsePongAdvertisement(splitPong(string(pong)), 8, true)
	if err != nil {
		return ServerStatus{}, err
	}
	return ServerStatus{
		ServerName: advertisement.MOTD, ServerSubName: advertisement.MOTDLine2,
		PlayerCount: advertisement.PlayerCount, MaxPlayers: advertisement.MaxPlayerCount,
		GameType: parseGameType(advertisement.GameMode),
	}, nil
}

// PongAdvertisement holds the Bedrock fields advertised in a RakNet unconnected
// pong. Ports are status and discovery metadata; they do not override a caller's
// dial address. Missing numeric fields are represented by zero; numeric conversion
// errors are tolerated, retaining the result returned by strconv.Atoi.
type PongAdvertisement struct {
	Edition         string
	MOTD            string
	ProtocolVersion int
	VersionName     string
	PlayerCount     int
	MaxPlayerCount  int
	ServerID        string
	MOTDLine2       string
	GameMode        string
	GameModeNumeric int
	PortIPv4        int
	PortIPv6        int
}

// PongFieldCountError reports an advertisement with fewer than six fields.
type PongFieldCountError struct {
	Fields int
}

// Error describes the missing advertisement fields.
func (e PongFieldCountError) Error() string {
	return fmt.Sprintf("invalid pong data: expected at least 6 fields, got %d", e.Fields)
}

// ParsePongAdvertisement parses all twelve Bedrock advertisement fields. It
// accepts legacy pongs containing at least the first six fields. Semicolons are
// literal delimiters and backslashes are preserved. Optional strings default to
// empty, and numeric conversion errors are tolerated. Missing numeric fields are
// zero. Use ParsePong for the stricter server-list status contract, which retains
// its legacy backslash handling.
func ParsePongAdvertisement(pong []byte) (PongAdvertisement, error) {
	return parsePongAdvertisement(strings.Split(string(pong), ";"), 6, false)
}

// parsePongAdvertisement owns the field layout shared by both public parsers.
func parsePongAdvertisement(fields []string, minimumFields int, strictCounts bool) (PongAdvertisement, error) {
	if len(fields) < minimumFields {
		if strictCounts {
			return PongAdvertisement{}, errors.New("invalid pong data")
		}
		return PongAdvertisement{}, PongFieldCountError{Fields: len(fields)}
	}
	field := func(index int) string {
		if index < len(fields) {
			return fields[index]
		}
		return ""
	}
	number := func(index int) int {
		value, _ := strconv.Atoi(field(index))
		return value
	}
	count, countErr := strconv.Atoi(fields[4])
	maximum, maximumErr := strconv.Atoi(fields[5])
	if strictCounts {
		if countErr != nil {
			return PongAdvertisement{}, errors.New("invalid player count")
		}
		if maximumErr != nil {
			return PongAdvertisement{}, errors.New("invalid max player count")
		}
	}
	return PongAdvertisement{
		Edition: field(0), MOTD: field(1), ProtocolVersion: number(2), VersionName: field(3),
		PlayerCount: count, MaxPlayerCount: maximum, ServerID: field(6), MOTDLine2: field(7),
		GameMode: field(8), GameModeNumeric: number(9), PortIPv4: number(10), PortIPv6: number(11),
	}, nil
}

// gameTypeName returns the pong string for a ServerStatus.GameType. Types without a pong string are
// advertised as Survival.
func gameTypeName(gameType int) string {
	switch gameType {
	case packet.GameTypeCreative:
		return "Creative"
	case packet.GameTypeAdventure:
		return "Adventure"
	case packet.GameTypeSpectator:
		return "Spectator"
	}
	return "Survival"
}

// parseGameType converts the game mode string of a pong to a ServerStatus.GameType. Unknown modes are
// treated as Survival.
func parseGameType(v string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "creative":
		return packet.GameTypeCreative
	case "adventure":
		return packet.GameTypeAdventure
	case "spectator":
		return packet.GameTypeSpectator
	}
	return packet.GameTypeSurvival
}
