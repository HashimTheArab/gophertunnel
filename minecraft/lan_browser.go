package minecraft

import (
	"cmp"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet/discovery"
	"github.com/sandertv/go-raknet"
)

// LANWorld is a world found on the local network by a LANBrowser.
type LANWorld struct {
	// NetherNet reports a world found by NetherNet LAN discovery; otherwise it answered a
	// RakNet unconnected ping.
	NetherNet bool
	// ServerName is the host's name, usually its player name, shown under the level name.
	ServerName string
	// LevelName is the world's name.
	LevelName string
	// Version is the game version the host advertises.
	Version string
	// Protocol is the protocol version the host advertises.
	Protocol int
	// PlayerCount and MaxPlayerCount are the current and maximum number of players.
	PlayerCount, MaxPlayerCount int
	// GameMode is the advertised default game mode, such as "Survival".
	GameMode string
	// Hardcore reports a hardcore world; only NetherNet hosts advertise it.
	Hardcore bool
	// Address is the RakNet address to join, or the UDP address a NetherNet host answers from.
	Address *net.UDPAddr
	// NetworkID is the NetherNet network ID of the host; zero for RakNet worlds.
	NetworkID uint64
	// ServerData is the host's full NetherNet advertisement, including its login nonce and
	// accepted authentication.
	ServerData discovery.ServerData
}

// LANBrowserConfig configures a LANBrowser.
type LANBrowserConfig struct {
	// Log receives discovery errors. If nil, slog.Default is used.
	Log *slog.Logger
	// RakNetPort is the port RakNet pings go to. If zero, 19132 is used.
	RakNetPort int
	// NetherNetAddress is where NetherNet discovery requests go. If nil, the discovery
	// listener's default broadcast addresses are used.
	NetherNetAddress *net.UDPAddr
}

// LANBrowser finds worlds on the local network as the vanilla client does: it runs NetherNet LAN
// discovery and pings for RakNet worlds at the same time and lists both.
type LANBrowser struct {
	conf      LANBrowserConfig
	nethernet *discovery.Listener
	pinger    *raknet.Pinger

	mu     sync.Mutex
	rakNet []rakNetLANWorld // in order of first answer

	closed chan struct{}
	once   sync.Once
	done   sync.WaitGroup
}

// rakNetLANWorld is a RakNet world and when it last answered.
type rakNetLANWorld struct {
	world LANWorld
	guid  int64
	seen  time.Time
}

const (
	// lanPingInterval is how often a LANBrowser pings for RakNet worlds.
	lanPingInterval = time.Second
	// rakNetLANWorldLifetime is how long a RakNet world stays listed after its last pong.
	rakNetLANWorldLifetime = 10 * time.Second
	// defaultRakNetLANPort is the IPv4 port RakNet LAN worlds answer on.
	defaultRakNetLANPort = 19132
)

// Browse starts a LANBrowser. Close stops it.
func (conf LANBrowserConfig) Browse() (*LANBrowser, error) {
	if conf.Log == nil {
		conf.Log = slog.Default()
	}
	if conf.RakNetPort == 0 {
		conf.RakNetPort = defaultRakNetLANPort
	}
	listener, err := discovery.ListenConfig{Log: conf.Log, BroadcastAddress: conf.NetherNetAddress}.Listen(":0")
	if err != nil {
		return nil, err
	}
	pinger, err := raknet.ListenPinger("udp4", ":0")
	if err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	b := &LANBrowser{conf: conf, nethernet: listener, pinger: pinger, closed: make(chan struct{})}
	b.done.Add(2)
	go b.ping()
	go b.readPongs()
	return b, nil
}

// NetherNet returns the browser's NetherNet discovery listener, which signals listed NetherNet
// worlds while the browser is open.
func (b *LANBrowser) NetherNet() *discovery.Listener {
	return b.nethernet
}

// Worlds lists the worlds found: NetherNet worlds, then RakNet worlds, as vanilla merges them. A
// world answering on both transports is listed once for each. Worlds without a server or level
// name and editor-mode worlds are left out.
func (b *LANBrowser) Worlds() []LANWorld {
	var worlds []LANWorld
	for id, data := range b.nethernet.Responses() {
		var advertisement discovery.ServerData
		if err := advertisement.UnmarshalBinary(data); err != nil {
			continue
		}
		worlds = append(worlds, LANWorld{
			NetherNet:      true,
			ServerName:     advertisement.ServerName,
			LevelName:      advertisement.LevelName,
			Version:        advertisement.Version,
			Protocol:       int(advertisement.Protocol),
			PlayerCount:    int(advertisement.PlayerCount),
			MaxPlayerCount: int(advertisement.MaxPlayerCount),
			GameMode:       netherNetGameMode(advertisement.GameType),
			Hardcore:       advertisement.Hardcore,
			NetworkID:      id,
			ServerData:     advertisement,
		})
		if advertisement.EditorWorld {
			worlds = worlds[:len(worlds)-1]
		}
	}
	// Responses arrive unordered; a stable order keeps rows from reshuffling between refreshes.
	slices.SortFunc(worlds, func(a, b LANWorld) int {
		return cmp.Or(cmp.Compare(a.ServerName, b.ServerName), cmp.Compare(a.LevelName, b.LevelName), cmp.Compare(a.NetworkID, b.NetworkID))
	})

	b.mu.Lock()
	b.pruneLocked(time.Now())
	for _, entry := range b.rakNet {
		worlds = append(worlds, entry.world)
	}
	b.mu.Unlock()

	return slices.DeleteFunc(worlds, func(world LANWorld) bool {
		return world.ServerName == "" || world.LevelName == ""
	})
}

// Close stops discovery and pinging.
func (b *LANBrowser) Close() error {
	var err error
	b.once.Do(func() {
		close(b.closed)
		err = errors.Join(b.nethernet.Close(), b.pinger.Close())
		b.done.Wait()
	})
	return err
}

// ping pings every RakNet LAN target each interval, dropping silent worlds first.
func (b *LANBrowser) ping() {
	defer b.done.Done()
	ticker := time.NewTicker(lanPingInterval)
	defer ticker.Stop()
	for {
		b.mu.Lock()
		b.pruneLocked(time.Now())
		b.mu.Unlock()
		for _, target := range rakNetLANTargets(b.conf.RakNetPort) {
			if err := b.pinger.Ping(target); err != nil {
				b.conf.Log.Debug("ping LAN target", slog.Any("target", target), slog.Any("error", err))
			}
		}
		select {
		case <-b.closed:
			return
		case <-ticker.C:
		}
	}
}

// readPongs records each pong that parses as a world until the browser closes.
func (b *LANBrowser) readPongs() {
	defer b.done.Done()
	for {
		pong, err := b.pinger.ReadPong()
		if err != nil {
			return
		}
		addr, ok := pong.Addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		world, editor, ok := parseLANPong(pong.Data, addr)
		if !ok || editor {
			continue
		}
		b.recordRakNet(world, pong.ServerGUID, time.Now())
	}
}

// recordRakNet updates the entry with the same address or GUID in place, or appends a new one.
func (b *LANBrowser) recordRakNet(world LANWorld, guid int64, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, entry := range b.rakNet {
		if entry.world.Address.String() == world.Address.String() || entry.guid == guid {
			b.rakNet[i] = rakNetLANWorld{world: world, guid: guid, seen: now}
			return
		}
	}
	b.rakNet = append(b.rakNet, rakNetLANWorld{world: world, guid: guid, seen: now})
}

// pruneLocked drops RakNet worlds silent for longer than their lifetime. b.mu must be held.
func (b *LANBrowser) pruneLocked(now time.Time) {
	b.rakNet = slices.DeleteFunc(b.rakNet, func(entry rakNetLANWorld) bool {
		return now.Sub(entry.seen) > rakNetLANWorldLifetime
	})
}

// parseLANPong reads a RakNet pong as vanilla's LAN list does: it must be an MCPE pong with at
// least four fields, and the advertised IPv4 port replaces the source port when present. editor
// reports an Editor Mode world.
func parseLANPong(data []byte, from *net.UDPAddr) (world LANWorld, editor, ok bool) {
	fields := splitPong(string(data))
	if len(fields) < 4 || fields[0] != "MCPE" || !isLANVersion(fields[3]) {
		return LANWorld{}, false, false
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
	addr := &net.UDPAddr{IP: from.IP, Port: from.Port, Zone: from.Zone}
	if len(fields) >= 12 {
		if port := number(10); port > 0 && port <= 0xffff {
			addr.Port = port
		}
	}
	return LANWorld{
		ServerName:     field(1),
		Protocol:       number(2),
		Version:        field(3),
		PlayerCount:    number(4),
		MaxPlayerCount: number(5),
		LevelName:      field(7),
		GameMode:       field(8),
		Address:        addr,
	}, number(12) != 0, true
}

// isLANVersion reports whether a pong's version holds only digits and dots.
func isLANVersion(version string) bool {
	return strings.Trim(version, "0123456789.") == ""
}

// netherNetGameMode words a NetherNet advertisement's game type as a pong does.
func netherNetGameMode(gameType int32) string {
	return gameTypeName(int(gameType))
}

// rakNetLANTargets returns the addresses vanilla pings for IPv4 RakNet LAN worlds: loopback and
// the directed broadcast address of every IPv4 interface that is up.
func rakNetLANTargets(port int) []*net.UDPAddr {
	targets := []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: port}}
	interfaces, err := net.Interfaces()
	if err != nil {
		return targets
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagBroadcast == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			network, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, mask := network.IP.To4(), network.Mask
			if ip == nil {
				continue
			}
			if len(mask) == net.IPv6len {
				mask = mask[12:]
			}
			broadcast := make(net.IP, net.IPv4len)
			for i := range broadcast {
				broadcast[i] = ip[i] | ^mask[i]
			}
			if !slices.ContainsFunc(targets, func(t *net.UDPAddr) bool { return t.IP.Equal(broadcast) }) {
				targets = append(targets, &net.UDPAddr{IP: broadcast, Port: port})
			}
		}
	}
	return targets
}
