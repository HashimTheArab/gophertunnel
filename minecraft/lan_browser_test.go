package minecraft

import (
	"net"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet/discovery"
	"github.com/sandertv/go-raknet"
)

// A pong parses as vanilla reads it: MCPE, a dotted version, and the advertised IPv4 port.
func TestParseLANPong(t *testing.T) {
	from := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 50000}
	world, editor, ok := parseLANPong([]byte("MCPE;Steve;924;1.26.60;2;8;123;My World;Creative;1;19132;19133;0;"), from)
	if !ok || editor {
		t.Fatalf("parseLANPong() ok = %t, editor = %t", ok, editor)
	}
	if world.ServerName != "Steve" || world.LevelName != "My World" || world.Version != "1.26.60" ||
		world.Protocol != 924 || world.PlayerCount != 2 || world.MaxPlayerCount != 8 || world.GameMode != "Creative" {
		t.Fatalf("parseLANPong() = %+v", world)
	}
	if world.Address.String() != "192.168.1.20:19132" {
		t.Fatalf("address = %s, want the advertised port", world.Address)
	}

	for _, pong := range []string{"MCEE;Steve;924;1.26.60", "MCPE;Steve;924", "MCPE;Steve;924;1.26.60 beta"} {
		if _, _, ok := parseLANPong([]byte(pong), from); ok {
			t.Fatalf("parseLANPong(%q) accepted", pong)
		}
	}
	if world, _, ok := parseLANPong([]byte("MCPE;Steve;924;1.26.60;2;8"), from); !ok || world.Address.Port != 50000 {
		t.Fatalf("short pong = %+v, %t, want the source port", world, ok)
	}
	if _, editor, _ := parseLANPong([]byte("MCPE;S;1;1.0;0;1;2;L;Survival;1;19132;19133;1;"), from); !editor {
		t.Fatal("editor flag not read")
	}
}

// Backslashes stay in the text, and a semicolon right after one does not split a field.
func TestSplitLANPong(t *testing.T) {
	got := splitLANPong(`MCPE;World\Name;a\;b;\\;end`)
	want := []string{"MCPE", `World\Name`, `a\;b`, `\\;end`}
	if len(got) != len(want) {
		t.Fatalf("splitLANPong() = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitLANPong() = %q, want %q", got, want)
		}
	}
}

// RakNet worlds update in place by address or GUID and expire ten seconds after their last pong.
func TestLANBrowserRakNetEntries(t *testing.T) {
	b := &LANBrowser{}
	start := time.Now()
	first := LANWorld{ServerName: "a", LevelName: "x", Address: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 19132}}
	second := LANWorld{ServerName: "b", LevelName: "y", Address: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 19132}}
	b.recordRakNet(first, 1, start)
	b.recordRakNet(second, 2, start)
	renamed := first
	renamed.LevelName = "z"
	b.recordRakNet(renamed, 1, start.Add(time.Second))
	if len(b.rakNet) != 2 || b.rakNet[0].world.LevelName != "z" {
		t.Fatalf("entries = %+v, want the first updated in place", b.rakNet)
	}
	b.pruneLocked(start.Add(rakNetLANWorldLifetime))
	if len(b.rakNet) != 2 {
		t.Fatal("pruned a world at exactly ten seconds")
	}
	b.pruneLocked(start.Add(rakNetLANWorldLifetime + time.Millisecond))
	if len(b.rakNet) != 1 || b.rakNet[0].guid != 1 {
		t.Fatalf("entries = %+v, want only the refreshed world", b.rakNet)
	}
}

// A RakNet world on the local machine is found by pinging loopback.
func TestLANBrowserFindsLoopbackRakNetWorld(t *testing.T) {
	listener, err := raknet.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	listener.PongData([]byte("MCPE;Host;924;1.26.60;1;10;99;LAN World;Survival;1;0;0;0;"))
	port := listener.Addr().(*net.UDPAddr).Port
	browser, err := LANBrowserConfig{RakNetPort: port}.Browse()
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	defer browser.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, world := range browser.Worlds() {
			if !world.NetherNet && world.LevelName == "LAN World" && world.ServerName == "Host" {
				if world.Address.Port != port {
					t.Fatalf("address = %s, want port %d", world.Address, port)
				}
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("loopback RakNet world not listed")
}

// NetherNet worlds come first, editor worlds are left out, and a world answering on both
// transports is listed once for each.
func TestLANBrowserListsNetherNetThenRakNet(t *testing.T) {
	var hosts []*net.UDPAddr
	for _, data := range []discovery.ServerData{
		{ServerName: "Host", LevelName: "LAN World", GameType: 1, MaxPlayerCount: 8, ConnectionType: 4},
		{ServerName: "Editor", LevelName: "Project", EditorWorld: true, ConnectionType: 4},
	} {
		addr := freeUDPAddr(t)
		host, err := discovery.ListenConfig{}.Listen(addr.String())
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		defer host.Close()
		host.ServerData(&data)
		hosts = append(hosts, addr)
	}
	rakNet, err := raknet.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer rakNet.Close()
	rakNet.PongData([]byte("MCPE;Host;924;1.26.60;1;10;99;LAN World;Survival;1;0;0;0;"))

	browsers := make([]*LANBrowser, len(hosts))
	for i, host := range hosts {
		b, err := LANBrowserConfig{
			RakNetPort:       rakNet.Addr().(*net.UDPAddr).Port,
			NetherNetAddress: host,
		}.Browse()
		if err != nil {
			t.Fatalf("Browse: %v", err)
		}
		defer b.Close()
		browsers[i] = b
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		worlds := browsers[0].Worlds()
		if len(worlds) == 2 {
			if !worlds[0].NetherNet || worlds[0].GameMode != "Creative" || worlds[1].NetherNet {
				t.Fatalf("worlds = %+v, want the NetherNet world first", worlds)
			}
			for _, world := range browsers[1].Worlds() {
				if world.NetherNet {
					t.Fatalf("editor world listed: %+v", world)
				}
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("worlds = %+v, want one NetherNet and one RakNet entry", browsers[0].Worlds())
}

// freeUDPAddr returns a loopback UDP address that was free a moment ago.
func freeUDPAddr(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr)
}

// A NetherNet world drops out a few seconds after its host stops answering.
func TestLANBrowserExpiresSilentNetherNetWorld(t *testing.T) {
	addr := freeUDPAddr(t)
	host, err := discovery.ListenConfig{}.Listen(addr.String())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	host.ServerData(&discovery.ServerData{ServerName: "Host", LevelName: "Gone", ConnectionType: 4})
	browser, err := LANBrowserConfig{RakNetPort: freeUDPAddr(t).Port, NetherNetAddress: addr}.Browse()
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	defer browser.Close()

	listed := func() bool {
		for _, world := range browser.Worlds() {
			if world.NetherNet && world.LevelName == "Gone" {
				return true
			}
		}
		return false
	}
	waitFor := func(want bool, within time.Duration) {
		t.Helper()
		deadline := time.Now().Add(within)
		for time.Now().Before(deadline) {
			if listed() == want {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("world listed = %t after %s, want %t", listed(), within, want)
	}
	waitFor(true, 6*time.Second)
	_ = host.Close()
	waitFor(false, 8*time.Second)
}
