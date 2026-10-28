package minecraft

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

const observerUnknownID = 700

func TestSelectiveObserverIncomingOwnershipAndOrder(t *testing.T) {
	conn := observerTestConn(t)
	var events []string
	var selected, legacy []byte
	conn.packetObserver = mustCompileObserver(t, PacketObserver{
		PacketIDs: []uint32{observerUnknownID, observerUnknownID},
		Func: func(header packet.Header, payload []byte, src, dst net.Addr) {
			events = append(events, "selective")
			if header.SenderSubClient != 1 || src.String() != "remote" || dst.String() != "local" {
				t.Fatalf("incoming header/addresses = %+v %v %v", header, src, dst)
			}
			selected = payload
			payload[0] = 9
		},
	})
	conn.packetFunc = func(_ packet.Header, payload []byte, _, _ net.Addr) {
		events = append(events, "legacy")
		legacy = payload
		if payload[0] != 9 || &payload[0] != &selected[0] {
			t.Fatal("observers did not share one owned payload in order")
		}
	}
	conn.acceptPacketHeader = func(packet.Header) bool {
		events = append(events, "filter")
		return false
	}
	frame := observerFrame(t, packet.Header{PacketID: observerUnknownID, SenderSubClient: 1}, []byte{1, 2, 3})
	if err := conn.receive(frame); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(events, []string{"selective", "legacy", "filter"}) {
		t.Fatalf("events = %v", events)
	}
	if frame[len(frame)-3] != 1 {
		t.Fatal("observer mutation changed the received frame")
	}
	clear(frame)
	if !bytes.Equal(selected, []byte{9, 2, 3}) || !bytes.Equal(legacy, selected) {
		t.Fatal("retained observer payload changed with decoder storage")
	}
	events = nil
	if _, err := parseData([]byte{0x80}, conn); err == nil || len(events) != 0 {
		t.Fatalf("malformed header: error=%v events=%v", err, events)
	}
}

func TestSelectiveObserverSelectionAndLegacyFallback(t *testing.T) {
	for _, test := range []struct {
		name   string
		ids    []uint32
		active bool
		legacy bool
	}{
		{name: "absent"},
		{name: "empty", active: true},
		{name: "nil callback", ids: []uint32{observerUnknownID}},
		{name: "selected", ids: []uint32{observerUnknownID}, active: true},
		{name: "both", ids: []uint32{observerUnknownID}, active: true, legacy: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := observerTestConn(t)
			var selected, legacy int
			observer := PacketObserver{PacketIDs: test.ids}
			if test.active {
				observer.Func = func(packet.Header, []byte, net.Addr, net.Addr) { selected++ }
			}
			conn.packetObserver = mustCompileObserver(t, observer)
			if test.legacy {
				conn.packetFunc = func(packet.Header, []byte, net.Addr, net.Addr) { legacy++ }
			}
			conn.loggedIn, conn.batchReading = true, true
			for _, id := range []uint32{observerUnknownID, packet.IDLevelChunk} {
				if err := conn.receive(observerFrame(t, packet.Header{PacketID: id}, []byte{1})); err != nil {
					t.Fatal(err)
				}
			}
			wantSelected := 0
			if test.active && len(test.ids) != 0 {
				wantSelected = 1
			}
			wantLegacy := 0
			if test.legacy {
				wantLegacy = 2
			}
			if selected != wantSelected || legacy != wantLegacy || len(conn.pendingBatch) != 2 {
				t.Fatalf("selected/legacy/delivered = %d/%d/%d, want %d/%d/2", selected, legacy, len(conn.pendingBatch), wantSelected, wantLegacy)
			}
		})
	}
}

func TestSelectiveObserverSkipsUnrelatedBodyAllocations(t *testing.T) {
	conn := observerTestConn(t)
	frame := observerFrame(t, packet.Header{PacketID: observerUnknownID}, make([]byte, 64*1024))
	var retained []byte
	var parsed *packetData
	callback := func(_ packet.Header, payload []byte, _, _ net.Addr) { retained = payload }
	measure := func() float64 {
		return testing.AllocsPerRun(100, func() {
			var err error
			parsed, err = parseData(frame, conn)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	baseline := measure()
	conn.packetObserver = mustCompileObserver(t, PacketObserver{PacketIDs: []uint32{packet.IDResourcePacksInfo}, Func: callback})
	if got := measure(); got != baseline {
		t.Fatalf("unselected allocations = %g, want baseline %g", got, baseline)
	}
	conn.packetObserver = mustCompileObserver(t, PacketObserver{PacketIDs: []uint32{observerUnknownID}, Func: callback})
	selected := measure()
	conn.packetFunc = callback
	both := measure()
	conn.packetObserver = compiledPacketObserver{}
	legacy := measure()
	if selected != baseline+1 || both != selected || legacy != selected {
		t.Fatalf("baseline/selected/both/legacy allocations = %g/%g/%g/%g", baseline, selected, both, legacy)
	}
	if parsed == nil || len(retained) != len(parsed.payload.Bytes()) {
		t.Fatal("allocation fixture did not retain its parse and observer results")
	}
}

func TestSelectiveObserverOutboundMutationAndRegistry(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			conn := observerTestConn(t)
			var events []string
			conn.packetObserver = mustCompileObserver(t, PacketObserver{
				PacketIDs: []uint32{observerUnknownID},
				Func: func(_ packet.Header, payload []byte, src, dst net.Addr) {
					if src.String() != "local" || dst.String() != "remote" {
						t.Fatalf("outgoing addresses = %v %v", src, dst)
					}
					events = append(events, "selective")
					payload[0] = 9
				},
			})
			conn.packetFunc = func(_ packet.Header, payload []byte, _, _ net.Addr) {
				events = append(events, "legacy")
				if payload[0] != 9 {
					t.Fatal("legacy observer ran before selective mutation")
				}
				payload[1] = 8
			}
			pk := &packet.Unknown{PacketID: observerUnknownID, Payload: []byte{1, 2}}
			if raw {
				if err := conn.WritePacketRaw(observerFrame(t, packet.Header{PacketID: pk.ID()}, pk.Payload)); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := conn.WritePacket(pk); err != nil {
					t.Fatal(err)
				}
			}
			frame := conn.bufferedSend[0]
			if !slices.Equal(events, []string{"selective", "legacy"}) || !bytes.Equal(frame[len(frame)-2:], []byte{9, 8}) {
				t.Fatalf("outbound events/frame = %v %v", events, frame)
			}
			events = nil
			conn.packetFunc = nil
			registry := &packet.ItemRegistry{Items: []protocol.ItemEntry{{Name: "minecraft:shield", RuntimeID: 355}}}
			if raw {
				frame, err := encodePacket(registry)
				if err != nil {
					t.Fatal(err)
				}
				if err := conn.WritePacketRaw(frame); err != nil {
					t.Fatal(err)
				}
			} else if err := conn.WritePacket(registry); err != nil {
				t.Fatal(err)
			}
			conn.observeRawWrite([]byte{0x80})
			if conn.shieldID.Load() != int32(registry.Items[0].RuntimeID) || len(events) != 0 {
				t.Fatal("unselected registry lost shield tracking or invoked an observer")
			}
		})
	}
}

func TestDialSnapshotsSelectiveObserverInterests(t *testing.T) {
	ids := []uint32{packet.IDRequestNetworkSettings, packet.IDNetworkSettings}
	var observed atomic.Uint32
	frame := observerFrame(t, packet.Header{PacketID: packet.IDNetworkSettings}, []byte{0x80})
	network := newScriptedDialNetwork(func(peer net.Conn) error {
		decoder := packet.NewDecoder(peer)
		if _, err := decoder.Decode(); err != nil {
			return err
		}
		if err := packet.NewEncoder(peer).Encode([][]byte{frame}); err != nil {
			return err
		}
		if _, err := decoder.Decode(); err == nil {
			return fmt.Errorf("client accepted malformed settings")
		}
		return nil
	})
	dialer := Dialer{FlushRate: -1, PacketObserver: PacketObserver{
		PacketIDs: ids,
		Func: func(header packet.Header, _ []byte, _, _ net.Addr) {
			observed.Add(1)
			if header.PacketID == packet.IDRequestNetworkSettings {
				ids[1] = packet.IDLevelChunk
			}
		},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialer.DialContextNetwork(ctx, network, "observer.invalid:19132")
	if conn != nil {
		_ = conn.Abort()
	}
	if scriptErr := <-network.done; scriptErr != nil {
		t.Fatal(scriptErr)
	}
	if err == nil || ctx.Err() != nil || observed.Load() != 2 {
		t.Fatalf("dial error/context/observations = %v/%v/%d", err, ctx.Err(), observed.Load())
	}
}

func TestPacketObserverRejectsIDsOutsideHeader(t *testing.T) {
	observer := PacketObserver{PacketIDs: []uint32{1023, 1024}, Func: func(packet.Header, []byte, net.Addr, net.Addr) {}}
	if _, err := (Dialer{PacketObserver: observer}).DialContextNetwork(context.Background(), nil, "observer.invalid:19132"); err == nil {
		t.Fatal("Dial accepted packet ID 1024")
	}
	observer.PacketIDs = observer.PacketIDs[:1]
	compiled := mustCompileObserver(t, observer)
	if !compiled.observes(1023) || compiled.observes(1022) || compiled.observes(1024+1023) {
		t.Fatal("bitset selection does not match the declared IDs")
	}
}

func mustCompileObserver(t *testing.T, observer PacketObserver) compiledPacketObserver {
	t.Helper()
	compiled, err := observer.compile()
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// observerTestConn supplies stable distinct addresses and aborts without flushing.
func observerTestConn(t *testing.T) *Conn {
	t.Helper()
	conn := newConn(&recordingConn{}, nil, slog.New(slog.DiscardHandler), DefaultProtocol, -1, false)
	t.Cleanup(func() { _ = conn.Abort() })
	return conn
}

// observerFrame encodes arbitrary packet bodies, including malformed fixtures.
func observerFrame(t *testing.T, header packet.Header, payload []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := header.Write(&buffer); err != nil {
		t.Fatal(err)
	}
	buffer.Write(payload)
	return buffer.Bytes()
}
