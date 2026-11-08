package minecraft

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/internal"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestLoginSuccessPreservesResourcePackNegotiation(t *testing.T) {
	for _, packs := range []string{"pending", "empty", "cached"} {
		for _, early := range []bool{true, false} {
			for _, combined := range []bool{true, false} {
				for _, cacheEnabled := range []bool{true, false} {
					name := fmt.Sprintf("%s/early=%t/combined=%t/cache=%t", packs, early, combined, cacheEnabled)
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						raw := &recordingConn{writes: make(chan []byte, 16)}
						conn := newConn(raw, nil, slog.New(internal.DiscardHandler{}), DefaultProtocol, -1, false)
						t.Cleanup(func() {
							_ = conn.Abort()
							conn.packStores.Wait()
						})
						conn.pool = DefaultProtocol.Packets(false)
						conn.handoff = HandoffAtStartGame
						conn.batchReading = true
						conn.cacheEnabled = cacheEnabled
						// Match Dial's expected replies immediately after sending Login.
						conn.expect(packet.IDResourcePacksInfo, packet.IDServerToClientHandshake, packet.IDPlayStatus, packet.IDStartGame)

						pack := testResourcePack(t)
						offer := &packet.ResourcePacksInfo{}
						stack := &packet.ResourcePackStack{BaseGameVersion: "*"}
						if packs != "empty" {
							offer.TexturePacks = []protocol.TexturePackInfo{{UUID: pack.UUID(), Version: pack.Version(), Size: uint64(pack.Size())}}
							if packs == "cached" {
								conn.resourcePackCache = memoryPackCache{pack.UUID(): pack}
								stack.TexturePacks = []protocol.StackResourcePack{{UUID: pack.UUID().String(), Version: pack.Version()}}
							}
						}
						success := &packet.PlayStatus{Status: packet.PlayStatusLoginSuccess}
						incoming := []packet.Packet{offer, success}
						if !early {
							incoming = []packet.Packet{success, offer}
						}
						// A repeated success during negotiation must neither resend capability nor rewind it.
						incoming = append(incoming, success)
						if packs == "pending" {
							incoming = append(incoming, &packet.ResourcePackDataInfo{
								UUID: pack.UUID().String() + "_" + pack.Version(), Size: uint64(pack.Size()),
								DataChunkSize: uint32(pack.Size()), ChunkCount: 1,
							})
						} else {
							incoming = append(incoming, stack)
						}
						incoming = append(incoming, &packet.StartGame{})
						feedPackLoginBatches(t, conn, incoming, combined)

						// StartGame completes the handoff and makes any wrongly deferred negotiation readable.
						batch, err := conn.ReadBatch()
						if err != nil {
							t.Fatalf("read handoff batch: %v", err)
						}
						if len(batch) != 1 || batch[0].ID() != packet.IDStartGame {
							t.Fatalf("negotiation escaped automatic handling: handoff batch = %v", batch)
						}

						response := uint32(packet.PackResponseAllPacksDownloaded)
						if packs == "pending" {
							response = packet.PackResponseSendPacks
						}
						want := []packet.Packet{
							&packet.ResourcePackClientResponse{Response: response},
							&packet.ClientCacheStatus{Enabled: cacheEnabled},
						}
						if !early {
							want[0], want[1] = want[1], want[0]
						}
						if packs == "pending" {
							want = append(want, &packet.ResourcePackChunkRequest{UUID: pack.UUID().String() + "_" + pack.Version()})
						} else {
							want = append(want, &packet.ResourcePackClientResponse{Response: packet.PackResponseCompleted})
						}
						for _, expected := range want {
							got := readPackLoginOutput(t, raw)
							if got.ID() != expected.ID() {
								t.Fatalf("sent %T, want %T", got, expected)
							}
							switch expected := expected.(type) {
							case *packet.ClientCacheStatus:
								if got.(*packet.ClientCacheStatus).Enabled != expected.Enabled {
									t.Fatalf("cache capability = %t, want %t", got.(*packet.ClientCacheStatus).Enabled, expected.Enabled)
								}
							case *packet.ResourcePackClientResponse:
								actual := got.(*packet.ResourcePackClientResponse)
								if actual.Response != expected.Response {
									t.Fatalf("pack response = %d, want %d", actual.Response, expected.Response)
								}
								if expected.Response == packet.PackResponseSendPacks && (len(actual.PacksToDownload) != 1 || actual.PacksToDownload[0] != pack.UUID().String()+"_"+pack.Version()) {
									t.Fatalf("requested packs = %v", actual.PacksToDownload)
								}
							case *packet.ResourcePackChunkRequest:
								if actual := got.(*packet.ResourcePackChunkRequest); actual.UUID != expected.UUID || actual.ChunkIndex != 0 {
									t.Fatalf("chunk request = %+v, want %+v", actual, expected)
								}
							}
						}
						select {
						case extra := <-raw.writes:
							t.Fatalf("unexpected extra outbound batch: %x", extra)
						default:
						}
					})
				}
			}
		}
	}
}

// feedPackLoginBatches passes real encoded batches through the receive dispatcher without a transport loop.
func feedPackLoginBatches(t *testing.T, conn *Conn, pks []packet.Packet, combined bool) {
	t.Helper()
	var frames [][]byte
	for _, pk := range pks {
		frame, err := encodePacket(pk)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	for len(frames) != 0 {
		n := 1
		if combined {
			n = len(frames)
		}
		var wire bytes.Buffer
		if err := packet.NewEncoder(&wire).Encode(frames[:n]); err != nil {
			t.Fatal(err)
		}
		if err := packet.NewDecoder(&wire).DecodeFunc(conn.receive); err != nil {
			t.Fatalf("receive batch: %v", err)
		}
		conn.flushBatch()
		frames = frames[n:]
	}
}

// readPackLoginOutput waits for one flushed response and decodes its protocol payload.
func readPackLoginOutput(t *testing.T, raw *recordingConn) packet.Packet {
	t.Helper()
	select {
	case wire := <-raw.writes:
		frames, err := packet.NewDecoder(bytes.NewReader(wire)).Decode()
		if err != nil {
			t.Fatal(err)
		}
		if len(frames) != 1 {
			t.Fatalf("outbound packet count = %d, want 1", len(frames))
		}
		payload := bytes.NewBuffer(frames[0])
		var header packet.Header
		if err := header.Read(payload); err != nil {
			t.Fatal(err)
		}
		factory, ok := DefaultProtocol.Packets(true)[header.PacketID]
		if !ok {
			t.Fatalf("unknown outbound packet ID %d", header.PacketID)
		}
		pk := factory()
		pk.Marshal(protocol.NewReader(payload, 0, true))
		return pk
	case <-time.After(5 * time.Second):
		t.Fatal("response was not flushed with the periodic flush ticker disabled")
		return nil
	}
}
