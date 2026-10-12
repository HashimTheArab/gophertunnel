package minecraft

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

func TestConn_ByteLimitRejectionKeepsCompletionsAndEncryptionConsistent(t *testing.T) {
	for _, mode := range []sendMode{buffered, flushBuffered, bypassBuffered} {
		for _, delay := range []time.Duration{0, time.Hour} {
			t.Run(fmt.Sprintf("mode=%d/delay=%s", mode, delay), func(t *testing.T) {
				conn, _ := newSendDelayConn(t)
				transport := &byteSplitTestTransport{}
				conn.delay.w = transport
				conn.proto = byteSplitWriteProtocol{DefaultProtocol}
				key := [32]byte{1}
				conn.enc.EnableCompression(packet.FlateCompression, 0)
				conn.enc.EnableEncryption(key)
				if err := conn.SetSendDelay(delay); err != nil {
					t.Fatal(err)
				}
				var completed []uint32
				conn.SetWriteObserver(func(pk packet.Packet) func() {
					id := pk.ID()
					return func() { completed = append(completed, id) }
				})
				err := conn.writePackets(mode,
					&packet.Unknown{PacketID: 700, Payload: make([]byte, 8*1024*1024)},
					testPacket(701),
				)
				if mode == buffered && err == nil {
					err = conn.Flush()
				}
				if err == nil {
					t.Fatal("oversized converted packet was accepted")
				}
				conn.delay.mu.Lock()
				staged, cursor := len(conn.delay.nextObservers), conn.delay.encodedPackets
				conn.delay.mu.Unlock()
				if staged != 0 || cursor != 0 {
					t.Fatalf("failed submission retained %d callbacks and cursor %d", staged, cursor)
				}
				want := []uint32{700}
				if delay > 0 {
					want = nil
				}
				if !slices.Equal(completed, want) {
					t.Fatalf("partial submission completed %v, want %v", completed, want)
				}
				if err := conn.WritePacketDirect(testPacket(702)); err != nil {
					t.Fatalf("valid write after rejection: %v", err)
				}
				if err := conn.SetSendDelay(0); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(completed, []uint32{700, 702}) {
					t.Fatalf("completed %v; the unfinished conversion must not complete", completed)
				}
				decoder := packet.NewDecoder(transport)
				decoder.EnableCompression(packet.FlateCompression, 0)
				decoder.EnableEncryption(key)
				var ids []uint32
				for range 2 {
					batch, err := decoder.Decode()
					if err != nil {
						t.Fatalf("decrypt accepted batch: %v", err)
					}
					for _, data := range batch {
						var header packet.Header
						if err := header.Read(bytes.NewReader(data)); err != nil {
							t.Fatal(err)
						}
						ids = append(ids, header.PacketID)
					}
				}
				if !slices.Equal(ids, []uint32{700, 710, 702}) {
					t.Fatalf("wire packet order = %v, want [700 710 702]", ids)
				}
			})
		}
	}
}

// byteSplitWriteProtocol creates a partly submitted logical conversion followed by an oversized packet.
type byteSplitWriteProtocol struct{ Protocol }

// ConvertFromLatest forces a byte split before the final, unencodable conversion output.
func (p byteSplitWriteProtocol) ConvertFromLatest(pk packet.Packet, conn *Conn) []packet.Packet {
	if pk.ID() != 701 {
		return p.Protocol.ConvertFromLatest(pk, conn)
	}
	return []packet.Packet{
		&packet.Unknown{PacketID: 710, Payload: make([]byte, 6*1024*1024)},
		&packet.Unknown{PacketID: 711, Payload: make([]byte, 4*1024*1024)},
		&packet.Unknown{PacketID: 712, Payload: make([]byte, packet.DefaultMaxDecompressedLen)},
	}
}

// byteSplitTestTransport retains each transport write for a later stateful encrypted decode.
type byteSplitTestTransport struct{ batches [][]byte }

// Write copies encoded bytes, as a test recorder must when the encoder reuses buffers.
func (t *byteSplitTestTransport) Write(data []byte) (int, error) {
	t.batches = append(t.batches, bytes.Clone(data))
	return len(data), nil
}

// Read returns one complete compressed batch to the decoder.
func (t *byteSplitTestTransport) Read(data []byte) (int, error) {
	if len(t.batches) == 0 {
		return 0, io.EOF
	}
	batch := t.batches[0]
	if len(batch) > len(data) {
		return 0, io.ErrShortBuffer
	}
	t.batches = t.batches[1:]
	return copy(data, batch), nil
}
